package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"io"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"os"
	"sort"
	"strings"
	"time"
)

func mountNodeCoverage(config sensorAgentConfig, dependencies *sensorAgentDependencies) (sensoradapter.NodeCoverageReader, *nodeWitnessFile, error) {
	if config.Coverage == nil || config.Coverage.Validate() != nil || config.Coverage.Sensor.Namespace != config.Namespace || !validCoverageWitnessPath(config.ObservationDirectory, config.SpoolDirectory) {
		return nil, nil, ErrCluster
	}
	inCluster, e := rest.InClusterConfig()
	if e != nil || inCluster.CAFile == "" {
		return nil, nil, ErrCluster
	}
	ca, e := os.ReadFile(inCluster.CAFile)
	if e != nil || len(ca) > 1<<20 {
		return nil, nil, ErrCluster
	}
	token, e := newTokenReader("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if e != nil {
		return nil, nil, ErrCluster
	}
	token.projected = true
	reader, e := sensoradapter.NewCoverageHTTPReader(inCluster.Host, ca, func(ctx context.Context) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrCluster
		}
		return readLineageToken(token, 0)
	}, *config.Coverage)
	if e != nil {
		token.Close()
		return nil, nil, ErrCluster
	}
	witness, e := openNodeWitness(config.ObservationDirectory, config.PodName, config.PodUID, uint32(os.Getegid()), false)
	if e != nil {
		reader.Close()
		token.Close()
		return nil, nil, ErrCluster
	}
	dependencies.coverageReader, dependencies.coverageToken, dependencies.coverageWitness = reader, token, witness
	return reader, witness, nil
}
func (c *ClusterCoordinator) upsertCoverage(ctx context.Context, local NodeReport, now time.Time) error {
	started := time.Now()
	if c.config.Coverage == nil || c.config.CoverageReader == nil || c.config.Witness == nil || local.NodeName != c.config.NodeName || local.ObservedAt.IsZero() || local.ObservedAt.Before(now.Add(-c.config.ReportTTL)) || local.ObservedAt.After(now.Add(5*time.Second)) {
		return ErrCluster
	}
	witness, e := c.config.Witness.read(now, c.config.ReportTTL)
	if e != nil || witness.Source.NodeName != c.config.NodeName || witness.Source.ClusterUID != c.config.Coverage.ClusterUID || witness.Source.EnrollmentBinding != c.config.Coverage.EnrollmentBinding {
		return ErrCluster
	}
	r := sensoradapter.NodeCoverageV2{Schema: sensoradapter.NodeCoverageSchema, EnrollmentBinding: witness.Source.EnrollmentBinding, ClusterUID: witness.Source.ClusterUID, NodeName: witness.Source.NodeName, NodeUID: witness.Source.NodeUID, BootID: witness.Source.BootID, GenerationID: witness.Source.GenerationID, SourceProfile: witness.Source.Profile, IdentityObservedAt: witness.ObservedAt, MeasuredAt: local.ObservedAt, Status: local.Status, Capabilities: append([]string(nil), local.Capabilities...), Kernel: local.Kernel, BTF: local.BTF, EventRate: local.EventRate, Drops: local.Drops}
	for index, target := range []sensoradapter.CoverageTarget{c.config.Coverage.Sensor, c.config.Coverage.Tetragon} {
		d, e := c.config.CoverageReader.DaemonSet(ctx, target)
		if e != nil || !sensoradapter.CoverageDaemonSetMatches(d, target, *c.config.Coverage) {
			return ErrCluster
		}
		pods, e := c.config.CoverageReader.Pods(ctx, target.Namespace, sensoradapter.CoverageSelector(d.Spec.Selector.MatchLabels))
		if e != nil {
			return ErrCluster
		}
		found := 0
		for _, p := range pods {
			if sensoradapter.CoveragePodMatches(p, d, target, c.config.NodeName, local.ObservedAt) {
				found++
				if index == 0 {
					if p.Metadata.Name != c.config.PodName || p.Metadata.UID != witness.PodUID {
						return ErrCluster
					}
					r.ReporterPodName, r.ReporterPodUID = p.Metadata.Name, p.Metadata.UID
				} else {
					r.TetragonPodName, r.TetragonPodUID = p.Metadata.Name, p.Metadata.UID
				}
			}
		}
		if found != 1 {
			return ErrCluster
		}
	}
	finalNow := now.Add(time.Since(started))
	if witness.ObservedAt.Before(finalNow.Add(-c.config.ReportTTL)) || local.ObservedAt.Before(finalNow.Add(-c.config.ReportTTL)) {
		return ErrCluster
	}
	encoded, e := sensoradapter.EncodeNodeCoverage(r)
	if e != nil {
		return ErrCluster
	}
	name := sensoradapter.CoverageLeaseName(r)
	holder := r.ReporterPodName
	seconds := int32(c.config.ReportTTL / time.Second)
	renew := metav1.NewMicroTime(now)
	current, e := c.config.Leases.Get(ctx, name, metav1.GetOptions{})
	labels := map[string]string{sensoradapter.NodeCoverageLabel: "v2", "zasp.io/enrollment": r.EnrollmentBinding[:32]}
	annotations := map[string]string{sensoradapter.NodeCoverageAnnotation: encoded}
	if e != nil {
		if !apierrors.IsNotFound(e) {
			return ErrClusterRetryable
		}
		_, e = c.config.Leases.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.config.Namespace, Labels: labels, Annotations: annotations}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &seconds, RenewTime: &renew}}, metav1.CreateOptions{})
		return clusterMutationError(e)
	}
	prior, e := sensoradapter.DecodeNodeCoverage(current.Annotations[sensoradapter.NodeCoverageAnnotation])
	if e != nil || prior.NodeUID != r.NodeUID || prior.BootID != r.BootID || prior.EnrollmentBinding != r.EnrollmentBinding || current.Namespace != c.config.Namespace || current.DeletionTimestamp != nil {
		return ErrCluster
	}
	next := current.DeepCopy()
	next.Labels, next.Annotations = labels, annotations
	next.Spec.HolderIdentity, next.Spec.LeaseDurationSeconds, next.Spec.RenewTime = &holder, &seconds, &renew
	_, e = c.config.Leases.Update(ctx, next, metav1.UpdateOptions{})
	return clusterMutationError(e)
}
func (c *ClusterCoordinator) aggregateCoverage(ctx context.Context, now time.Time) (sensoradapter.Heartbeat, time.Time, error) {
	result, e := sensoradapter.ObserveNodeCoverage(ctx, c.config.CoverageReader, *c.config.Coverage, now, c.config.ReportTTL)
	if e != nil {
		return sensoradapter.Heartbeat{}, time.Time{}, ErrClusterRetryable
	}
	return aggregateCoverageReport(result, now)
}

func aggregateCoverageReport(result sensoradapter.NodeCoverageResult, now time.Time) (sensoradapter.Heartbeat, time.Time, error) {
	observed := now
	status := "healthy"
	if !result.Complete {
		status = "degraded"
	}
	caps := map[string]bool{"file": true, "network": true, "process": true}
	btf := result.Complete
	kernel := "unknown"
	var rate, drops uint64
	for _, r := range result.Reports {
		if r.MeasuredAt.Before(observed) {
			observed = r.MeasuredAt
		}
		if r.IdentityObservedAt.Before(observed) {
			observed = r.IdentityObservedAt
		}
		if kernel == "unknown" {
			kernel = r.Kernel
		} else if kernel != r.Kernel {
			kernel = "mixed"
			status = "degraded"
		}
		btf = btf && r.BTF
		rate = min(uint64(1_000_000_000), rate+r.EventRate)
		drops = min(uint64(1_000_000_000), drops+r.Drops)
		for key := range caps {
			found := false
			for _, v := range r.Capabilities {
				found = found || key == v
			}
			if !found {
				delete(caps, key)
			}
		}
	}
	values := make([]string, 0, len(caps))
	for key := range caps {
		values = append(values, key)
	}
	sort.Strings(values)
	if len(values) == 0 || len(result.Reports) == 0 {
		values = []string{"process"}
		status = "degraded"
		btf = false
	}
	return sensoradapter.Heartbeat{Status: status, Capabilities: values, Kernel: kernel, BTF: btf, EventRate: rate, Drops: drops}, observed, nil
}

// Encoding is shared with live preflight; no stdin host observations accepted.
func decodeCoverageSelection(body string) (*sensoradapter.NodeCoverageSelection, error) {
	var s sensoradapter.NodeCoverageSelection
	d := json.NewDecoder(strings.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF || s.Validate() != nil {
		return nil, ErrCluster
	}
	return &s, nil
}

const clusterCoveragePendingAnnotation = "zasp.io/pending-coverage-v2"

type coveragePendingWire struct {
	Schema          string    `json:"schema"`
	SelectionDigest string    `json:"selection_digest"`
	PayloadDigest   string    `json:"payload_digest"`
	ObservedAt      time.Time `json:"observed_at"`
}

func (c *ClusterCoordinator) coveragePendingConfigDigest() string {
	body, _ := json.Marshal(struct {
		Selection                *sensoradapter.NodeCoverageSelection
		Namespace                string
		ReportTTL, LeaseDuration time.Duration
	}{c.config.Coverage, c.config.Namespace, c.config.ReportTTL, c.config.LeaseDuration})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
func (c *ClusterCoordinator) encodeCoveragePending(payload string, observed time.Time) string {
	digest := sha256.Sum256([]byte(payload))
	wire := coveragePendingWire{Schema: "zasp-coverage-pending-v2", SelectionDigest: c.coveragePendingConfigDigest(), PayloadDigest: hex.EncodeToString(digest[:]), ObservedAt: observed}
	body, _ := json.Marshal(wire)
	return base64.RawURLEncoding.EncodeToString(body)
}
func (c *ClusterCoordinator) validCoveragePending(payload, marker string, now time.Time) bool {
	if marker == "" || len(marker) > 2048 {
		return false
	}
	body, e := base64.RawURLEncoding.DecodeString(marker)
	if e != nil {
		return false
	}
	var wire coveragePendingWire
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(new(any)) != io.EOF || wire.Schema != "zasp-coverage-pending-v2" || wire.ObservedAt.IsZero() || wire.ObservedAt.Before(now.Add(-c.config.ReportTTL)) || wire.ObservedAt.After(now.Add(5*time.Second)) {
		return false
	}
	return marker == c.encodeCoveragePending(payload, wire.ObservedAt)
}
