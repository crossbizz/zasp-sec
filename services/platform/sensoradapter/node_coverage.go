package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrNodeCoverage = errors.New("selected sensor coverage unavailable")

const NodeCoverageAnnotation = "zasp.io/node-coverage-v2"
const NodeCoverageLabel = "zasp.io/coverage-version"
const NodeCoverageSchema = "zasp-node-coverage-v2"

var coverageUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var coverageName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
var coverageBinding = regexp.MustCompile(`^[0-9a-f]{64}$`)
var coverageLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)

type CoverageTarget struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Release          string `json:"release"`
	ReleaseNamespace string `json:"release_namespace"`
	Image            string `json:"image"`
	ServiceAccount   string `json:"service_account"`
	Container        string `json:"container"`
}
type NodeCoverageSelection struct {
	SourceProfile     string            `json:"source_profile"`
	ClusterUID        string            `json:"cluster_uid"`
	EnrollmentBinding string            `json:"enrollment_binding"`
	MatchLabels       map[string]string `json:"match_labels"`
	Sensor            CoverageTarget    `json:"sensor"`
	Tetragon          CoverageTarget    `json:"tetragon"`
}

func (s NodeCoverageSelection) Validate() error {
	if s.SourceProfile != "tetragon-local-stream-v2" && s.SourceProfile != "tetragon-local-stream-v3" {
		return ErrNodeCoverage
	}
	if !validCoverageUUID(s.ClusterUID) || !coverageBinding.MatchString(s.EnrollmentBinding) || len(s.MatchLabels) < 1 || len(s.MatchLabels) > 8 {
		return ErrNodeCoverage
	}
	for k, v := range s.MatchLabels {
		parts := strings.Split(k, "/")
		if len(parts) > 2 || len(k) > 253 || !coverageLabel.MatchString(parts[len(parts)-1]) || !coverageLabel.MatchString(v) {
			return ErrNodeCoverage
		}
		if len(parts) == 2 && !coverageName.MatchString(parts[0]) {
			return ErrNodeCoverage
		}
	}
	for _, t := range []CoverageTarget{s.Sensor, s.Tetragon} {
		if !coverageName.MatchString(t.Namespace) || !coverageName.MatchString(t.Name) || !coverageName.MatchString(t.Release) || t.ReleaseNamespace != t.Namespace || !coverageName.MatchString(t.ServiceAccount) || !coverageName.MatchString(t.Container) || len(t.Image) > 512 || !regexp.MustCompile(`^[-A-Za-z0-9./:]+@sha256:[0-9a-f]{64}$`).MatchString(t.Image) {
			return ErrNodeCoverage
		}
	}
	if s.Sensor.Namespace == s.Tetragon.Namespace && s.Sensor.Name == s.Tetragon.Name {
		return ErrNodeCoverage
	}
	return nil
}
func validCoverageUUID(s string) bool {
	return coverageUUID.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func CoverageSelector(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	v := make([]string, len(keys))
	for i, k := range keys {
		v[i] = k + "=" + labels[k]
	}
	return strings.Join(v, ",")
}
func CoverageReportSelector(binding string) string {
	if !coverageBinding.MatchString(binding) {
		return "invalid=invalid"
	}
	return NodeCoverageLabel + "=v2,zasp.io/enrollment=" + binding[:32]
}
func CoverageLeaseName(r NodeCoverageV2) string {
	sum := sha256.Sum256([]byte(r.ClusterUID + "/" + r.EnrollmentBinding + "/" + r.NodeUID + "/" + r.BootID))
	return "zasp-coverage-v2-" + hex.EncodeToString(sum[:20])
}

type NodeCoverageV2 struct {
	Schema             string    `json:"schema"`
	EnrollmentBinding  string    `json:"enrollment_binding"`
	ClusterUID         string    `json:"cluster_uid"`
	NodeName           string    `json:"node_name"`
	NodeUID            string    `json:"node_uid"`
	BootID             string    `json:"boot_id"`
	ReporterPodName    string    `json:"reporter_pod_name"`
	ReporterPodUID     string    `json:"reporter_pod_uid"`
	TetragonPodName    string    `json:"tetragon_pod_name"`
	TetragonPodUID     string    `json:"tetragon_pod_uid"`
	GenerationID       string    `json:"generation_id"`
	SourceProfile      string    `json:"source_profile"`
	IdentityObservedAt time.Time `json:"identity_observed_at"`
	MeasuredAt         time.Time `json:"measured_at"`
	Status             string    `json:"status"`
	Capabilities       []string  `json:"capabilities"`
	Kernel             string    `json:"kernel"`
	BTF                bool      `json:"btf"`
	EventRate          uint64    `json:"event_rate"`
	Drops              uint64    `json:"drops"`
}

func (r NodeCoverageV2) Validate() error {
	if r.Schema != NodeCoverageSchema || !coverageBinding.MatchString(r.EnrollmentBinding) || !validCoverageUUID(r.ClusterUID) || !validCoverageUUID(r.NodeUID) || !validCoverageUUID(r.BootID) || !validCoverageUUID(r.ReporterPodUID) || !validCoverageUUID(r.TetragonPodUID) || !validCoverageUUID(r.GenerationID) || !coverageName.MatchString(r.NodeName) || !coverageName.MatchString(r.ReporterPodName) || !coverageName.MatchString(r.TetragonPodName) || r.IdentityObservedAt.IsZero() || r.MeasuredAt.IsZero() || r.SourceProfile != "tetragon-local-stream-v2" && r.SourceProfile != "tetragon-local-stream-v3" || r.Status != "healthy" && r.Status != "degraded" || len(r.Kernel) < 1 || len(r.Kernel) > 128 || len(r.Capabilities) < 1 || len(r.Capabilities) > 3 || r.EventRate > 1_000_000_000 || r.Drops > 1_000_000_000 {
		return ErrNodeCoverage
	}
	seen := map[string]bool{}
	for _, c := range r.Capabilities {
		if c != "process" && c != "file" && c != "network" || seen[c] {
			return ErrNodeCoverage
		}
		seen[c] = true
	}
	return nil
}
func EncodeNodeCoverage(r NodeCoverageV2) (string, error) {
	if r.Validate() != nil {
		return "", ErrNodeCoverage
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > 8192 {
		return "", ErrNodeCoverage
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func DecodeNodeCoverage(v string) (NodeCoverageV2, error) {
	var r NodeCoverageV2
	b, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil || len(b) > 8192 || base64.RawURLEncoding.EncodeToString(b) != v {
		return r, ErrNodeCoverage
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Validate() != nil {
		return NodeCoverageV2{}, ErrNodeCoverage
	}
	canonical, e := EncodeNodeCoverage(r)
	if e != nil || canonical != v {
		return NodeCoverageV2{}, ErrNodeCoverage
	}
	return r, nil
}

type CoverageMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	Generation        int64             `json:"generation"`
	ResourceVersion   string            `json:"resourceVersion"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	OwnerReferences   []struct {
		UID        string `json:"uid"`
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Controller *bool  `json:"controller"`
	} `json:"ownerReferences"`
}
type CoverageNode struct {
	Metadata CoverageMeta `json:"metadata"`
	Spec     struct {
		ProviderID    string `json:"providerID"`
		Unschedulable bool   `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		NodeInfo struct {
			BootID          string `json:"bootID"`
			KernelVersion   string `json:"kernelVersion"`
			OperatingSystem string `json:"operatingSystem"`
		} `json:"nodeInfo"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}
type CoveragePodSpec struct {
	NodeName           string            `json:"nodeName"`
	ServiceAccountName string            `json:"serviceAccountName"`
	NodeSelector       map[string]string `json:"nodeSelector"`
	Affinity           json.RawMessage   `json:"affinity"`
	Containers         []struct {
		Name  string `json:"name"`
		Image string `json:"image"`
	} `json:"containers"`
}
type CoveragePod struct {
	Metadata CoverageMeta    `json:"metadata"`
	Spec     CoveragePodSpec `json:"spec"`
	Status   struct {
		Phase      string     `json:"phase"`
		StartTime  *time.Time `json:"startTime"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		ContainerStatuses []struct {
			Name         string `json:"name"`
			Ready        bool   `json:"ready"`
			RestartCount int    `json:"restartCount"`
			State        struct {
				Running *struct {
					StartedAt time.Time `json:"startedAt"`
				} `json:"running"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}
type CoverageDaemonSet struct {
	Metadata CoverageMeta `json:"metadata"`
	Spec     struct {
		Selector struct {
			MatchLabels      map[string]string `json:"matchLabels"`
			MatchExpressions []json.RawMessage `json:"matchExpressions"`
		} `json:"selector"`
		Template struct {
			Metadata CoverageMeta    `json:"metadata"`
			Spec     CoveragePodSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
	} `json:"status"`
}
type CoverageLease struct {
	Metadata CoverageMeta `json:"metadata"`
	Spec     struct {
		HolderIdentity       *string    `json:"holderIdentity"`
		LeaseDurationSeconds *int32     `json:"leaseDurationSeconds"`
		RenewTime            *time.Time `json:"renewTime"`
	} `json:"spec"`
}
type NodeCoverageReader interface {
	ClusterUID(context.Context) (string, error)
	Nodes(context.Context, string) ([]CoverageNode, error)
	DaemonSet(context.Context, CoverageTarget) (CoverageDaemonSet, error)
	Pods(context.Context, string, string) ([]CoveragePod, error)
	Reports(context.Context, string, string) ([]CoverageLease, error)
}
type NodeCoverageResult struct {
	Complete     bool
	Nodes        int
	Reports      []NodeCoverageV2
	Reason       string
	TargetDigest string
}

func sameLabels(a, b map[string]string) bool { return CoverageSelector(a) == CoverageSelector(b) }
func matchesLabels(actual, expected map[string]string) bool {
	for k, v := range expected {
		if actual[k] != v {
			return false
		}
	}
	return true
}
func validCoverageDS(d CoverageDaemonSet, t CoverageTarget, s NodeCoverageSelection) bool {
	if d.Metadata.Name != t.Name || d.Metadata.Namespace != t.Namespace || !validCoverageUUID(d.Metadata.UID) || d.Metadata.DeletionTimestamp != nil || d.Metadata.Generation < 1 || d.Status.ObservedGeneration < d.Metadata.Generation || d.Metadata.Annotations["meta.helm.sh/release-name"] != t.Release || d.Metadata.Annotations["meta.helm.sh/release-namespace"] != t.ReleaseNamespace || !sameLabels(d.Spec.Template.Spec.NodeSelector, s.MatchLabels) || len(d.Spec.Selector.MatchLabels) == 0 || len(d.Spec.Selector.MatchExpressions) > 0 || !matchesLabels(d.Spec.Template.Metadata.Labels, d.Spec.Selector.MatchLabels) || d.Spec.Template.Spec.ServiceAccountName != t.ServiceAccount {
		return false
	}
	if len(d.Spec.Template.Spec.Affinity) > 0 && string(d.Spec.Template.Spec.Affinity) != "null" && string(d.Spec.Template.Spec.Affinity) != "{}" {
		return false
	}
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.Name == t.Container && c.Image == t.Image {
			return true
		}
	}
	return false
}
func CoveragePodMatches(p CoveragePod, d CoverageDaemonSet, t CoverageTarget, node string, at time.Time) bool {
	if p.Metadata.Namespace != t.Namespace || !validCoverageUUID(p.Metadata.UID) || p.Metadata.DeletionTimestamp != nil || p.Spec.NodeName != node || p.Spec.ServiceAccountName != t.ServiceAccount || p.Status.Phase != "Running" || !matchesLabels(p.Metadata.Labels, d.Spec.Selector.MatchLabels) {
		return false
	}
	owned := false
	for _, o := range p.Metadata.OwnerReferences {
		if o.Kind == "DaemonSet" && o.Name == t.Name && o.UID == d.Metadata.UID && o.Controller != nil && *o.Controller {
			owned = true
		}
	}
	if !owned {
		return false
	}
	ready := false
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			ready = true
		}
	}
	if !ready {
		return false
	}
	containerPresent := false
	for _, c := range p.Spec.Containers {
		if c.Name == t.Container {
			if containerPresent || c.Image != t.Image {
				return false
			}
			containerPresent = true
		}
	}
	if !containerPresent {
		return false
	}
	for _, c := range p.Status.ContainerStatuses {
		if c.Name == t.Container {
			return c.Ready && c.State.Running != nil && !c.State.Running.StartedAt.IsZero() && !at.Before(c.State.Running.StartedAt)
		}
	}
	return false
}
func ObserveNodeCoverage(ctx context.Context, reader NodeCoverageReader, s NodeCoverageSelection, now time.Time, ttl time.Duration) (NodeCoverageResult, error) {
	started := time.Now()
	result := NodeCoverageResult{Reason: "coverage_unavailable"}
	if ctx == nil || ctx.Err() != nil || reader == nil || s.Validate() != nil || ttl < 6*time.Second || ttl > 5*time.Minute || now.IsZero() {
		return result, ErrNodeCoverage
	}
	uid, e := reader.ClusterUID(ctx)
	if e != nil || uid != s.ClusterUID {
		return result, ErrNodeCoverage
	}
	nodes, e := reader.Nodes(ctx, CoverageSelector(s.MatchLabels))
	if e != nil || len(nodes) < 1 || len(nodes) > 1000 {
		return result, ErrNodeCoverage
	}
	sensor, e := reader.DaemonSet(ctx, s.Sensor)
	if e != nil || !validCoverageDS(sensor, s.Sensor, s) {
		return result, ErrNodeCoverage
	}
	tetragon, e := reader.DaemonSet(ctx, s.Tetragon)
	if e != nil || !validCoverageDS(tetragon, s.Tetragon, s) {
		return result, ErrNodeCoverage
	}
	sp, e := reader.Pods(ctx, s.Sensor.Namespace, CoverageSelector(sensor.Spec.Selector.MatchLabels))
	if e != nil || len(sp) > 2000 {
		return result, ErrNodeCoverage
	}
	tp, e := reader.Pods(ctx, s.Tetragon.Namespace, CoverageSelector(tetragon.Spec.Selector.MatchLabels))
	if e != nil || len(tp) > 2000 {
		return result, ErrNodeCoverage
	}
	leases, e := reader.Reports(ctx, s.Sensor.Namespace, CoverageReportSelector(s.EnrollmentBinding))
	if e != nil || len(leases) > 2000 {
		return result, ErrNodeCoverage
	}
	reports := map[string]NodeCoverageV2{}
	for _, l := range leases {
		r, e := DecodeNodeCoverage(l.Metadata.Annotations[NodeCoverageAnnotation])
		if e != nil || l.Metadata.Namespace != s.Sensor.Namespace || l.Metadata.Name != CoverageLeaseName(r) || l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity != r.ReporterPodName || l.Spec.RenewTime == nil || l.Spec.LeaseDurationSeconds == nil || *l.Spec.LeaseDurationSeconds != int32(ttl/time.Second) {
			continue
		}
		if r.ClusterUID != s.ClusterUID || r.EnrollmentBinding != s.EnrollmentBinding {
			continue
		}
		key := r.NodeUID + "/" + r.BootID
		if _, exists := reports[key]; exists {
			return result, ErrNodeCoverage
		}
		if l.Spec.RenewTime.Before(r.MeasuredAt) || l.Spec.RenewTime.After(now.Add(5*time.Second)) || l.Spec.RenewTime.Before(now.Add(-ttl)) {
			continue
		}
		reports[key] = r
	}
	identities := make([]string, 0, len(nodes))
	seen := map[string]bool{}
	providers := map[string]bool{}
	result.Complete = true
	result.Reason = "complete"
	for _, n := range nodes {
		key := n.Metadata.UID + "/" + n.Status.NodeInfo.BootID
		if providers[n.Spec.ProviderID] || seen[n.Metadata.Name] || seen[n.Metadata.UID] || !coverageName.MatchString(n.Metadata.Name) || !validCoverageUUID(n.Metadata.UID) || !validCoverageUUID(n.Status.NodeInfo.BootID) || n.Metadata.DeletionTimestamp != nil || n.Spec.Unschedulable || !matchesLabels(n.Metadata.Labels, s.MatchLabels) || n.Status.NodeInfo.OperatingSystem != "linux" || n.Metadata.Labels["eks.amazonaws.com/compute-type"] == "fargate" || !regexp.MustCompile(`^aws:///[^/]+/i-([a-f0-9]{8}|[a-f0-9]{17})$`).MatchString(n.Spec.ProviderID) {
			return result, ErrNodeCoverage
		}
		seen[n.Metadata.Name], seen[n.Metadata.UID] = true, true
		providers[n.Spec.ProviderID] = true
		nodeReady := false
		for _, c := range n.Status.Conditions {
			nodeReady = nodeReady || c.Type == "Ready" && c.Status == "True"
		}
		identities = append(identities, coverageNodeState(n))
		r, ok := reports[key]
		fresh := ok && !r.MeasuredAt.After(now.Add(5*time.Second)) && !r.MeasuredAt.Before(now.Add(-ttl)) && !r.IdentityObservedAt.After(r.MeasuredAt.Add(5*time.Second)) && !r.IdentityObservedAt.Before(now.Add(-ttl)) && r.NodeName == n.Metadata.Name && r.Kernel == n.Status.NodeInfo.KernelVersion && r.SourceProfile == s.SourceProfile
		sc, tc := 0, 0
		for _, p := range sp {
			if CoveragePodMatches(p, sensor, s.Sensor, n.Metadata.Name, r.MeasuredAt) {
				sc++
				if p.Metadata.UID != r.ReporterPodUID || p.Metadata.Name != r.ReporterPodName {
					fresh = false
				}
			}
		}
		for _, p := range tp {
			if CoveragePodMatches(p, tetragon, s.Tetragon, n.Metadata.Name, r.MeasuredAt) {
				tc++
				if p.Metadata.UID != r.TetragonPodUID || p.Metadata.Name != r.TetragonPodName {
					fresh = false
				}
			}
		}
		if !nodeReady || !fresh || sc != 1 || tc != 1 || r.Status != "healthy" || !r.BTF || r.Drops > 0 || len(r.Capabilities) != 3 {
			result.Complete = false
			result.Reason = "selected_node_incomplete"
		}
		if fresh {
			result.Reports = append(result.Reports, r)
		}
	}
	second, e := reader.Nodes(ctx, CoverageSelector(s.MatchLabels))
	if e != nil || len(second) != len(nodes) {
		return NodeCoverageResult{Reason: "inventory_changed"}, ErrNodeCoverage
	}
	other := make([]string, 0, len(second))
	for _, n := range second {
		other = append(other, coverageNodeState(n))
	}
	sort.Strings(identities)
	sort.Strings(other)
	if strings.Join(identities, "|") != strings.Join(other, "|") {
		return NodeCoverageResult{Reason: "inventory_changed"}, ErrNodeCoverage
	}
	for _, pair := range []struct {
		old    CoverageDaemonSet
		target CoverageTarget
	}{{sensor, s.Sensor}, {tetragon, s.Tetragon}} {
		d, e := reader.DaemonSet(ctx, pair.target)
		if e != nil || !validCoverageDS(d, pair.target, s) || d.Metadata.UID != pair.old.Metadata.UID || d.Metadata.Generation != pair.old.Metadata.Generation {
			return NodeCoverageResult{Reason: "release_changed"}, ErrNodeCoverage
		}
	}
	finalNow := now.Add(time.Since(started))
	for _, r := range result.Reports {
		if r.MeasuredAt.Before(finalNow.Add(-ttl)) || r.IdentityObservedAt.Before(finalNow.Add(-ttl)) {
			return NodeCoverageResult{Reason: "observation_expired"}, ErrNodeCoverage
		}
	}
	digest, _ := json.Marshal(struct {
		Selection              NodeCoverageSelection
		Nodes                  []string
		SensorUID, TetragonUID string
	}{s, identities, sensor.Metadata.UID, tetragon.Metadata.UID})
	sum := sha256.Sum256(digest)
	result.TargetDigest = hex.EncodeToString(sum[:])
	result.Nodes = len(nodes)
	return result, nil
}

func CoverageDaemonSetMatches(d CoverageDaemonSet, t CoverageTarget, s NodeCoverageSelection) bool {
	return validCoverageDS(d, t, s)
}

// Ignore resourceVersion churn while detecting changed identity, selection or readiness
// between the bounded inventory passes.
func coverageNodeState(n CoverageNode) string {
	state, _ := json.Marshal(struct {
		Name, UID, BootID, ProviderID, Kernel, OperatingSystem string
		Labels                                                 map[string]string
		Deleting, Unschedulable                                bool
		Conditions                                             any
	}{n.Metadata.Name, n.Metadata.UID, n.Status.NodeInfo.BootID, n.Spec.ProviderID,
		n.Status.NodeInfo.KernelVersion, n.Status.NodeInfo.OperatingSystem,
		n.Metadata.Labels, n.Metadata.DeletionTimestamp != nil, n.Spec.Unschedulable,
		n.Status.Conditions})
	return string(state)
}
