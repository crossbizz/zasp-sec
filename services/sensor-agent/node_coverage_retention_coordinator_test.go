package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const retainedStateTestKey = "zasp.io/coverage-retention-state"
const retainedSlotTestKey = "zasp.io/coverage-slot"

// Controlled Kubernetes application dependencies, never host/witness/RBAC proof.
// Existing rooted mounted witness fixture and its explicit skip are unchanged.
type retainedCoordinatorReader struct {
	*mountedCoverageFixture
	nodes   []sensoradapter.CoverageNode
	refused bool
}

func (r *retainedCoordinatorReader) Nodes(context.Context, string) ([]sensoradapter.CoverageNode, error) {
	if r.refused {
		return nil, ErrClusterRetryable
	}
	return r.nodes, nil
}

type retainedCoordinatorLeases struct{ *memoryClusterAPI }

func (a *retainedCoordinatorLeases) Create(ctx context.Context, v *coordinationv1.Lease, o metav1.CreateOptions) (*coordinationv1.Lease, error) {
	c := v.DeepCopy()
	c.UID = types.UID(fmt.Sprintf("99999999-0000-4000-8000-%012d", a.revision+1))
	return a.memoryClusterAPI.Create(ctx, c, o)
}

type retainedCoordinatorSink struct {
	now         func() time.Time
	bodies      [][]byte
	legacy      int
	disposition string
	err         error
}

func (s *retainedCoordinatorSink) Heartbeat(context.Context, sensoradapter.Heartbeat) error {
	s.legacy++
	return errors.New("retained mode used legacy sink")
}
func (s *retainedCoordinatorSink) SendRetainedHeartbeat(_ context.Context, body []byte) (nodecoveragewire.Receipt, error) {
	s.bodies = append(s.bodies, bytes.Clone(body))
	if s.err != nil {
		return nodecoveragewire.Receipt{}, s.err
	}
	var env nodecoveragewire.Envelope
	if json.Unmarshal(body, &env) != nil {
		return nodecoveragewire.Receipt{}, ErrCluster
	}
	sum := sha256.Sum256(body)
	return nodecoveragewire.Receipt{SensorID: "pid_10000001-0000-4000-8000-000000000001", Sequence: env.Sequence, RequestDigest: hex.EncodeToString(sum[:]), Disposition: s.disposition, ResolvedAt: s.now(), SourceObservedAt: env.SourceObservedAt, ExpiresAt: env.SourceObservedAt.Add(time.Duration(env.TTLSeconds) * time.Second)}, nil
}

func retainedCoordinatorFixture(t *testing.T, count int, now func() time.Time) (*ClusterCoordinator, *retainedCoordinatorLeases, *retainedCoordinatorReader, *retainedCoordinatorSink) {
	t.Helper()
	stamp := now()
	api := &retainedCoordinatorLeases{newMemoryClusterAPI(nil)}
	target := sensoradapter.CoverageTarget{Namespace: "agentsec", Name: "sensor-agent", Release: "zasp", ReleaseNamespace: "agentsec", Image: "example/sensor@sha256:" + strings.Repeat("a", 64), ServiceAccount: "sensor-agent", Container: "sensor-agent"}
	tetra := target
	tetra.Name = "zasp-tetragon"
	tetra.Release = "zasp-tetragon"
	tetra.ServiceAccount = "zasp-tetragon"
	tetra.Container = "tetragon"
	selection := sensoradapter.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "11111111-1111-4111-8111-111111111111", EnrollmentBinding: strings.Repeat("a", 64), MatchLabels: map[string]string{"pool": "selected"}, Sensor: target, Tetragon: tetra}
	base := &mountedCoverageFixture{api: api.memoryClusterAPI, uid: selection.ClusterUID, targets: map[string]sensoradapter.CoverageDaemonSet{}, pods: map[string][]sensoradapter.CoveragePod{}}
	reader := &retainedCoordinatorReader{mountedCoverageFixture: base}
	decode := func(v any, out any) {
		t.Helper()
		raw, e := json.Marshal(v)
		if e != nil || json.Unmarshal(raw, out) != nil {
			t.Fatal("invalid typed reader fixture")
		}
	}
	dsUIDs := []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}
	for n, tr := range []sensoradapter.CoverageTarget{target, tetra} {
		labels := map[string]string{"app.kubernetes.io/name": tr.Container}
		var ds sensoradapter.CoverageDaemonSet
		decode(map[string]any{"metadata": map[string]any{"name": tr.Name, "namespace": tr.Namespace, "uid": dsUIDs[n], "generation": 1, "annotations": map[string]string{"meta.helm.sh/release-name": tr.Release, "meta.helm.sh/release-namespace": tr.Namespace}}, "spec": map[string]any{"selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"nodeSelector": selection.MatchLabels, "serviceAccountName": tr.ServiceAccount, "containers": []any{map[string]string{"name": tr.Container, "image": tr.Image}}}}}, "status": map[string]any{"observedGeneration": 1}}, &ds)
		base.targets[tr.Name] = ds
	}
	for n := 0; n < count; n++ {
		name := fmt.Sprintf("node-%04d", n)
		uid := fmt.Sprintf("00000001-0000-4000-8000-%012d", n+1)
		boot := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		var node sensoradapter.CoverageNode
		decode(map[string]any{"metadata": map[string]any{"name": name, "uid": uid, "labels": selection.MatchLabels}, "spec": map[string]any{"providerID": fmt.Sprintf("aws:///us-west-2a/i-%017x", n+1)}, "status": map[string]any{"nodeInfo": map[string]any{"bootID": boot, "kernelVersion": "6.8.1", "operatingSystem": "linux"}, "conditions": []any{map[string]string{"type": "Ready", "status": "True"}}}}, &node)
		reader.nodes = append(reader.nodes, node)
		podNames := []string{"sensor-" + name, "tetragon-" + name}
		podUIDs := []string{fmt.Sprintf("00000002-0000-4000-8000-%012d", n+1), fmt.Sprintf("00000003-0000-4000-8000-%012d", n+1)}
		for j, tr := range []sensoradapter.CoverageTarget{target, tetra} {
			labels := map[string]string{"app.kubernetes.io/name": tr.Container}
			var pod sensoradapter.CoveragePod
			decode(map[string]any{"metadata": map[string]any{"name": podNames[j], "namespace": tr.Namespace, "uid": podUIDs[j], "labels": labels, "ownerReferences": []any{map[string]any{"kind": "DaemonSet", "name": tr.Name, "uid": dsUIDs[j], "controller": true}}}, "spec": map[string]any{"nodeName": name, "serviceAccountName": tr.ServiceAccount, "containers": []any{map[string]string{"name": tr.Container, "image": tr.Image}}}, "status": map[string]any{"phase": "Running", "conditions": []any{map[string]string{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": tr.Container, "ready": true, "state": map[string]any{"running": map[string]any{"startedAt": stamp.Add(-time.Minute)}}}}}}, &pod)
			key := tr.Namespace + "/" + sensoradapter.CoverageSelector(labels)
			base.pods[key] = append(base.pods[key], pod)
		}
		report := sensoradapter.NodeCoverageV2{Schema: sensoradapter.NodeCoverageSchema, EnrollmentBinding: selection.EnrollmentBinding, ClusterUID: selection.ClusterUID, NodeName: name, NodeUID: uid, BootID: boot, ReporterPodName: podNames[0], ReporterPodUID: podUIDs[0], TetragonPodName: podNames[1], TetragonPodUID: podUIDs[1], GenerationID: "77777777-7777-4777-8777-777777777777", SourceProfile: selection.SourceProfile, IdentityObservedAt: stamp, MeasuredAt: stamp, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.1", BTF: true}
		encoded, e := sensoradapter.EncodeNodeCoverage(report)
		if e != nil {
			t.Fatal("report fixture rejected", e)
		}
		holder := report.ReporterPodName
		ttl := int32(30)
		renew := metav1.NewMicroTime(stamp)
		_, e = api.Create(context.Background(), &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: sensoradapter.CoverageLeaseName(report), Namespace: "agentsec", Labels: map[string]string{sensoradapter.NodeCoverageLabel: "v2", "zasp.io/enrollment": selection.EnrollmentBinding[:32]}, Annotations: map[string]string{sensoradapter.NodeCoverageAnnotation: encoded}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &ttl, RenewTime: &renew}}, metav1.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
	}
	sink := &retainedCoordinatorSink{now: now, disposition: "accepted"}
	c, e := NewClusterCoordinator(ClusterCoordinatorConfig{SensorID: "pid_10000001-0000-4000-8000-000000000001", Namespace: "agentsec", Coverage: &selection, CoverageReader: reader, Witness: &nodeWitnessFile{}, PodName: "adapter-a", NodeName: "node-0000", LeaseDuration: 15 * time.Second, ReportTTL: 30 * time.Second, Leases: api, Pods: api, Heartbeats: sink, Now: now, NodeCoverageRetention: true, RetainedHeartbeats: sink})
	if e != nil {
		t.Fatal(e)
	}
	return c, api, reader, sink
}

func retainedCoordinatorStoredBody(t *testing.T, api *retainedCoordinatorLeases) ([]byte, map[string]any) {
	t.Helper()
	state := api.leases[clusterStateLeaseName]
	if state == nil {
		t.Fatal("durable coordinator state missing")
	}
	var manifestState map[string]any
	if json.Unmarshal([]byte(state.Annotations[retainedStateTestKey]), &manifestState) != nil || manifestState["phase"] != "pending" {
		t.Fatal("opted-in full observation was not durably sealed as pending")
	}
	type piece struct {
		index int
		raw   []byte
	}
	var pieces []piece
	for _, lease := range api.leases {
		encoded := lease.Annotations[retainedSlotTestKey]
		if encoded == "" {
			continue
		}
		var slot struct {
			Index        int    `json:"index"`
			Data         string `json:"data"`
			StateUID     string `json:"state_uid"`
			StorageEpoch int64  `json:"storage_epoch"`
			SHA256       string `json:"sha256"`
			Bytes        int    `json:"bytes"`
		}
		if json.Unmarshal([]byte(encoded), &slot) != nil {
			t.Fatal("slot malformed")
		}
		raw, e := base64.RawURLEncoding.DecodeString(slot.Data)
		sum := sha256.Sum256(raw)
		if e != nil || len(raw) > 65536 || len(raw) != slot.Bytes || hex.EncodeToString(sum[:]) != slot.SHA256 || slot.StateUID != string(state.UID) || slot.StorageEpoch != int64(manifestState["storage_epoch"].(float64)) {
			t.Fatal("slot custody or bounded byte identity lost")
		}
		if len(lease.OwnerReferences) != 1 || lease.OwnerReferences[0].UID != state.UID || lease.OwnerReferences[0].BlockOwnerDeletion != nil && *lease.OwnerReferences[0].BlockOwnerDeletion {
			t.Fatal("slot uses wrong UID ownership or requires new privilege")
		}
		pieces = append(pieces, piece{slot.Index, raw})
	}
	if len(pieces) < 1 || len(pieces) > 256 {
		t.Fatal("missing or unbounded chunk pool")
	}
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].index < pieces[j].index })
	var body []byte
	for n, p := range pieces {
		if p.index != n {
			t.Fatal("chunk order/gaps")
		}
		body = append(body, p.raw...)
	}
	if len(body) > 16<<20 {
		t.Fatal("full payload exceeds finite contract")
	}
	return body, manifestState
}

func TestRetainedCoordinatorPreparesFullCapacityWithoutLegacyAnnotation(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c, api, _, sink := retainedCoordinatorFixture(t, 1000, func() time.Time { return now })
	if _, e := c.pendingOrPrepare(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	body, state := retainedCoordinatorStoredBody(t, api)
	var env nodecoveragewire.Envelope
	if json.Unmarshal(body, &env) != nil || len(env.SelectedNodes) != 1000 || len(env.Reports) != 1000 || env.Sequence != 1 || env.StorageEpoch != 1 || env.StateUID != string(api.leases[clusterStateLeaseName].UID) || state["resolved_attempt_sequence"] != float64(0) {
		t.Fatal("whole selected inventory/reports/source identity lost")
	}
	if len(body) <= 256<<10 || api.leases[clusterStateLeaseName].Annotations[clusterPendingAnnotation] != "" || sink.legacy != 0 || len(sink.bodies) != 0 {
		t.Fatal("large body stored in original annotation or sent before custody")
	}
	for _, lease := range api.leases {
		total := 0
		for key, value := range lease.Annotations {
			total += len(key) + len(value)
		}
		if total > 200<<10 {
			t.Fatal("annotation budget exceeded")
		}
	}
}

func TestRetainedCoordinatorResolvesExactPendingWithoutFreshObservation(t *testing.T) {
	for _, mode := range []string{"unknown", "accepted", "expired_not_committed", "changed_chunk"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			c, api, reader, sink := retainedCoordinatorFixture(t, 2, func() time.Time { return now })
			if _, e := c.pendingOrPrepare(context.Background(), now); e != nil {
				t.Fatal(e)
			}
			body, _ := retainedCoordinatorStoredBody(t, api)
			before := api.leases[clusterStateLeaseName].DeepCopy()
			reader.refused = true
			now = now.Add(time.Minute)
			if mode == "unknown" {
				sink.err = ErrClusterRetryable
			} else if mode == "expired_not_committed" {
				sink.disposition = mode
			}
			if mode == "changed_chunk" {
				for _, l := range api.leases {
					if l.Annotations[retainedSlotTestKey] != "" {
						l.Annotations[retainedSlotTestKey] = "{}"
						break
					}
				}
			}
			e := c.Tick(context.Background(), fixtureNodeReport("node-0000", now))
			if mode == "changed_chunk" {
				if e == nil || len(sink.bodies) != 0 {
					t.Fatal("corrupt durable pending acquired send authority")
				}
				return
			}
			if len(sink.bodies) != 1 || !bytes.Equal(sink.bodies[0], body) || sink.legacy != 0 {
				t.Fatal("sealed pending requires re-observation or changed original bytes")
			}
			if mode == "unknown" {
				if e == nil || !bytes.Equal([]byte(before.Annotations[retainedStateTestKey]), []byte(api.leases[clusterStateLeaseName].Annotations[retainedStateTestKey])) {
					t.Fatal("unknown send discarded or advanced pending")
				}
				return
			}
			var state map[string]any
			if e != nil || json.Unmarshal([]byte(api.leases[clusterStateLeaseName].Annotations[retainedStateTestKey]), &state) != nil || state["phase"] != "idle" || state["resolved_attempt_sequence"] != float64(1) {
				t.Fatal("confirmed exact typed disposition did not resolve pending attempt")
			}
		})
	}
}

func TestRetainedCoordinatorRefusesIncompleteOptInConfiguration(t *testing.T) {
	for _, mode := range []string{"missing_coverage", "missing_retained_sink"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			c, _, _, _ := retainedCoordinatorFixture(t, 1, func() time.Time { return now })
			cfg := c.config
			if mode == "missing_coverage" {
				cfg.Coverage = nil
			} else {
				cfg.RetainedHeartbeats = nil
			}
			if value, e := NewClusterCoordinator(cfg); e == nil || value != nil {
				t.Fatal("retained opt-in silently fell back to legacy configuration")
			}
		})
	}
}
