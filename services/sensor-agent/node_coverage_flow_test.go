package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"io"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type mountedCoverageFixture struct {
	api     *memoryClusterAPI
	uid     string
	node    sensoradapter.CoverageNode
	targets map[string]sensoradapter.CoverageDaemonSet
	pods    map[string][]sensoradapter.CoveragePod
}

func (f *mountedCoverageFixture) ClusterUID(context.Context) (string, error) { return f.uid, nil }
func (f *mountedCoverageFixture) Nodes(context.Context, string) ([]sensoradapter.CoverageNode, error) {
	return []sensoradapter.CoverageNode{f.node}, nil
}
func (f *mountedCoverageFixture) DaemonSet(_ context.Context, t sensoradapter.CoverageTarget) (sensoradapter.CoverageDaemonSet, error) {
	return f.targets[t.Name], nil
}
func (f *mountedCoverageFixture) Pods(_ context.Context, namespace, selector string) ([]sensoradapter.CoveragePod, error) {
	return f.pods[namespace+"/"+selector], nil
}
func (f *mountedCoverageFixture) Reports(context.Context, string, string) ([]sensoradapter.CoverageLease, error) {
	out := []sensoradapter.CoverageLease{}
	for _, l := range f.api.leases {
		if l.Labels[sensoradapter.NodeCoverageLabel] != "v2" {
			continue
		}
		var v sensoradapter.CoverageLease
		b, _ := json.Marshal(l)
		if json.Unmarshal(b, &v) != nil {
			return nil, ErrCluster
		}
		out = append(out, v)
	}
	return out, nil
}
func TestSelectedCoverageMountedGenerationWitnessProbeAndLease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires existing isolated root-owned witness file fixture; not host/provider proof")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	boot, _ := fixtureBootReader(t)
	identityAPI := newLineageIdentityAPIFixture()
	endpoint, _ := lineageGenerationFixture(t, nil)
	spool, e := newLineageSpool(t.TempDir(), uint32(os.Geteuid()))
	if e != nil {
		t.Fatal(e)
	}
	defer spool.Close()
	generation, e := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), identityAPI, boot, endpoint, spool)
	if e != nil {
		t.Fatal("actual local generation fixture refused")
	}
	defer generation.Close()
	parent := t.TempDir()
	observations := filepath.Join(parent, "observations")
	if os.Mkdir(observations, 0750) != nil {
		t.Fatal("witness directory refused")
	}
	podUID := "11111111-1111-4111-8111-111111111111"
	writer, e := openNodeWitness(observations, "sensor-node-a", podUID, uint32(os.Getegid()), true)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	generation.coverage = writer
	if e = writer.publish(ctx, generation.Source()); e != nil {
		t.Fatal("producer witness publication refused")
	}
	reader, e := openNodeWitness(observations, "sensor-node-a", podUID, uint32(os.Getegid()), false)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, e = reader.read(now.Add(31*time.Second), 30*time.Second); e == nil {
		t.Fatal("stale producer witness acquired current authority")
	}
	source := generation.Source()
	selection := sensoradapter.NodeCoverageSelection{SourceProfile: source.Profile, ClusterUID: source.ClusterUID, EnrollmentBinding: source.EnrollmentBinding, MatchLabels: map[string]string{"eks.amazonaws.com/nodegroup": "selected-sensors"}, Sensor: sensoradapter.CoverageTarget{Namespace: "agentsec", Name: "sensor-agent", Release: "zasp", ReleaseNamespace: "agentsec", Image: "example/sensor@sha256:" + strings.Repeat("a", 64), ServiceAccount: "sensor-agent", Container: "sensor-agent"}, Tetragon: sensoradapter.CoverageTarget{Namespace: "tetragon", Name: "zasp-tetragon", Release: "zasp-tetragon", ReleaseNamespace: "tetragon", Image: "example/tetragon@sha256:" + strings.Repeat("c", 64), ServiceAccount: "zasp-tetragon", Container: "tetragon"}}
	api := newMemoryClusterAPI(nil)
	fixture := &mountedCoverageFixture{api: api, uid: source.ClusterUID, targets: map[string]sensoradapter.CoverageDaemonSet{}, pods: map[string][]sensoradapter.CoveragePod{}}
	raw, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": source.NodeName, "uid": source.NodeUID, "labels": selection.MatchLabels}, "spec": map[string]any{"providerID": "aws:///us-west-2a/i-0123456789abcdef0"}, "status": map[string]any{"nodeInfo": map[string]any{"bootID": source.BootID, "kernelVersion": "6.8.1", "operatingSystem": "linux"}, "conditions": []any{map[string]string{"type": "Ready", "status": "True"}}}})
	if json.Unmarshal(raw, &fixture.node) != nil {
		t.Fatal("Node fixture rejected")
	}
	for n, target := range []sensoradapter.CoverageTarget{selection.Sensor, selection.Tetragon} {
		dsUID := []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}[n]
		labels := map[string]string{"app": target.Name}
		var d sensoradapter.CoverageDaemonSet
		raw, _ = json.Marshal(map[string]any{"metadata": map[string]any{"name": target.Name, "namespace": target.Namespace, "uid": dsUID, "generation": 1, "annotations": map[string]string{"meta.helm.sh/release-name": target.Release, "meta.helm.sh/release-namespace": target.Namespace}}, "spec": map[string]any{"selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"nodeSelector": selection.MatchLabels, "serviceAccountName": target.ServiceAccount, "containers": []any{map[string]string{"name": target.Container, "image": target.Image}}}}}, "status": map[string]any{"observedGeneration": 1}})
		if json.Unmarshal(raw, &d) != nil {
			t.Fatal("DS fixture rejected")
		}
		fixture.targets[target.Name] = d
		name, uid := "sensor-node-a", podUID
		if n == 1 {
			name, uid = "tetragon-node-a", "44444444-4444-4444-8444-444444444444"
		}
		var p sensoradapter.CoveragePod
		raw, _ = json.Marshal(map[string]any{"metadata": map[string]any{"name": name, "namespace": target.Namespace, "uid": uid, "labels": labels, "ownerReferences": []any{map[string]any{"kind": "DaemonSet", "name": target.Name, "uid": dsUID, "controller": true}}}, "spec": map[string]any{"nodeName": "node-a", "serviceAccountName": target.ServiceAccount, "containers": []any{map[string]string{"name": target.Container, "image": target.Image}}}, "status": map[string]any{"phase": "Running", "conditions": []any{map[string]string{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": target.Container, "ready": true, "state": map[string]any{"running": map[string]any{"startedAt": now.Add(-time.Minute)}}}}}})
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("Pod fixture rejected")
		}
		fixture.pods[target.Namespace+"/"+sensoradapter.CoverageSelector(labels)] = []sensoradapter.CoveragePod{p}
	}
	kernel, btf := filepath.Join(t.TempDir(), "kernel"), filepath.Join(t.TempDir(), "btf")
	writeSensorFixture(t, kernel, "6.8.1\n", 0444)
	writeSensorFixture(t, btf, "btf", 0444)
	probe, e := NewLocalSensorProbe(LocalSensorProbeConfig{NodeName: "node-a", KernelFile: kernel, BTFFile: btf, MetricsURL: "http://10.0.0.8:2112/metrics", PollInterval: time.Second, Do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.ReplaceAll(tetragonMetricsFixture(), " 1\n", " 0\n")))}, nil
	}, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	report, e := probe.Report(ctx, sensoradapter.StreamResult{})
	if e != nil {
		t.Fatal("actual probe fixture refused")
	}
	sink := &recordingHeartbeatSink{}
	coordinator, e := NewClusterCoordinator(ClusterCoordinatorConfig{Namespace: "agentsec", PodName: "sensor-node-a", NodeName: "node-a", Coverage: &selection, CoverageReader: fixture, Witness: reader, LeaseDuration: 15 * time.Second, ReportTTL: 30 * time.Second, Leases: api, Pods: api, Heartbeats: sink, Now: func() time.Time { return now }})
	if e != nil {
		t.Fatal(e)
	}
	if e = coordinator.Tick(ctx, report); e != nil {
		t.Fatal("mounted v2 heartbeat refused", e)
	}
	if len(sink.values) != 1 || sink.values[0].Status != "healthy" {
		t.Fatal("actual witness/probe/lease inventory flow incomplete")
	}
	// Exact v2 retry retains the original payload, sequence and observation marker.
	now = now.Add(time.Second)
	api.failStateCommitOnce = true
	if e = coordinator.Tick(ctx, report); !errors.Is(e, ErrClusterRetryable) {
		t.Fatal("expected uncertain heartbeat state commit")
	}
	marker := api.leases[clusterStateLeaseName].Annotations[clusterCoveragePendingAnnotation]
	if marker == "" {
		t.Fatal("v2 pending lacks original observation custody")
	}
	now = now.Add(time.Second)
	if e = coordinator.Tick(ctx, report); e != nil || len(sink.values) != 3 || !reflect.DeepEqual(sink.values[1], sink.values[2]) {
		t.Fatal("exact v2 pending retry changed or refused")
	}
	// Reusing the same measured report after producer expiry must not refresh it.
	now = now.Add(31 * time.Second)
	if coordinator.Tick(ctx, report) == nil {
		t.Fatal("stale witness/report restamped after producer stopped")
	}
	if validCoverageWitnessPath(filepath.Join(parent, "other", "observations"), filepath.Join(parent, "producer")) {
		t.Fatal("foreign observation sibling accepted")
	}
}

func TestSelectedCoveragePendingReplayRequiresOriginalCurrentObservation(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"exact retry", "unmarked legacy", "copied payload", "expired", "future", "changed config"} {
		t.Run(mode, func(t *testing.T) {
			api := newMemoryClusterAPI(nil)
			sink := &recordingHeartbeatSink{}
			c := newFixtureCoordinator(t, api, sink, "sensor-node-a", "node-a", func() time.Time { return now })
			// This fixture exercises durable pending replay; fresh aggregation is covered
			// above through the actual producer/witness/probe/Lease composition.
			target := sensoradapter.CoverageTarget{Namespace: "agentsec", Name: "sensor-agent", Release: "zasp", ReleaseNamespace: "agentsec", Image: "example/sensor@sha256:" + strings.Repeat("b", 64), ServiceAccount: "sensor-agent", Container: "sensor-agent"}
			tetra := target
			tetra.Name, tetra.Release, tetra.ServiceAccount, tetra.Container = "zasp-tetragon", "zasp-tetragon", "zasp-tetragon", "tetragon"
			c.config.Coverage = &sensoradapter.NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "11111111-1111-4111-8111-111111111111", EnrollmentBinding: strings.Repeat("a", 64), MatchLabels: map[string]string{"pool": "selected"}, Sensor: target, Tetragon: tetra}
			if c.config.Coverage.Validate() != nil {
				t.Fatal("invalid protected selection fixture")
			}
			heartbeat := sensoradapter.Heartbeat{Sequence: 1, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.1", BTF: true}
			payload, e := encodePendingHeartbeat(heartbeat)
			if e != nil {
				t.Fatal(e)
			}
			observed := now.Add(-time.Second)
			if mode == "expired" {
				observed = now.Add(-31 * time.Second)
			}
			if mode == "future" {
				observed = now.Add(6 * time.Second)
			}
			marker := c.encodeCoveragePending(payload, observed)
			switch mode {
			case "unmarked legacy":
				marker = ""
			case "copied payload":
				heartbeat.Status = "degraded"
				payload, _ = encodePendingHeartbeat(heartbeat)
			case "changed config":
				c.config.Coverage.MatchLabels["pool"] = "other"
			}
			_, e = api.Create(context.Background(), &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: clusterStateLeaseName, Namespace: "agentsec", Labels: ownedLabels(clusterStateAuthority), Annotations: map[string]string{clusterSequenceAnnotation: "0", clusterPendingAnnotation: payload, clusterCoveragePendingAnnotation: marker}}}, metav1.CreateOptions{})
			if e != nil {
				t.Fatal(e)
			}
			before := api.leases[clusterStateLeaseName].DeepCopy()
			got, e := c.pendingOrPrepare(context.Background(), now)
			if mode == "exact retry" {
				if e != nil || !reflect.DeepEqual(got, heartbeat) || c.pendingCoverageMarker != marker {
					t.Fatal("exact retry lost original observation custody")
				}
			} else if e == nil {
				t.Fatal("unknown or stale pending acquired coverage authority")
			}
			if !reflect.DeepEqual(before, api.leases[clusterStateLeaseName]) || len(sink.values) != 0 {
				t.Fatal("unresolved pending was rewritten or sent")
			}
		})
	}
}
