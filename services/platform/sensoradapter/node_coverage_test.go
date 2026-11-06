package sensoradapter

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type coverageReaderFixture struct {
	uid               string
	nodes             []CoverageNode
	ds                map[string]CoverageDaemonSet
	pods              map[string][]CoveragePod
	leases            []CoverageLease
	nodeCalls         int
	deny              bool
	secondNodeChanged bool
	secondDelay       time.Duration
}

func (f *coverageReaderFixture) ClusterUID(context.Context) (string, error) {
	if f.deny {
		return "", ErrNodeCoverage
	}
	return f.uid, nil
}
func (f *coverageReaderFixture) Nodes(context.Context, string) ([]CoverageNode, error) {
	f.nodeCalls++
	if f.nodeCalls == 2 && f.secondDelay > 0 {
		time.Sleep(f.secondDelay)
	}
	if f.secondNodeChanged && f.nodeCalls == 2 {
		nodes := append([]CoverageNode(nil), f.nodes...)
		nodes[0].Spec.Unschedulable = true
		return nodes, nil
	}
	return f.nodes, nil
}
func (f *coverageReaderFixture) DaemonSet(_ context.Context, t CoverageTarget) (CoverageDaemonSet, error) {
	return f.ds[t.Name], nil
}
func (f *coverageReaderFixture) Pods(_ context.Context, ns, selector string) ([]CoveragePod, error) {
	return f.pods[ns+"/"+selector], nil
}
func (f *coverageReaderFixture) Reports(context.Context, string, string) ([]CoverageLease, error) {
	return f.leases, nil
}
func coverageFixture(t *testing.T, now time.Time) (NodeCoverageSelection, *coverageReaderFixture) {
	t.Helper()
	s := NodeCoverageSelection{SourceProfile: "tetragon-local-stream-v2", ClusterUID: "11111111-1111-4111-8111-111111111111", EnrollmentBinding: strings.Repeat("a", 64), MatchLabels: map[string]string{"eks.amazonaws.com/nodegroup": "selected-sensors"}, Sensor: CoverageTarget{Namespace: "edge", Name: "sensor-agent", Release: "zasp", ReleaseNamespace: "edge", Image: "example/sensor@sha256:" + strings.Repeat("b", 64), ServiceAccount: "sensor-agent", Container: "sensor-agent"}, Tetragon: CoverageTarget{Namespace: "tetragon", Name: "zasp-tetragon", Release: "zasp-tetragon", ReleaseNamespace: "tetragon", Image: "quay.io/cilium/tetragon@sha256:" + strings.Repeat("c", 64), ServiceAccount: "zasp-tetragon", Container: "tetragon"}}
	f := &coverageReaderFixture{uid: s.ClusterUID, ds: map[string]CoverageDaemonSet{}, pods: map[string][]CoveragePod{}}
	for index, target := range []CoverageTarget{s.Sensor, s.Tetragon} {
		d := CoverageDaemonSet{}
		d.Metadata = CoverageMeta{Name: target.Name, Namespace: target.Namespace, UID: []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}[index], Generation: 1, Annotations: map[string]string{"meta.helm.sh/release-name": target.Release, "meta.helm.sh/release-namespace": target.Namespace}}
		d.Status.ObservedGeneration = 1
		d.Spec.Selector.MatchLabels = map[string]string{"app": target.Name}
		d.Spec.Template.Metadata.Labels = d.Spec.Selector.MatchLabels
		d.Spec.Template.Spec.NodeSelector = s.MatchLabels
		d.Spec.Template.Spec.ServiceAccountName = target.ServiceAccount
		d.Spec.Template.Spec.Containers = []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		}{{target.Container, target.Image}}
		f.ds[target.Name] = d
	}
	for index, name := range []string{"node-a", "node-b"} {
		node := CoverageNode{Metadata: CoverageMeta{Name: name, UID: []string{"44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"}[index], Labels: s.MatchLabels}}
		node.Spec.ProviderID = []string{"aws:///us-west-2a/i-0123456789abcdef0", "aws:///us-west-2a/i-0123456789abcdef1"}[index]
		node.Status.NodeInfo.BootID = "66666666-6666-4666-8666-666666666666"
		node.Status.NodeInfo.OperatingSystem = "linux"
		node.Status.NodeInfo.KernelVersion = "6.8.1"
		node.Status.Conditions = []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		}{{"Ready", "True"}}
		f.nodes = append(f.nodes, node)
		r := NodeCoverageV2{Schema: NodeCoverageSchema, EnrollmentBinding: s.EnrollmentBinding, ClusterUID: s.ClusterUID, NodeName: name, NodeUID: node.Metadata.UID, BootID: node.Status.NodeInfo.BootID, GenerationID: "77777777-7777-4777-8777-777777777777", SourceProfile: s.SourceProfile, IdentityObservedAt: now.Add(-time.Second), MeasuredAt: now, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.1", BTF: true}
		for j, target := range []CoverageTarget{s.Sensor, s.Tetragon} {
			d := f.ds[target.Name]
			podUID := []string{"88888888-8888-4888-8888-888888888888", "99999999-9999-4999-8999-999999999999", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}[index*2+j]
			pod := CoveragePod{}
			raw, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": target.Name + "-" + name, "namespace": target.Namespace, "uid": podUID, "labels": d.Spec.Selector.MatchLabels, "ownerReferences": []any{map[string]any{"uid": d.Metadata.UID, "kind": "DaemonSet", "name": target.Name, "controller": true}}}, "spec": map[string]any{"nodeName": name, "serviceAccountName": target.ServiceAccount, "containers": []any{map[string]any{"name": target.Container, "image": target.Image}}}, "status": map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": target.Container, "ready": true, "state": map[string]any{"running": map[string]any{"startedAt": now.Add(-time.Minute)}}}}}})
			if json.Unmarshal(raw, &pod) != nil {
				t.Fatal("coverage API fixture rejected")
			}
			key := target.Namespace + "/" + CoverageSelector(d.Spec.Selector.MatchLabels)
			f.pods[key] = append(f.pods[key], pod)
			if j == 0 {
				r.ReporterPodName, r.ReporterPodUID = pod.Metadata.Name, podUID
			} else {
				r.TetragonPodName, r.TetragonPodUID = pod.Metadata.Name, podUID
			}
		}
		encoded, e := EncodeNodeCoverage(r)
		if e != nil {
			t.Fatal(e)
		}
		lease := CoverageLease{Metadata: CoverageMeta{Name: CoverageLeaseName(r), Namespace: s.Sensor.Namespace, Annotations: map[string]string{NodeCoverageAnnotation: encoded}}}
		holder := r.ReporterPodName
		seconds := int32(30)
		lease.Spec.HolderIdentity = &holder
		lease.Spec.LeaseDurationSeconds = &seconds
		observed := now
		lease.Spec.RenewTime = &observed
		f.leases = append(f.leases, lease)
	}
	return s, f
}
func TestSelectedNodeCoverageUsesInventoryCurrentReleaseAndFreshIdentity(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"complete", "missing selected pod", "reused node name", "reboot", "replaced DS", "foreign release", "selector mismatch", "stale report", "foreign binding", "old pod UID", "empty inventory", "forbidden", "node changed during observation", "missing intended container", "expired during observation"} {
		t.Run(mode, func(t *testing.T) {
			s, f := coverageFixture(t, now)
			switch mode {
			case "missing selected pod":
				key := s.Tetragon.Namespace + "/" + CoverageSelector(f.ds[s.Tetragon.Name].Spec.Selector.MatchLabels)
				f.pods[key] = f.pods[key][:1]
			case "reused node name":
				f.nodes[1].Metadata.UID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
			case "reboot":
				f.nodes[1].Status.NodeInfo.BootID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			case "replaced DS":
				d := f.ds[s.Sensor.Name]
				d.Metadata.UID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
				f.ds[s.Sensor.Name] = d
			case "foreign release":
				d := f.ds[s.Tetragon.Name]
				d.Metadata.Annotations["meta.helm.sh/release-name"] = "foreign"
				f.ds[s.Tetragon.Name] = d
			case "selector mismatch":
				d := f.ds[s.Tetragon.Name]
				d.Spec.Template.Spec.NodeSelector = map[string]string{"pool": "foreign"}
				f.ds[s.Tetragon.Name] = d
			case "stale report", "foreign binding":
				r, _ := DecodeNodeCoverage(f.leases[1].Metadata.Annotations[NodeCoverageAnnotation])
				if mode == "stale report" {
					r.MeasuredAt = now.Add(-time.Hour)
				} else {
					r.EnrollmentBinding = strings.Repeat("f", 64)
				}
				v, _ := EncodeNodeCoverage(r)
				f.leases[1].Metadata.Annotations[NodeCoverageAnnotation] = v
			case "old pod UID":
				key := s.Sensor.Namespace + "/" + CoverageSelector(f.ds[s.Sensor.Name].Spec.Selector.MatchLabels)
				f.pods[key][1].Metadata.UID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
			case "empty inventory":
				f.nodes = nil
			case "forbidden":
				f.deny = true
			case "node changed during observation":
				f.secondNodeChanged = true
			case "expired during observation":
				for i := range f.leases {
					r, _ := DecodeNodeCoverage(f.leases[i].Metadata.Annotations[NodeCoverageAnnotation])
					r.MeasuredAt, r.IdentityObservedAt = now.Add(-30*time.Second+10*time.Millisecond), now.Add(-30*time.Second+10*time.Millisecond)
					f.leases[i].Metadata.Annotations[NodeCoverageAnnotation], _ = EncodeNodeCoverage(r)
				}
				f.secondDelay = 20 * time.Millisecond
			case "missing intended container":
				key := s.Sensor.Namespace + "/" + CoverageSelector(f.ds[s.Sensor.Name].Spec.Selector.MatchLabels)
				f.pods[key][1].Spec.Containers = nil
			}
			result, e := ObserveNodeCoverage(context.Background(), f, s, now, 30*time.Second)
			if mode == "complete" {
				if e != nil || !result.Complete || result.Nodes != 2 || f.nodeCalls != 2 {
					t.Fatal("complete real resource set not reconciled")
				}
			} else if e == nil && result.Complete {
				t.Fatal("incomplete or misbound selected set became healthy")
			}
		})
	}
}

func TestSelectedCoverageHTTPReaderKeepsBoundedReadAuthority(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"consistent pages", "changed list version", "oversized continuation", "redirect", "foreign daemonset"} {
		t.Run(mode, func(t *testing.T) {
			selection, fixture := coverageFixture(t, now)
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/nodes" || r.Header.Get("Authorization") != "Bearer explicit-bounded-coverage-token" || r.URL.Query().Get("labelSelector") != CoverageSelector(selection.MatchLabels) || r.URL.Query().Get("limit") != "200" {
					t.Error("reader exceeded configured GET authority")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if mode == "redirect" {
					http.Redirect(w, r, serverURLForCoverageRedirect, http.StatusFound)
					return
				}
				version, next, index := "123", "page2", 0
				if r.URL.Query().Get("continue") != "" {
					if r.URL.Query().Get("continue") != "page2" {
						t.Error("unexpected continuation")
					}
					next, index = "", 1
					if mode == "changed list version" {
						version = "124"
					}
				}
				if mode == "oversized continuation" {
					next = strings.Repeat("x", 4097)
				}
				json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": version, "continue": next}, "items": []CoverageNode{fixture.nodes[index]}})
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			reader, e := NewCoverageHTTPReader(server.URL, ca, func(context.Context) ([]byte, error) { return []byte("explicit-bounded-coverage-token"), nil }, selection)
			if e != nil {
				t.Fatal("explicit read authority refused")
			}
			defer reader.Close()
			if mode == "foreign daemonset" {
				foreign := selection.Sensor
				foreign.Name = "foreign"
				if _, e := reader.DaemonSet(context.Background(), foreign); e == nil || calls != 0 {
					t.Fatal("foreign target reached transport")
				}
				return
			}
			nodes, e := reader.Nodes(context.Background(), CoverageSelector(selection.MatchLabels))
			if mode == "consistent pages" {
				if e != nil || len(nodes) != 2 || calls != 2 {
					t.Fatal("consistent paginated inventory lost")
				}
			} else if e == nil || calls > 2 {
				t.Fatal("ambiguous or unbounded read accepted")
			}
		})
	}
}

// A redirect must be refused before any request to this unrelated origin.
const serverURLForCoverageRedirect = "https://unconfigured.invalid/forbidden"
