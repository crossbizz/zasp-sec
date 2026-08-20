package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestClusterCoordinatorElectsOneReporterAndAggregatesExactReadyNodes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	api := newMemoryClusterAPI([]corev1.Pod{readyTetragonPod("tetragon-a", "node-a"), readyTetragonPod("tetragon-b", "node-b")})
	sink := &recordingHeartbeatSink{}
	a := newFixtureCoordinator(t, api, sink, "adapter-a", "node-a", func() time.Time { return now })
	b := newFixtureCoordinator(t, api, sink, "adapter-b", "node-b", func() time.Time { return now })
	if err := a.Tick(context.Background(), fixtureNodeReport("node-a", now)); err != nil {
		t.Fatalf("a first Tick: %v", err)
	}
	if err := b.Tick(context.Background(), fixtureNodeReport("node-b", now)); err != nil {
		t.Fatalf("b first Tick: %v", err)
	}
	now = now.Add(time.Second)
	if err := a.Tick(context.Background(), fixtureNodeReport("node-a", now)); err != nil {
		t.Fatalf("a second Tick: %v", err)
	}
	if len(sink.values) != 2 || sink.values[0].Sequence != 1 || sink.values[0].Status != "degraded" || sink.values[1].Sequence != 2 || sink.values[1].Status != "healthy" || sink.values[1].Kernel != "6.8.1" || !sink.values[1].BTF || sink.values[1].EventRate != 14 || sink.values[1].Drops != 2 || !reflect.DeepEqual(sink.values[1].Capabilities, []string{"file", "network", "process"}) {
		t.Fatalf("heartbeats = %#v", sink.values)
	}
}

func TestClusterCoordinatorReplaysPreparedHeartbeatAfterLostStateCommit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	api := newMemoryClusterAPI([]corev1.Pod{readyTetragonPod("tetragon-a", "node-a")})
	api.failStateCommitOnce = true
	sink := &recordingHeartbeatSink{}
	coordinator := newFixtureCoordinator(t, api, sink, "adapter-a", "node-a", func() time.Time { return now })
	if err := coordinator.Tick(context.Background(), fixtureNodeReport("node-a", now)); !errors.Is(err, ErrClusterRetryable) {
		t.Fatalf("first Tick = %v", err)
	}
	if len(sink.values) != 1 {
		t.Fatalf("first heartbeats = %#v", sink.values)
	}
	now = now.Add(time.Second)
	if err := coordinator.Tick(context.Background(), fixtureNodeReport("node-a", now)); err != nil {
		t.Fatalf("replay Tick: %v", err)
	}
	if len(sink.values) != 2 || !reflect.DeepEqual(sink.values[0], sink.values[1]) || sink.values[1].Sequence != 1 {
		t.Fatalf("replayed heartbeats = %#v", sink.values)
	}
}

func TestClusterCoordinatorTakeoverUsesDurablePendingHeartbeat(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	api := newMemoryClusterAPI([]corev1.Pod{readyTetragonPod("tetragon-a", "node-a"), readyTetragonPod("tetragon-b", "node-b")})
	sink := &recordingHeartbeatSink{err: ErrClusterRetryable}
	a := newFixtureCoordinator(t, api, sink, "adapter-a", "node-a", func() time.Time { return now })
	b := newFixtureCoordinator(t, api, sink, "adapter-b", "node-b", func() time.Time { return now })
	if err := a.Tick(context.Background(), fixtureNodeReport("node-a", now)); !errors.Is(err, ErrClusterRetryable) {
		t.Fatalf("prepare Tick = %v", err)
	}
	sink.err = nil
	now = now.Add(16 * time.Second)
	if err := b.Tick(context.Background(), fixtureNodeReport("node-b", now)); err != nil {
		t.Fatalf("takeover Tick: %v", err)
	}
	if len(sink.values) != 2 || !reflect.DeepEqual(sink.values[0], sink.values[1]) || sink.values[1].Sequence != 1 {
		t.Fatalf("takeover heartbeats = %#v", sink.values)
	}
}

func TestClusterCoordinatorFailsClosedOnForeignOrMalformedClusterObjects(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*memoryClusterAPI){
		"foreign leader": func(api *memoryClusterAPI) {
			api.leases[clusterLeaderLeaseName] = &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: clusterLeaderLeaseName, Namespace: "agentsec", ResourceVersion: "1", Labels: map[string]string{"app": "foreign"}}}
		},
		"duplicate tetragon node": func(api *memoryClusterAPI) { api.pods = append(api.pods, readyTetragonPod("tetragon-b", "node-a")) },
		"foreign report": func(api *memoryClusterAPI) {
			api.leases["foreign"] = &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "agentsec", Labels: map[string]string{clusterAuthorityLabel: clusterNodeAuthority}, Annotations: map[string]string{clusterReportAnnotation: "secret"}}}
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api := newMemoryClusterAPI([]corev1.Pod{readyTetragonPod("tetragon-a", "node-a")})
			mutate(api)
			sink := &recordingHeartbeatSink{}
			coordinator := newFixtureCoordinator(t, api, sink, "adapter-a", "node-a", func() time.Time { return now })
			if err := coordinator.Tick(context.Background(), fixtureNodeReport("node-a", now)); err == nil || len(sink.values) != 0 {
				t.Fatalf("Tick = %v, heartbeats=%#v", err, sink.values)
			}
		})
	}
}

func TestNewClusterCoordinatorRejectsUnsafeAuthority(t *testing.T) {
	t.Parallel()
	api := newMemoryClusterAPI(nil)
	sink := &recordingHeartbeatSink{}
	now := func() time.Time { return time.Now().UTC() }
	valid := ClusterCoordinatorConfig{Namespace: "agentsec", PodName: "adapter-a", NodeName: "node-a", LeaseDuration: 15 * time.Second, ReportTTL: 30 * time.Second, Leases: api, Pods: api, Heartbeats: sink, Now: now}
	for name, mutate := range map[string]func(*ClusterCoordinatorConfig){
		"namespace": func(value *ClusterCoordinatorConfig) { value.Namespace = "../secret" }, "pod": func(value *ClusterCoordinatorConfig) { value.PodName = "" }, "node": func(value *ClusterCoordinatorConfig) { value.NodeName = " node" },
		"short lease": func(value *ClusterCoordinatorConfig) { value.LeaseDuration = 4 * time.Second }, "short ttl": func(value *ClusterCoordinatorConfig) { value.ReportTTL = value.LeaseDuration },
		"nil leases": func(value *ClusterCoordinatorConfig) { value.Leases = nil }, "nil pods": func(value *ClusterCoordinatorConfig) { value.Pods = nil }, "nil sink": func(value *ClusterCoordinatorConfig) { value.Heartbeats = nil }, "nil clock": func(value *ClusterCoordinatorConfig) { value.Now = nil },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := valid
			mutate(&value)
			if coordinator, err := NewClusterCoordinator(value); err == nil || coordinator != nil {
				t.Fatalf("NewClusterCoordinator = %#v, %v", coordinator, err)
			}
		})
	}
}

type recordingHeartbeatSink struct {
	values []sensoradapter.Heartbeat
	err    error
}

func (sink *recordingHeartbeatSink) Heartbeat(_ context.Context, value sensoradapter.Heartbeat) error {
	sink.values = append(sink.values, value)
	return sink.err
}

type memoryClusterAPI struct {
	leases              map[string]*coordinationv1.Lease
	pods                []corev1.Pod
	revision            int
	failStateCommitOnce bool
}

func newMemoryClusterAPI(pods []corev1.Pod) *memoryClusterAPI {
	return &memoryClusterAPI{leases: map[string]*coordinationv1.Lease{}, pods: pods}
}
func (api *memoryClusterAPI) Get(_ context.Context, name string, _ metav1.GetOptions) (*coordinationv1.Lease, error) {
	value, ok := api.leases[name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, name)
	}
	return value.DeepCopy(), nil
}
func (api *memoryClusterAPI) Create(_ context.Context, value *coordinationv1.Lease, _ metav1.CreateOptions) (*coordinationv1.Lease, error) {
	if _, ok := api.leases[value.Name]; ok {
		return nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, value.Name)
	}
	api.revision++
	copy := value.DeepCopy()
	copy.ResourceVersion = string(rune('0' + api.revision))
	api.leases[value.Name] = copy
	return copy.DeepCopy(), nil
}
func (api *memoryClusterAPI) Update(_ context.Context, value *coordinationv1.Lease, _ metav1.UpdateOptions) (*coordinationv1.Lease, error) {
	prior, ok := api.leases[value.Name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, value.Name)
	}
	if value.ResourceVersion != prior.ResourceVersion {
		return nil, apierrors.NewConflict(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, value.Name, errors.New("conflict"))
	}
	if value.Name == clusterStateLeaseName && api.failStateCommitOnce && value.Annotations[clusterPendingAnnotation] == "" {
		api.failStateCommitOnce = false
		return nil, apierrors.NewConflict(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, value.Name, errors.New("lost response"))
	}
	api.revision++
	copy := value.DeepCopy()
	copy.ResourceVersion = string(rune('0' + api.revision))
	api.leases[value.Name] = copy
	return copy.DeepCopy(), nil
}
func (api *memoryClusterAPI) List(_ context.Context, options metav1.ListOptions) (*coordinationv1.LeaseList, error) {
	result := &coordinationv1.LeaseList{}
	for _, value := range api.leases {
		if options.LabelSelector == clusterNodeSelector && value.Labels[clusterAuthorityLabel] == clusterNodeAuthority {
			result.Items = append(result.Items, *value.DeepCopy())
		}
	}
	return result, nil
}
func (api *memoryClusterAPI) ListPods(_ context.Context, options metav1.ListOptions) (*corev1.PodList, error) {
	if options.LabelSelector != tetragonPodSelector {
		return nil, errors.New("selector")
	}
	return &corev1.PodList{Items: append([]corev1.Pod(nil), api.pods...)}, nil
}

func newFixtureCoordinator(t *testing.T, api *memoryClusterAPI, sink *recordingHeartbeatSink, pod, node string, now func() time.Time) *ClusterCoordinator {
	t.Helper()
	value, err := NewClusterCoordinator(ClusterCoordinatorConfig{Namespace: "agentsec", PodName: pod, NodeName: node, LeaseDuration: 15 * time.Second, ReportTTL: 30 * time.Second, Leases: api, Pods: api, Heartbeats: sink, Now: now})
	if err != nil {
		t.Fatalf("NewClusterCoordinator: %v", err)
	}
	return value
}
func fixtureNodeReport(node string, now time.Time) NodeReport {
	return NodeReport{NodeName: node, ObservedAt: now, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.1", BTF: true, EventRate: 7, Drops: 1}
}
func readyTetragonPod(name, node string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "agentsec"}, Spec: corev1.PodSpec{NodeName: node}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
}
