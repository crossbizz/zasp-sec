package main

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The Node inventory is an independent Kubernetes API observation. A missing
// Tetragon Pod must not remove an actual selected node from expected coverage.
// These tests intentionally compile against the pre-change production API.
type selectedNodeCoverageAPI struct {
	*memoryClusterAPI
	nodes     []corev1.Node
	nodeReads int
}

func (api *selectedNodeCoverageAPI) ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error) {
	api.nodeReads++
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrClusterRetryable
	}
	return &corev1.NodeList{Items: append([]corev1.Node(nil), api.nodes...)}, nil
}
func coverageContractNode(name, uid string) corev1.Node {
	provider := "aws:///us-west-2a/i-0123456789abcdef0"
	if name == "node-b" {
		provider = "aws:///us-west-2a/i-0123456789abcdef1"
	}
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid), Labels: map[string]string{"eks.amazonaws.com/nodegroup": "selected-sensors", "kubernetes.io/os": "linux"}}, Spec: corev1.NodeSpec{ProviderID: provider}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", KernelVersion: "6.8.1", OperatingSystem: "linux"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
}

// Missing-node coverage is exercised by the shared reader's multi-resource
// acceptance matrix, mounted by the production coordinator and preflight.
func TestSensorReportTimestampCannotBeRefreshedByCoordinator(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	api := newMemoryClusterAPI([]corev1.Pod{readyTetragonPod("tetragon-a", "node-a")})
	sink := &recordingHeartbeatSink{}
	coordinator := newFixtureCoordinator(t, api, sink, "adapter-a", "node-a", func() time.Time { return now })
	stale := fixtureNodeReport("node-a", now.Add(-2*time.Minute))
	_ = coordinator.Tick(context.Background(), stale)
	for _, heartbeat := range sink.values {
		if heartbeat.Status == "healthy" {
			t.Fatal("stale measured report was restamped as current healthy coverage")
		}
	}
}
