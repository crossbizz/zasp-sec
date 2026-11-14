package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

// scriptedConfigMaps answers each call from a function; a nil function
// fails the test, so a test states every API call it expects.
type scriptedConfigMaps struct {
	t      *testing.T
	get    func(string) (*corev1.ConfigMap, error)
	create func(*corev1.ConfigMap) (*corev1.ConfigMap, error)
	update func(*corev1.ConfigMap) (*corev1.ConfigMap, error)
}

func (api *scriptedConfigMaps) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
	if api.get == nil {
		api.t.Fatal("unexpected Get")
	}
	return api.get(name)
}

func (api *scriptedConfigMaps) Create(_ context.Context, value *corev1.ConfigMap, _ metav1.CreateOptions) (*corev1.ConfigMap, error) {
	if api.create == nil {
		api.t.Fatal("unexpected Create")
	}
	return api.create(value)
}

func (api *scriptedConfigMaps) Update(_ context.Context, value *corev1.ConfigMap, _ metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	if api.update == nil {
		api.t.Fatal("unexpected Update")
	}
	return api.update(value)
}

func egressNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
}

func egressDocument(now time.Time, workloads ...agentsignals.EgressWorkload) agentsignals.EgressObservations {
	if workloads == nil {
		workloads = []agentsignals.EgressWorkload{}
	}
	return agentsignals.EgressObservations{Version: agentsignals.EgressObservationsVersion, Node: "node-a", GeneratedAt: agentsignals.FormatEgressTime(now), Workloads: workloads}
}

func egressWorkload(name, token string, seen time.Time) agentsignals.EgressWorkload {
	return agentsignals.EgressWorkload{Namespace: "shop", Kind: "Deployment", Name: name, Destinations: []agentsignals.EgressDestination{{Token: token, LastSeen: agentsignals.FormatEgressTime(seen)}}}
}

func TestPublishEgressObservationsFailsClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	document := egressDocument(now, egressWorkload("support-bot", "openai", now))
	apiDown := errors.New("connection refused")
	for name, api := range map[string]*scriptedConfigMaps{
		"get fails": {get: func(string) (*corev1.ConfigMap, error) { return nil, apiDown }},
		"get forbidden": {get: func(name string) (*corev1.ConfigMap, error) {
			return nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, name, apiDown)
		}},
		"get returns nothing": {get: func(string) (*corev1.ConfigMap, error) { return nil, nil }},
		"create fails": {
			get:    func(name string) (*corev1.ConfigMap, error) { return nil, egressNotFound(name) },
			create: func(*corev1.ConfigMap) (*corev1.ConfigMap, error) { return nil, apiDown },
		},
		"update fails": {
			get: func(name string) (*corev1.ConfigMap, error) {
				return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name}}, nil
			},
			update: func(*corev1.ConfigMap) (*corev1.ConfigMap, error) {
				return nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "x", apiDown)
			},
		},
	} {
		api.t = t
		if err := publishEgressObservations(ctx, api, document); !errors.Is(err, errEgressPublish) {
			t.Errorf("%s: err = %v, want errEgressPublish", name, err)
		}
	}
}

func TestPublishEgressObservationsRefusesInvalidDocumentsBeforeTheAPI(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	api := &scriptedConfigMaps{t: t} // any API call fails the test
	badNode := egressDocument(now, egressWorkload("support-bot", "openai", now))
	badNode.Node = "Node_A"
	badVersion := egressDocument(now)
	badVersion.Version = "egress-observations-v0"
	unsorted := egressDocument(now, egressWorkload("zeta", "openai", now), egressWorkload("alpha", "openai", now))
	// The tracker holds up to MaximumEgressWorkloads workloads, but with
	// long names that many do not fit in one document.
	var large []agentsignals.EgressWorkload
	for index := range agentsignals.MaximumEgressWorkloads {
		name := indexedAddress(index).String() + "-" + strings.Repeat("w", 200)
		large = append(large, agentsignals.EgressWorkload{Namespace: strings.Repeat("n", 63), Kind: "Deployment", Name: name, Destinations: []agentsignals.EgressDestination{{Token: "openai", LastSeen: agentsignals.FormatEgressTime(now)}}})
	}
	oversized := egressDocument(now, large...)
	oversized.Normalize()
	for name, document := range map[string]agentsignals.EgressObservations{"invalid node": badNode, "unknown version": badVersion, "unsorted workloads": unsorted, "oversized": oversized} {
		if err := publishEgressObservations(ctx, api, document); !errors.Is(err, errEgressPublish) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPublishEgressObservationsTakesOverAndClearsTheNodeConfigMap(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	api := fake.NewSimpleClientset().CoreV1().ConfigMaps("zasp-edge")
	name := egressConfigMapName("node-a")
	// A ConfigMap of the node's name that carries foreign content.
	if _, err := api.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"owner": "someone-else"}, Annotations: map[string]string{"note": "kept"}},
		Data:       map[string]string{"other.json": "{}"}, BinaryData: map[string][]byte{"blob": {1, 2, 3}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadEgressObservations(ctx, api, "node-a"); ok {
		t.Fatal("restored a ConfigMap this sensor did not label")
	}
	if err := publishEgressObservations(ctx, api, egressDocument(now, egressWorkload("support-bot", "openai", now))); err != nil {
		t.Fatal(err)
	}
	stored, err := api.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Labels) != 2 || stored.Labels["owner"] != "" || stored.Labels[agentsignals.EgressObservationsLabel] != agentsignals.EgressObservationsLabelValue || stored.BinaryData != nil || len(stored.Data) != 1 || stored.Annotations["note"] != "kept" {
		t.Fatalf("stored = %+v", stored)
	}
	// When every observation has aged out, the stale document is replaced
	// by an empty one rather than left behind.
	if err := publishEgressObservations(ctx, api, egressDocument(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	loaded, ok := loadEgressObservations(ctx, api, "node-a")
	if !ok || len(loaded.Workloads) != 0 || loaded.GeneratedAt != agentsignals.FormatEgressTime(now.Add(time.Hour)) {
		t.Fatalf("loaded = %+v, %v", loaded, ok)
	}
	// A labelled ConfigMap whose body is not a valid document is not restored.
	stored, _ = api.Get(ctx, name, metav1.GetOptions{})
	stored.Data[agentsignals.EgressObservationsKey] = `{"version":"egress-observations-v1","node":"node-a","extra":true}`
	if _, err := api.Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadEgressObservations(ctx, api, "node-a"); ok {
		t.Fatal("restored a corrupt document")
	}
}

func TestEgressConfigMapNameIsStableAndBounded(t *testing.T) {
	long := strings.Repeat("n", 253)
	if egressConfigMapName("node-a") != egressConfigMapName("node-a") || egressConfigMapName("node-a") == egressConfigMapName("node-b") {
		t.Fatal("names are not a stable function of the node")
	}
	if name := egressConfigMapName(long); len(name) != len("zasp-egress-")+24 || !validKubernetesName(name) || strings.Contains(name, "nnnn") {
		t.Fatalf("name = %q", name)
	}
}
