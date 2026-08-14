package main

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const testMarker = "0123456789abcdef"

func TestRunProofIndexesOneScopedEventAndRejectsTheOtherOrganization(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend()
	result, err := RunProof(context.Background(), ProofOptions{
		Endpoint:       "http://127.0.0.1:49152",
		Marker:         testMarker,
		Events:         backend,
		Admin:          backend,
		CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("RunProof returned %v", err)
	}
	if result != (ProofResult{Indexed: true, ScopedQuery: true, CrossOrganizationZero: true, Cleanup: true, Audit: true}) {
		t.Fatalf("result = %#v", result)
	}
	if len(backend.indexes) != 0 {
		t.Fatal("proof index remained after cleanup")
	}
	if got, want := backend.queryOrganizations, []string{"org-a-" + testMarker, "org-b-" + testMarker}; !slices.Equal(got, want) {
		t.Fatalf("query Organizations = %v, want exact A then B scopes", got)
	}
	assertSubsequence(t, backend.operations, []string{
		"list-indexes", "create-index", "inspect-index", "index-event",
		"query-session", "query-session", "inspect-index", "list-documents",
		"delete-index", "list-indexes", "list-indexes",
	})
	if backend.lastSpec.Dynamic != "strict" || backend.lastSpec.Shards != 1 || backend.lastSpec.Replicas != 0 {
		t.Fatal("proof did not create the strict one-shard zero-replica projection")
	}
	wantFields := map[string]string{
		"event_id": "keyword", "organization_id": "keyword", "workspace_id": "keyword",
		"environment_id": "keyword", "session_id": "keyword", "agent_id": "keyword",
		"source": "keyword", "source_event_id": "keyword", "event_class": "keyword",
		"action": "keyword", "decision": "keyword", "event_time": "date:strict_date_time",
	}
	if !equalStringMaps(backend.lastSpec.Fields, wantFields) {
		t.Fatalf("mapping fields = %v, want exact normalized metadata-only schema", backend.lastSpec.Fields)
	}
}

func TestRunProofReconcilesOnlyExactAmbiguousMutations(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"create-index", "index-event", "delete-index"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			backend := newFakeBackend()
			backend.ambiguous[operation] = true
			result, err := RunProof(context.Background(), proofOptions(backend))
			if err != nil {
				t.Fatalf("RunProof returned %v", err)
			}
			if !result.Indexed || !result.ScopedQuery || !result.CrossOrganizationZero || !result.Cleanup || !result.Audit {
				t.Fatalf("result = %#v", result)
			}
			if len(backend.indexes) != 0 {
				t.Fatal("ambiguous mutation left a proof index")
			}
		})
	}
}

func TestRunProofRejectsPrefixCollisionsAndCrossOrganizationLeakage(t *testing.T) {
	t.Parallel()
	t.Run("any generated-prefix collision", func(t *testing.T) {
		backend := newFakeBackend()
		state := IndexState{Name: proofPrefix + testMarker + "-foreign"}
		backend.indexes[state.Name] = &fakeIndex{state: state}
		if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errOwnership) {
			t.Fatalf("RunProof error = %v, want ownership", err)
		}
		if slices.Contains(backend.operations, "create-index") {
			t.Fatal("created an index after a generated-prefix collision")
		}
	})
	t.Run("Organization B leakage", func(t *testing.T) {
		backend := newFakeBackend()
		backend.leakCrossOrganization = true
		if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errScope) {
			t.Fatalf("RunProof error = %v, want scope", err)
		}
		if len(backend.indexes) != 0 {
			t.Fatal("scope failure bypassed cleanup")
		}
	})
	t.Run("EventStore scope rejection remains a scope failure", func(t *testing.T) {
		backend := newFakeBackend()
		backend.failOnce["query-session"] = errScope
		if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errScope) {
			t.Fatalf("RunProof error = %v, want scope", err)
		}
		if len(backend.indexes) != 0 {
			t.Fatal("EventStore scope rejection bypassed cleanup")
		}
	})
	t.Run("duplicate Organization A hits", func(t *testing.T) {
		backend := newFakeBackend()
		backend.duplicateOrganizationA = true
		if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errContent) {
			t.Fatalf("RunProof error = %v, want content", err)
		}
		if len(backend.indexes) != 0 {
			t.Fatal("duplicate result failure bypassed cleanup")
		}
	})
}

func TestRunProofRetainsIndexAcrossPostCreateFailures(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"index-event", "query-session"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			backend := newFakeBackend()
			backend.failOnce[operation] = errors.New("provider detail")
			if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errProvider) {
				t.Fatalf("RunProof error = %v, want provider", err)
			}
			if len(backend.indexes) != 0 {
				t.Fatal("post-create failure stranded the proof index")
			}
			assertSubsequence(t, backend.operations, []string{"create-index", operation, "inspect-index", "list-documents", "delete-index", "list-indexes"})
		})
	}
}

func TestRunProofReprovesOwnershipAndGivesCleanupFailurePrecedence(t *testing.T) {
	t.Parallel()
	t.Run("changed mapping metadata blocks delete", func(t *testing.T) {
		backend := newFakeBackend()
		backend.mutateAt["inspect-index"] = 2
		if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errCleanup) {
			t.Fatalf("RunProof error = %v, want cleanup", err)
		}
		if slices.Contains(backend.operations, "delete-index") {
			t.Fatal("changed projection was deleted")
		}
	})
	t.Run("cleanup failure overrides query failure", func(t *testing.T) {
		backend := newFakeBackend()
		backend.failOnce["query-session"] = errors.New("provider detail")
		backend.fail["delete-index"] = errors.New("provider detail")
		if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errCleanup) {
			t.Fatalf("RunProof error = %v, want cleanup precedence", err)
		}
	})
}

func TestRunProofRecoversPanicAndCleansWithIndependentContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	backend := newFakeBackend()
	backend.panicAt = "query-session"
	backend.cancel = cancel
	if _, err := RunProof(ctx, proofOptions(backend)); !errors.Is(err, errProvider) {
		t.Fatalf("RunProof error = %v, want provider", err)
	}
	if len(backend.indexes) != 0 {
		t.Fatal("panic or canceled request context bypassed independent cleanup")
	}
}

func TestRunProofContainsCleanupPanicWithCleanupPrecedence(t *testing.T) {
	t.Parallel()
	backend := newFakeBackend()
	backend.panicAtCount["inspect-index"] = 2
	if _, err := RunProof(context.Background(), proofOptions(backend)); !errors.Is(err, errCleanup) {
		t.Fatalf("RunProof error = %v, want cleanup", err)
	}
}

func TestOrganizationScopeAndNormalizedEventSchemaFailClosed(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{"", "Org-A", " leading", strings.Repeat("a", 129)} {
		if _, err := newOrganizationScope(invalid); !errors.Is(err, errScope) {
			t.Fatalf("newOrganizationScope accepted %q", invalid)
		}
	}
	typeOfEvent := reflect.TypeOf(NormalizedSessionEvent{})
	for index := 0; index < typeOfEvent.NumField(); index++ {
		name := strings.ToLower(typeOfEvent.Field(index).Name)
		for _, forbidden := range []string{"prompt", "response", "content", "body", "secret"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("normalized event exposes forbidden durable field %q", name)
			}
		}
	}
}

func proofOptions(backend *fakeBackend) ProofOptions {
	return ProofOptions{
		Endpoint: "http://127.0.0.1:49152", Marker: testMarker,
		Events: backend, Admin: backend, CleanupTimeout: time.Second, PollInterval: time.Millisecond,
	}
}

type fakeBackend struct {
	indexes                map[string]*fakeIndex
	operations             []string
	queryOrganizations     []string
	lastSpec               IndexSpec
	counts                 map[string]int
	fail                   map[string]error
	failOnce               map[string]error
	ambiguous              map[string]bool
	mutateAt               map[string]int
	leakCrossOrganization  bool
	duplicateOrganizationA bool
	panicAt                string
	panicAtCount           map[string]int
	cancel                 context.CancelFunc
}

type fakeIndex struct {
	state     IndexState
	documents []NormalizedSessionEvent
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		indexes: map[string]*fakeIndex{}, counts: map[string]int{}, fail: map[string]error{},
		failOnce: map[string]error{}, ambiguous: map[string]bool{}, mutateAt: map[string]int{}, panicAtCount: map[string]int{},
	}
}

func (f *fakeBackend) step(operation string) error {
	f.operations = append(f.operations, operation)
	f.counts[operation]++
	if f.panicAt == operation || f.panicAtCount[operation] == f.counts[operation] {
		if f.cancel != nil {
			f.cancel()
		}
		panic("provider detail")
	}
	if err := f.failOnce[operation]; err != nil {
		delete(f.failOnce, operation)
		return err
	}
	return f.fail[operation]
}

func (f *fakeBackend) ListIndexes(_ context.Context, prefix string) ([]IndexState, error) {
	if err := f.step("list-indexes"); err != nil {
		return nil, err
	}
	var result []IndexState
	for name, index := range f.indexes {
		if strings.HasPrefix(name, prefix) {
			result = append(result, cloneIndexState(index.state))
		}
	}
	return result, nil
}

func (f *fakeBackend) CreateIndex(_ context.Context, spec IndexSpec) (IndexState, error) {
	if err := f.step("create-index"); err != nil {
		return IndexState{}, err
	}
	if _, exists := f.indexes[spec.Name]; exists {
		return IndexState{}, errors.New("provider detail")
	}
	f.lastSpec = cloneIndexSpec(spec)
	state := IndexState{Name: spec.Name, Marker: spec.Marker, Role: spec.Role, Dynamic: spec.Dynamic, Shards: spec.Shards, Replicas: spec.Replicas, Fields: cloneStringMap(spec.Fields)}
	f.indexes[spec.Name] = &fakeIndex{state: state}
	if f.ambiguous["create-index"] {
		return IndexState{}, errors.New("provider detail")
	}
	return cloneIndexState(state), nil
}

func (f *fakeBackend) InspectIndex(_ context.Context, name string) (IndexState, error) {
	if err := f.step("inspect-index"); err != nil {
		return IndexState{}, err
	}
	index, exists := f.indexes[name]
	if !exists {
		return IndexState{}, errors.New("provider detail")
	}
	state := cloneIndexState(index.state)
	if f.mutateAt["inspect-index"] == f.counts["inspect-index"] {
		state.Marker = "foreign-marker"
		index.state = state
	}
	return state, nil
}

func (f *fakeBackend) ListDocuments(_ context.Context, name string, limit int) ([]NormalizedSessionEvent, error) {
	if err := f.step("list-documents"); err != nil {
		return nil, err
	}
	index, exists := f.indexes[name]
	if !exists || limit < 2 {
		return nil, errors.New("provider detail")
	}
	return append([]NormalizedSessionEvent(nil), index.documents...), nil
}

func (f *fakeBackend) DeleteIndex(_ context.Context, name string) error {
	if err := f.step("delete-index"); err != nil {
		return err
	}
	delete(f.indexes, name)
	if f.ambiguous["delete-index"] {
		return errors.New("provider detail")
	}
	return nil
}

func (f *fakeBackend) IndexSessionEvent(_ context.Context, scope OrganizationScope, event NormalizedSessionEvent) error {
	if err := f.step("index-event"); err != nil {
		return err
	}
	index := f.onlyIndex()
	if scope.OrganizationID() == "" || scope.OrganizationID() != event.OrganizationID || index == nil {
		return errors.New("provider detail")
	}
	index.documents = append(index.documents, event)
	if f.ambiguous["index-event"] {
		return errors.New("provider detail")
	}
	return nil
}

func (f *fakeBackend) QuerySession(_ context.Context, scope OrganizationScope, filter SessionFilter) ([]NormalizedSessionEvent, error) {
	if err := f.step("query-session"); err != nil {
		return nil, err
	}
	f.queryOrganizations = append(f.queryOrganizations, scope.OrganizationID())
	index := f.onlyIndex()
	if index == nil || scope.OrganizationID() == "" || filter.SessionID == "" || filter.EnvironmentID == "" {
		return nil, errors.New("provider detail")
	}
	var result []NormalizedSessionEvent
	for _, event := range index.documents {
		if event.OrganizationID == scope.OrganizationID() && event.SessionID == filter.SessionID && event.EnvironmentID == filter.EnvironmentID {
			result = append(result, event)
		}
	}
	if f.leakCrossOrganization && strings.HasPrefix(scope.OrganizationID(), "org-b-") && len(index.documents) == 1 {
		result = append(result, index.documents[0])
	}
	if f.duplicateOrganizationA && strings.HasPrefix(scope.OrganizationID(), "org-a-") && len(result) == 1 {
		result = append(result, result[0])
	}
	return result, nil
}

func (f *fakeBackend) onlyIndex() *fakeIndex {
	for _, index := range f.indexes {
		return index
	}
	return nil
}

func assertSubsequence(t *testing.T, got, want []string) {
	t.Helper()
	position := 0
	for _, operation := range got {
		if position < len(want) && operation == want[position] {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("operations = %v, missing ordered subsequence %v", got, want)
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneIndexSpec(source IndexSpec) IndexSpec {
	source.Fields = cloneStringMap(source.Fields)
	return source
}

func cloneIndexState(source IndexState) IndexState {
	source.Fields = cloneStringMap(source.Fields)
	return source
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
