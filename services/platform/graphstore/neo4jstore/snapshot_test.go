package neo4jstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const (
	integrationID = "pid_00000000-0000-4000-8000-000000000007"
	snapshot7ID   = "pid_00000000-0000-4000-8000-000000000008"
	snapshot8ID   = "pid_00000000-0000-4000-8000-000000000009"
)

func TestReplaceSnapshotUsesOneLockedTransactionAndExactReplay(t *testing.T) {
	input := validSnapshotProjection(7, snapshot7ID)
	before := cloneTestSnapshotProjection(input)
	fresh := validSnapshotWriteSession(input, emptySnapshotMarker(), 0, 0)
	replay := validSnapshotReplaySession(input)
	provider := &fakeProvider{sessions: []graphSession{fresh, replay}}
	adapter, err := newAdapterForProvider(provider, databaseName)
	if err != nil {
		t.Fatal(err)
	}

	want := snapshotAcknowledgement(input, false, 0, 0)
	got, err := adapter.ReplaceSnapshot(context.Background(), input)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReplaceSnapshot() = (%#v, %v), want %#v", got, err, want)
	}
	want.Replayed = true
	got, err = adapter.ReplaceSnapshot(context.Background(), input)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReplaceSnapshot(replay) = (%#v, %v), want %#v", got, err, want)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatalf("ReplaceSnapshot mutated input: %#v", input)
	}

	if !reflect.DeepEqual(fresh.tx.queries, []string{lockSnapshotQuery, removeSnapshotEdgesQuery, removeSnapshotNodesQuery, upsertSnapshotNodesQuery, upsertSnapshotEdgesQuery, activateSnapshotQuery, readbackSnapshotQuery}) {
		t.Fatalf("write queries = %#v", fresh.tx.queries)
	}
	if !reflect.DeepEqual(replay.tx.queries, []string{lockSnapshotQuery, readbackSnapshotQuery}) {
		t.Fatalf("replay queries = %#v", replay.tx.queries)
	}
	for _, session := range []*fakeSession{fresh, replay} {
		if session.tx.commitCalls != 1 || session.tx.rollbackCalls != 0 || session.closeCalls != 1 {
			t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
		}
	}
	if !reflect.DeepEqual(provider.configs, []sessionConfig{{Database: databaseName, Access: accessWrite}, {Database: databaseName, Access: accessWrite}}) {
		t.Fatalf("session configs = %#v", provider.configs)
	}
	assertSnapshotParameters(t, fresh.tx.parameters, input)
}

func TestReplaceSnapshotEmptyRemovesPriorProjection(t *testing.T) {
	active := validSnapshotProjection(7, snapshot7ID)
	empty := validSnapshotProjection(8, snapshot8ID)
	empty.Nodes = []graphstore.DriverSnapshotNode{}
	empty.Edges = []graphstore.DriverSnapshotEdge{}
	empty.Snapshot.ContentDigest = sha256.Sum256([]byte("empty-content"))
	session := validSnapshotWriteSession(empty, snapshotMarker(active), 1, 2)
	adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)

	want := snapshotAcknowledgement(empty, false, 2, 1)
	got, err := adapter.ReplaceSnapshot(context.Background(), empty)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReplaceSnapshot(empty) = (%#v, %v), want %#v", got, err, want)
	}
	if session.tx.commitCalls != 1 || session.tx.rollbackCalls != 0 {
		t.Fatalf("settlement commit=%d rollback=%d", session.tx.commitCalls, session.tx.rollbackCalls)
	}
}

func TestReplaceSnapshotRejectsStaleAndSameGenerationDriftBeforeCleanup(t *testing.T) {
	active := validSnapshotProjection(8, snapshot8ID)
	tests := []struct {
		name  string
		input graphstore.DriverSnapshotProjection
		want  error
	}{
		{name: "older generation", input: validSnapshotProjection(7, snapshot7ID), want: graphstore.ErrSnapshotStale},
		{name: "same generation drift", input: validSnapshotProjection(8, snapshot7ID), want: graphstore.ErrSnapshotDrift},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := &fakeSession{tx: &fakeTransaction{results: []*fakeResult{snapshotMarkerResult(snapshotMarker(active))}}}
			adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
			got, err := adapter.ReplaceSnapshot(context.Background(), test.input)
			wantResult := graphstore.DriverSnapshotReplaced{CandidateSnapshot: test.input.Snapshot, ActiveSnapshot: active.Snapshot, NodeIDs: snapshotNodeIDs(active), EdgeIDs: snapshotEdgeIDs(active), Outcome: graphstore.DriverSnapshotNoMutation}
			if !errors.Is(err, test.want) || err.Error() != test.want.Error() || !reflect.DeepEqual(got, wantResult) {
				t.Fatalf("ReplaceSnapshot() = (%#v, %v), want %v", got, err, test.want)
			}
			if !reflect.DeepEqual(session.tx.queries, []string{lockSnapshotQuery}) || session.tx.commitCalls != 1 || session.tx.rollbackCalls != 0 {
				t.Fatalf("stale settlement queries=%#v commit=%d rollback=%d", session.tx.queries, session.tx.commitCalls, session.tx.rollbackCalls)
			}
		})
	}
}

func TestReplaceSnapshotReconcilesCommitLostAcknowledgement(t *testing.T) {
	input := validSnapshotProjection(7, snapshot7ID)
	write := validSnapshotWriteSession(input, emptySnapshotMarker(), 0, 0)
	write.tx.commitErr = errors.New(seededProviderDetail)
	reconcile := validSnapshotReadSession(input)
	provider := &fakeProvider{sessions: []graphSession{write, reconcile}}
	adapter, _ := newAdapterForProvider(provider, databaseName)

	want := snapshotAcknowledgement(input, true, 0, 0)
	got, err := adapter.ReplaceSnapshot(context.Background(), input)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReplaceSnapshot(lost ACK) = (%#v, %v), want %#v", got, err, want)
	}
	if write.tx.commitCalls != 1 || write.tx.rollbackCalls != 0 || reconcile.tx.commitCalls != 1 || reconcile.tx.rollbackCalls != 0 {
		t.Fatalf("settlement write=%d/%d reconcile=%d/%d", write.tx.commitCalls, write.tx.rollbackCalls, reconcile.tx.commitCalls, reconcile.tx.rollbackCalls)
	}
	if !reflect.DeepEqual(reconcile.tx.queries, []string{readbackSnapshotQuery}) || provider.configs[1].Access != accessRead {
		t.Fatalf("reconcile queries/config = %#v/%#v", reconcile.tx.queries, provider.configs[1])
	}

	hostile := validSnapshotReadSession(input)
	foreignDigest := sha256.Sum256([]byte("foreign"))
	hostile.tx.results[0].records[0].Values[3] = hex.EncodeToString(foreignDigest[:])
	writeAgain := validSnapshotWriteSession(input, emptySnapshotMarker(), 0, 0)
	writeAgain.tx.commitErr = errors.New(seededProviderDetail)
	adapter, _ = newAdapterForProvider(&fakeProvider{sessions: []graphSession{writeAgain, hostile}}, databaseName)
	if got, err = adapter.ReplaceSnapshot(context.Background(), input); !errors.Is(err, graphstore.ErrSnapshotUnknownOutcome) || !reflect.DeepEqual(got, graphstore.DriverSnapshotReplaced{}) || strings.Contains(err.Error(), seededProviderDetail) {
		t.Fatalf("ReplaceSnapshot(hostile reconcile) = (%#v, %v)", got, err)
	}
}

func TestReplaceSnapshotCancellationAfterMutationRollsBackWithNoMutationProof(t *testing.T) {
	input := validSnapshotProjection(7, snapshot7ID)
	ctx, cancel := context.WithCancel(context.Background())
	session := validSnapshotWriteSession(input, emptySnapshotMarker(), 0, 0)
	session.tx.results[1].onNext = cancel
	adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)

	got, err := adapter.ReplaceSnapshot(ctx, input)
	if !errors.Is(err, graphstore.ErrSnapshotCanceled) || !reflect.DeepEqual(got, noMutationSnapshotResult(input)) {
		t.Fatalf("ReplaceSnapshot(canceled after mutation) = (%#v, %v)", got, err)
	}
	if session.tx.commitCalls != 0 || session.tx.rollbackCalls != 1 || session.tx.rollbackContextErr != nil || session.closeCalls != 1 {
		t.Fatalf("settlement commit=%d rollback=%d rollbackCtx=%v close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.tx.rollbackContextErr, session.closeCalls)
	}
}

func TestReplaceSnapshotRejectsMalformedDirectInputAndContainsProviderFailures(t *testing.T) {
	valid := validSnapshotProjection(7, snapshot7ID)
	tests := []struct {
		name   string
		mutate func(*graphstore.DriverSnapshotProjection)
	}{
		{name: "zero generation", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Snapshot.Generation = 0 }},
		{name: "zero digest", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Snapshot.InputDigest = [sha256.Size]byte{} }},
		{name: "invalid source", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Snapshot.Source = "AWS" }},
		{name: "foreign node binding", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Nodes[0].Snapshot.SnapshotID = snapshot8ID }},
		{name: "foreign edge binding", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Edges[0].Snapshot.Generation++ }},
		{name: "unsorted nodes", mutate: func(value *graphstore.DriverSnapshotProjection) {
			value.Nodes[0], value.Nodes[1] = value.Nodes[1], value.Nodes[0]
		}},
		{name: "duplicate edge", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Edges = append(value.Edges, value.Edges[0]) }},
		{name: "missing endpoint", mutate: func(value *graphstore.DriverSnapshotProjection) { value.Edges[0].TargetID = snapshot8ID }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneTestSnapshotProjection(valid)
			test.mutate(&input)
			provider := &fakeProvider{session: validSnapshotWriteSession(valid, emptySnapshotMarker(), 0, 0)}
			adapter, _ := newAdapterForProvider(provider, databaseName)
			if result, err := adapter.ReplaceSnapshot(context.Background(), input); !errors.Is(err, graphstore.ErrSnapshotUnavailable) || !reflect.DeepEqual(result, graphstore.DriverSnapshotReplaced{}) || provider.calls != 0 {
				t.Fatalf("ReplaceSnapshot() = (%#v, %v), calls=%d", result, err, provider.calls)
			}
		})
	}

	session := validSnapshotWriteSession(valid, emptySnapshotMarker(), 0, 0)
	session.tx.runErrorAt = 3
	adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
	if result, err := adapter.ReplaceSnapshot(context.Background(), valid); !errors.Is(err, graphstore.ErrSnapshotRetryable) || !reflect.DeepEqual(result, noMutationSnapshotResult(valid)) || strings.Contains(err.Error(), seededProviderDetail) {
		t.Fatalf("ReplaceSnapshot(provider failure) = (%#v, %v)", result, err)
	}
	if session.tx.rollbackCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("cleanup rollback=%d close=%d", session.tx.rollbackCalls, session.closeCalls)
	}
}

func TestSnapshotCleanupQueryFencesSourceAndRelationshipEvolution(t *testing.T) {
	for _, fragment := range []string{"edge.source = $source", "input.kind = edge.kind", "input.source_id = startNode(edge).node_id", "input.target_id = endNode(edge).node_id"} {
		if !strings.Contains(removeSnapshotEdgesQuery, fragment) {
			t.Fatalf("removeSnapshotEdgesQuery missing %q", fragment)
		}
	}
	if !strings.Contains(removeSnapshotNodesQuery, "source: $source") || !strings.Contains(lockSnapshotQuery, "source: $source") {
		t.Fatal("snapshot marker/node cleanup is not source-fenced")
	}
}

func validSnapshotProjection(generation int64, snapshotID string) graphstore.DriverSnapshotProjection {
	inputDigest := sha256.Sum256([]byte("input-" + snapshotID))
	contentDigest := sha256.Sum256([]byte("content-" + snapshotID))
	binding := graphstore.DriverSnapshot{OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID, IntegrationID: integrationID, Source: "aws", SnapshotID: snapshotID, Generation: generation, InputDigest: inputDigest, ContentDigest: contentDigest}
	return graphstore.DriverSnapshotProjection{
		Snapshot: binding,
		Nodes: []graphstore.DriverSnapshotNode{
			{Snapshot: binding, NodeID: nodeAID, Kind: "cloud_account"},
			{Snapshot: binding, NodeID: nodeBID, Kind: "identity_role"},
		},
		Edges: []graphstore.DriverSnapshotEdge{{Snapshot: binding, EdgeID: edgeID, Kind: "contains_identity", SourceID: nodeAID, TargetID: nodeBID}},
	}
}

func emptySnapshotMarker() snapshotMarkerState { return snapshotMarkerState{} }

func snapshotMarker(input graphstore.DriverSnapshotProjection) snapshotMarkerState {
	return snapshotMarkerState{Snapshot: input.Snapshot, NodeIDs: snapshotNodeIDs(input), EdgeIDs: snapshotEdgeIDs(input)}
}

func snapshotMarkerResult(marker snapshotMarkerState) *fakeResult {
	return &fakeResult{keys: snapshotMarkerKeys, records: []graphRecord{{Keys: snapshotMarkerKeys, Values: snapshotMarkerValues(marker)}}}
}

func snapshotMarkerValues(marker snapshotMarkerState) []any {
	return []any{marker.Snapshot.Generation, marker.Snapshot.SnapshotID, hex.EncodeToString(marker.Snapshot.InputDigest[:]), hex.EncodeToString(marker.Snapshot.ContentDigest[:]), stringsToAny(marker.NodeIDs), stringsToAny(marker.EdgeIDs), stringsToAny(snapshotMarkerProperties)}
}

func validSnapshotWriteSession(input graphstore.DriverSnapshotProjection, marker snapshotMarkerState, removedEdges, removedNodes int64) *fakeSession {
	return &fakeSession{tx: &fakeTransaction{results: []*fakeResult{
		snapshotMarkerResult(marker),
		countResult("removed", removedEdges),
		countResult("removed", removedNodes),
		countResult("matched", int64(len(input.Nodes))),
		countResult("matched", int64(len(input.Edges))),
		countResult("activated", 1),
		snapshotReadbackResult(input),
	}}}
}

func validSnapshotReplaySession(input graphstore.DriverSnapshotProjection) *fakeSession {
	return &fakeSession{tx: &fakeTransaction{results: []*fakeResult{snapshotMarkerResult(snapshotMarker(input)), snapshotReadbackResult(input)}}}
}

func validSnapshotReadSession(input graphstore.DriverSnapshotProjection) *fakeSession {
	return &fakeSession{tx: &fakeTransaction{results: []*fakeResult{snapshotReadbackResult(input)}}}
}

func countResult(key string, value int64) *fakeResult {
	return &fakeResult{keys: []string{key}, records: []graphRecord{{Keys: []string{key}, Values: []any{value}}}}
}

func snapshotReadbackResult(input graphstore.DriverSnapshotProjection) *fakeResult {
	values := snapshotMarkerValues(snapshotMarker(input))
	values = append(values, snapshotNodeReadback(input), snapshotEdgeReadback(input))
	return &fakeResult{keys: snapshotReadbackKeys, records: []graphRecord{{Keys: snapshotReadbackKeys, Values: values}}}
}

func snapshotNodeReadback(input graphstore.DriverSnapshotProjection) []any {
	items := make([]any, len(input.Nodes))
	for index, node := range input.Nodes {
		items[index] = map[string]any{"organization_id": input.Snapshot.OrganizationID, "workspace_id": input.Snapshot.WorkspaceID, "environment_id": input.Snapshot.EnvironmentID, "integration_id": input.Snapshot.IntegrationID, "source": input.Snapshot.Source, "node_id": node.NodeID, "kind": node.Kind, "snapshot_id": input.Snapshot.SnapshotID, "generation": input.Snapshot.Generation, "input_digest": hex.EncodeToString(input.Snapshot.InputDigest[:]), "content_digest": hex.EncodeToString(input.Snapshot.ContentDigest[:]), "schema_version": schemaVersion, "property_keys": stringsToAny(snapshotNodeProperties)}
	}
	return items
}

func snapshotEdgeReadback(input graphstore.DriverSnapshotProjection) []any {
	items := make([]any, len(input.Edges))
	for index, edge := range input.Edges {
		items[index] = map[string]any{"organization_id": input.Snapshot.OrganizationID, "workspace_id": input.Snapshot.WorkspaceID, "environment_id": input.Snapshot.EnvironmentID, "integration_id": input.Snapshot.IntegrationID, "source": input.Snapshot.Source, "edge_id": edge.EdgeID, "kind": edge.Kind, "source_id": edge.SourceID, "target_id": edge.TargetID, "snapshot_id": input.Snapshot.SnapshotID, "generation": input.Snapshot.Generation, "input_digest": hex.EncodeToString(input.Snapshot.InputDigest[:]), "content_digest": hex.EncodeToString(input.Snapshot.ContentDigest[:]), "schema_version": schemaVersion, "property_keys": stringsToAny(snapshotEdgeProperties)}
	}
	return items
}

func snapshotAcknowledgement(input graphstore.DriverSnapshotProjection, replayed bool, removedNodes, removedEdges int) graphstore.DriverSnapshotReplaced {
	return graphstore.DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: input.Snapshot, NodeIDs: snapshotNodeIDs(input), EdgeIDs: snapshotEdgeIDs(input), Replayed: replayed, RemovedNodes: removedNodes, RemovedEdges: removedEdges, Outcome: graphstore.DriverSnapshotDurable}
}

func cloneTestSnapshotProjection(input graphstore.DriverSnapshotProjection) graphstore.DriverSnapshotProjection {
	return graphstore.DriverSnapshotProjection{Snapshot: input.Snapshot, Nodes: append([]graphstore.DriverSnapshotNode(nil), input.Nodes...), Edges: append([]graphstore.DriverSnapshotEdge(nil), input.Edges...)}
}

func stringsToAny(input []string) []any {
	result := make([]any, len(input))
	for index, value := range input {
		result[index] = value
	}
	return result
}

func assertSnapshotParameters(t *testing.T, parameters []map[string]any, input graphstore.DriverSnapshotProjection) {
	t.Helper()
	want := snapshotParameters(input)
	for index, got := range parameters {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parameters[%d] = %#v, want %#v", index, got, want)
		}
	}
}
