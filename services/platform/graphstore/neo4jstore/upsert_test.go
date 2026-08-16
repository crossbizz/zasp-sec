package neo4jstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const (
	organizationID = "pid_00000000-0000-4000-8000-000000000001"
	workspaceID    = "pid_00000000-0000-4000-8000-000000000002"
	environmentID  = "pid_00000000-0000-4000-8000-000000000003"
	nodeAID        = "pid_00000000-0000-4000-8000-000000000004"
	nodeBID        = "pid_00000000-0000-4000-8000-000000000005"
	edgeID         = "pid_00000000-0000-4000-8000-000000000006"
)

func TestUpsertUsesExactTransactionAndReturnsCanonicalAcknowledgement(t *testing.T) {
	projection := validDriverProjection()
	before := cloneTestProjection(projection)
	first := validUpsertSession()
	second := validUpsertSession()
	provider := &fakeProvider{sessions: []graphSession{first, second}}
	adapter, err := newAdapterForProvider(provider, databaseName)
	if err != nil {
		t.Fatal(err)
	}

	want := graphstore.DriverUpserted{NodeIDs: []string{nodeAID, nodeBID}, EdgeIDs: []string{edgeID}}
	for attempt := 0; attempt < 2; attempt++ {
		got, upsertErr := adapter.Upsert(context.Background(), projection)
		if upsertErr != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("attempt %d Upsert = (%#v, %v), want %#v", attempt, got, upsertErr, want)
		}
		got.NodeIDs[0] = "mutated"
		got.EdgeIDs[0] = "mutated"
	}
	if !reflect.DeepEqual(projection, before) {
		t.Fatalf("Upsert mutated caller projection: %#v", projection)
	}
	if provider.calls != 2 || !reflect.DeepEqual(provider.configs, []sessionConfig{
		{Database: databaseName, Access: accessWrite}, {Database: databaseName, Access: accessWrite},
	}) {
		t.Fatalf("provider calls/configs = %d/%#v", provider.calls, provider.configs)
	}
	for _, session := range []*fakeSession{first, second} {
		if !reflect.DeepEqual(session.tx.queries, []string{upsertNodesQuery, upsertEdgesQuery, readbackUpsertQuery}) {
			t.Fatalf("queries = %#v", session.tx.queries)
		}
		wantParameters := validUpsertParameters()
		for index, parameters := range session.tx.parameters {
			if !reflect.DeepEqual(parameters, wantParameters) {
				t.Fatalf("parameters[%d] = %#v, want %#v", index, parameters, wantParameters)
			}
		}
		if session.tx.commitCalls != 1 || session.tx.rollbackCalls != 0 || session.closeCalls != 1 {
			t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
		}
		for index, result := range session.tx.results {
			if result.consumeCalls != 1 {
				t.Fatalf("result %d consumed %d times", index, result.consumeCalls)
			}
		}
	}
}

func TestUpsertRejectsMalformedDirectCallsBeforeProviderIO(t *testing.T) {
	valid := validDriverProjection()
	tests := []struct {
		name   string
		mutate func(*graphstore.DriverProjection)
	}{
		{name: "empty", mutate: func(value *graphstore.DriverProjection) { *value = graphstore.DriverProjection{} }},
		{name: "foreign node scope", mutate: func(value *graphstore.DriverProjection) {
			value.Nodes[1].OrganizationID = "pid_00000000-0000-4000-8000-000000000007"
		}},
		{name: "foreign edge scope", mutate: func(value *graphstore.DriverProjection) {
			value.Edges[0].WorkspaceID = "pid_00000000-0000-4000-8000-000000000007"
		}},
		{name: "invalid scope ID", mutate: func(value *graphstore.DriverProjection) { value.Nodes[0].EnvironmentID = "not-a-product-id" }},
		{name: "invalid node ID", mutate: func(value *graphstore.DriverProjection) { value.Nodes[0].NodeID = "not-a-product-id" }},
		{name: "invalid edge ID", mutate: func(value *graphstore.DriverProjection) { value.Edges[0].EdgeID = "not-a-product-id" }},
		{name: "provider node kind", mutate: func(value *graphstore.DriverProjection) { value.Nodes[0].Kind = "aws_role" }},
		{name: "invalid edge kind", mutate: func(value *graphstore.DriverProjection) { value.Edges[0].Kind = "Contains" }},
		{name: "unsorted nodes", mutate: func(value *graphstore.DriverProjection) {
			value.Nodes[0], value.Nodes[1] = value.Nodes[1], value.Nodes[0]
		}},
		{name: "duplicate nodes", mutate: func(value *graphstore.DriverProjection) { value.Nodes[1] = value.Nodes[0] }},
		{name: "duplicate edges", mutate: func(value *graphstore.DriverProjection) { value.Edges = append(value.Edges, value.Edges[0]) }},
		{name: "duplicate semantic edge", mutate: func(value *graphstore.DriverProjection) {
			duplicate := value.Edges[0]
			duplicate.EdgeID = "pid_00000000-0000-4000-8000-000000000007"
			value.Edges = append(value.Edges, duplicate)
		}},
		{name: "self edge", mutate: func(value *graphstore.DriverProjection) { value.Edges[0].TargetID = value.Edges[0].SourceID }},
		{name: "missing source", mutate: func(value *graphstore.DriverProjection) {
			value.Edges[0].SourceID = "pid_00000000-0000-4000-8000-000000000007"
		}},
		{name: "missing target", mutate: func(value *graphstore.DriverProjection) {
			value.Edges[0].TargetID = "pid_00000000-0000-4000-8000-000000000007"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestProjection(valid)
			test.mutate(&candidate)
			provider := &fakeProvider{session: validUpsertSession()}
			adapter, err := newAdapterForProvider(provider, databaseName)
			if err != nil {
				t.Fatal(err)
			}
			acknowledged, upsertErr := adapter.Upsert(context.Background(), candidate)
			if !errors.Is(upsertErr, ErrUpsert) || len(acknowledged.NodeIDs) != 0 || len(acknowledged.EdgeIDs) != 0 {
				t.Fatalf("Upsert = (%#v, %v), want empty fixed failure", acknowledged, upsertErr)
			}
			if provider.calls != 0 {
				t.Fatalf("provider calls = %d, want 0", provider.calls)
			}
		})
	}
}

func TestUpsertRejectsMalformedProviderAcknowledgement(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeSession)
	}{
		{name: "node count zero", mutate: func(session *fakeSession) { session.tx.results[0].records[0].Values[0] = int64(0) }},
		{name: "node count string", mutate: func(session *fakeSession) { session.tx.results[0].records[0].Values[0] = "2" }},
		{name: "edge count extra row", mutate: func(session *fakeSession) {
			session.tx.results[1].records = append(session.tx.results[1].records, session.tx.results[1].records[0])
		}},
		{name: "readback missing node", mutate: func(session *fakeSession) { session.tx.results[2].records[0].Values[0] = validNodeReadback()[:1] }},
		{name: "readback extra edge", mutate: func(session *fakeSession) {
			edges := validEdgeReadback()
			session.tx.results[2].records[0].Values[1] = append(edges, edges[0])
		}},
		{name: "readback string slice alias", mutate: func(session *fakeSession) { session.tx.results[2].records[0].Values[0] = []map[string]any{{}} }},
		{name: "wrong node keys", mutate: func(session *fakeSession) {
			nodes := validNodeReadback()
			nodes[0].(map[string]any)["extra"] = true
			session.tx.results[2].records[0].Values[0] = nodes
		}},
		{name: "wrong node version", mutate: func(session *fakeSession) {
			nodes := validNodeReadback()
			nodes[0].(map[string]any)["schema_version"] = int64(2)
			session.tx.results[2].records[0].Values[0] = nodes
		}},
		{name: "wrong node kind", mutate: func(session *fakeSession) {
			nodes := validNodeReadback()
			nodes[0].(map[string]any)["kind"] = "identity_role"
			session.tx.results[2].records[0].Values[0] = nodes
		}},
		{name: "wrong edge endpoint", mutate: func(session *fakeSession) {
			edges := validEdgeReadback()
			edges[0].(map[string]any)["target_id"] = nodeAID
			session.tx.results[2].records[0].Values[1] = edges
		}},
		{name: "wrong readback keys", mutate: func(session *fakeSession) { session.tx.results[2].keys = []string{"edges", "nodes"} }},
		{name: "multiple readback rows", mutate: func(session *fakeSession) {
			session.tx.results[2].records = append(session.tx.results[2].records, session.tx.results[2].records[0])
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := validUpsertSession()
			test.mutate(session)
			adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
			acknowledged, err := adapter.Upsert(context.Background(), validDriverProjection())
			if !errors.Is(err, ErrUpsert) || strings.Contains(err.Error(), seededProviderDetail) || len(acknowledged.NodeIDs) != 0 {
				t.Fatalf("Upsert = (%#v, %v), want fixed failure", acknowledged, err)
			}
			if session.tx.commitCalls != 0 || session.tx.rollbackCalls != 1 || session.closeCalls != 1 {
				t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
			}
		})
	}
}

func TestUpsertContainsProviderFailuresAndUsesIndependentCleanup(t *testing.T) {
	providerError := errors.New(seededProviderDetail)
	tests := []struct {
		name   string
		ctx    func() context.Context
		mutate func(*fakeSession)
	}{
		{name: "canceled", ctx: canceledContext, mutate: func(*fakeSession) {}},
		{name: "expired", ctx: expiredContext, mutate: func(*fakeSession) {}},
		{name: "begin error with candidate", ctx: backgroundContext, mutate: func(session *fakeSession) { session.beginErr = providerError }},
		{name: "run error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.runErrorAt = 2 }},
		{name: "result panic", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.results[2].nextPanic = true }},
		{name: "consume error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.results[2].consumeErr = providerError }},
		{name: "commit error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.commitErr = providerError }},
		{name: "rollback error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.runErrorAt = 2; session.tx.rollbackErr = providerError }},
		{name: "close error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.closeErr = providerError }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := validUpsertSession()
			test.mutate(session)
			provider := &fakeProvider{session: session}
			adapter, _ := newAdapterForProvider(provider, databaseName)
			acknowledged, err := adapter.Upsert(test.ctx(), validDriverProjection())
			if !errors.Is(err, ErrUpsert) || strings.Contains(err.Error(), seededProviderDetail) || len(acknowledged.NodeIDs) != 0 {
				t.Fatalf("Upsert = (%#v, %v), want fixed failure", acknowledged, err)
			}
			if test.name == "canceled" || test.name == "expired" {
				if provider.calls != 0 {
					t.Fatalf("provider calls = %d, want 0", provider.calls)
				}
				return
			}
			if session.closeCalls != 1 || (session.tx.commitCalls == 0 && session.tx.rollbackCalls != 1) {
				t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
			}
		})
	}
}

func validDriverProjection() graphstore.DriverProjection {
	return graphstore.DriverProjection{
		Nodes: []graphstore.DriverNode{
			{OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID, NodeID: nodeAID, Kind: "cloud_account"},
			{OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID, NodeID: nodeBID, Kind: "identity_role"},
		},
		Edges: []graphstore.DriverEdge{
			{OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID, EdgeID: edgeID, Kind: "contains_identity", SourceID: nodeAID, TargetID: nodeBID},
		},
	}
}

func validUpsertParameters() map[string]any {
	return map[string]any{
		"organization_id": organizationID,
		"workspace_id":    workspaceID,
		"environment_id":  environmentID,
		"nodes": []any{
			map[string]any{"node_id": nodeAID, "kind": "cloud_account"},
			map[string]any{"node_id": nodeBID, "kind": "identity_role"},
		},
		"edges": []any{
			map[string]any{"edge_id": edgeID, "kind": "contains_identity", "source_id": nodeAID, "target_id": nodeBID},
		},
		"schema_version": int64(1),
	}
}

func validUpsertSession() *fakeSession {
	return &fakeSession{tx: &fakeTransaction{results: []*fakeResult{
		{keys: []string{"matched"}, records: []graphRecord{{Keys: []string{"matched"}, Values: []any{int64(2)}}}},
		{keys: []string{"matched"}, records: []graphRecord{{Keys: []string{"matched"}, Values: []any{int64(1)}}}},
		{keys: []string{"nodes", "edges"}, records: []graphRecord{{Keys: []string{"nodes", "edges"}, Values: []any{validNodeReadback(), validEdgeReadback()}}}},
	}}}
}

func validNodeReadback() []any {
	return []any{
		map[string]any{"organization_id": organizationID, "workspace_id": workspaceID, "environment_id": environmentID, "node_id": nodeAID, "kind": "cloud_account", "schema_version": int64(1)},
		map[string]any{"organization_id": organizationID, "workspace_id": workspaceID, "environment_id": environmentID, "node_id": nodeBID, "kind": "identity_role", "schema_version": int64(1)},
	}
}

func validEdgeReadback() []any {
	return []any{
		map[string]any{"organization_id": organizationID, "workspace_id": workspaceID, "environment_id": environmentID, "edge_id": edgeID, "kind": "contains_identity", "source_id": nodeAID, "target_id": nodeBID, "schema_version": int64(1)},
	}
}

func cloneTestProjection(value graphstore.DriverProjection) graphstore.DriverProjection {
	return graphstore.DriverProjection{Nodes: append([]graphstore.DriverNode(nil), value.Nodes...), Edges: append([]graphstore.DriverEdge(nil), value.Edges...)}
}

func backgroundContext() context.Context { return context.Background() }

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	return ctx
}
