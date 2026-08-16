package neo4jstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const (
	nodeCID = "pid_00000000-0000-4000-8000-000000000007"
	nodeDID = "pid_00000000-0000-4000-8000-000000000008"
	edgeBID = "pid_00000000-0000-4000-8000-000000000009"
	edgeCID = "pid_00000000-0000-4000-8000-00000000000a"
)

func TestReadUsesFixedDirectionQueriesAndBoundedTransactions(t *testing.T) {
	tests := []struct {
		name      string
		query     graphstore.DriverQuery
		session   *fakeSession
		wantQuery string
		want      graphstore.DriverProjection
	}{
		{
			name: "outgoing", query: validReadQuery(nodeAID, "outgoing", 1, 2, 1),
			session:   readSession(rootRecord(nodeAID, "cloud_account"), []graphRecord{adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)}),
			wantQuery: readOutgoingQuery, want: validDriverProjection(),
		},
		{
			name: "incoming", query: validReadQuery(nodeBID, "incoming", 1, 2, 1),
			session:   readSession(rootRecord(nodeBID, "identity_role"), []graphRecord{adjacentRecord(nodeAID, "cloud_account", edgeID, "contains_identity", nodeAID, nodeBID)}),
			wantQuery: readIncomingQuery, want: validDriverProjection(),
		},
		{
			name: "both", query: validReadQuery(nodeAID, "both", 1, 2, 1),
			session:   readSession(rootRecord(nodeAID, "cloud_account"), []graphRecord{adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)}),
			wantQuery: readBothQuery, want: validDriverProjection(),
		},
		{
			name: "depth zero", query: validReadQuery(nodeAID, "both", 0, 2, 1),
			session: readSession(rootRecord(nodeAID, "cloud_account")),
			want:    graphstore.DriverProjection{Nodes: []graphstore.DriverNode{validDriverProjection().Nodes[0]}, Edges: []graphstore.DriverEdge{}},
		},
		{
			name: "missing root", query: validReadQuery(nodeAID, "outgoing", 3, 10, 10),
			session: readSession(),
			want:    graphstore.DriverProjection{Nodes: []graphstore.DriverNode{}, Edges: []graphstore.DriverEdge{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &fakeProvider{session: test.session}
			adapter, _ := newAdapterForProvider(provider, databaseName)
			got, err := adapter.Read(context.Background(), test.query)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Read = (%#v, %v), want %#v", got, err, test.want)
			}
			if !reflect.DeepEqual(test.session.tx.queries[0], readRootQuery) {
				t.Fatalf("root query = %q", test.session.tx.queries[0])
			}
			if test.wantQuery != "" && (len(test.session.tx.queries) != 2 || test.session.tx.queries[1] != test.wantQuery) {
				t.Fatalf("queries = %#v", test.session.tx.queries)
			}
			if test.wantQuery == "" && len(test.session.tx.queries) != 1 {
				t.Fatalf("queries = %#v, want root only", test.session.tx.queries)
			}
			if test.session.tx.commitCalls != 1 || test.session.tx.rollbackCalls != 0 || test.session.closeCalls != 1 {
				t.Fatalf("settlement commit=%d rollback=%d close=%d", test.session.tx.commitCalls, test.session.tx.rollbackCalls, test.session.closeCalls)
			}
			if len(got.Nodes) != 0 {
				got.Nodes[0] = graphstore.DriverNode{}
				providerRecord := test.session.tx.results[0].records[0].Values[0].(map[string]any)
				if providerRecord["properties"].(map[string]any)["node_id"] != test.query.RootID {
					t.Fatal("caller mutation changed provider-owned record")
				}
			}
		})
	}
}

func TestReadHandlesCyclesConvergenceDuplicatesAndDeterministicLimits(t *testing.T) {
	t.Run("cycle and repeated exact rows", func(t *testing.T) {
		first := adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)
		second := adjacentRecord(nodeAID, "cloud_account", edgeBID, "returns_to", nodeBID, nodeAID)
		session := readSession(rootRecord(nodeAID, "cloud_account"), []graphRecord{first, first}, []graphRecord{second})
		adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
		got, err := adapter.Read(context.Background(), validReadQuery(nodeAID, "outgoing", 2, 3, 3))
		want := graphstore.DriverProjection{
			Nodes: validDriverProjection().Nodes,
			Edges: []graphstore.DriverEdge{
				validDriverProjection().Edges[0],
				{OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID, EdgeID: edgeBID, Kind: "returns_to", SourceID: nodeBID, TargetID: nodeAID},
			},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("cycle Read = (%#v, %v), want %#v", got, err, want)
		}
		if !reflect.DeepEqual(session.tx.parameters[1], readLevelParameters([]string{nodeAID}, 2, 3)) ||
			!reflect.DeepEqual(session.tx.parameters[2], readLevelParameters([]string{nodeBID}, 1, 2)) {
			t.Fatalf("level parameters = %#v", session.tx.parameters[1:])
		}
	})

	t.Run("converging paths retain one node and both edges", func(t *testing.T) {
		toB := adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)
		toC := adjacentRecord(nodeCID, "identity_role", edgeBID, "contains_identity", nodeAID, nodeCID)
		toDFromB := adjacentRecord(nodeDID, "sensitive_resource", edgeCID, "can_access", nodeBID, nodeDID)
		toDFromC := adjacentRecord(nodeDID, "sensitive_resource", "pid_00000000-0000-4000-8000-00000000000b", "can_access", nodeCID, nodeDID)
		session := readSession(rootRecord(nodeAID, "cloud_account"), []graphRecord{toB, toC}, []graphRecord{toDFromB, toDFromC})
		adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
		got, err := adapter.Read(context.Background(), validReadQuery(nodeAID, "outgoing", 2, 4, 4))
		if err != nil || len(got.Nodes) != 4 || len(got.Edges) != 4 || got.Nodes[3].NodeID != nodeDID {
			t.Fatalf("converging Read = (%#v, %v)", got, err)
		}
	})

	t.Run("node limit retains the sorted prefix", func(t *testing.T) {
		rows := []graphRecord{
			adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID),
			adjacentRecord(nodeCID, "identity_role", edgeBID, "contains_identity", nodeAID, nodeCID),
		}
		session := readSession(rootRecord(nodeAID, "cloud_account"), rows)
		adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
		got, err := adapter.Read(context.Background(), validReadQuery(nodeAID, "outgoing", 1, 2, 2))
		if err != nil || len(got.Nodes) != 2 || len(got.Edges) != 1 || got.Nodes[1].NodeID != nodeBID || got.Edges[0].EdgeID != edgeID {
			t.Fatalf("limited Read = (%#v, %v)", got, err)
		}
	})
}

func TestReadRejectsMalformedQueryBeforeProviderIO(t *testing.T) {
	valid := validReadQuery(nodeAID, "outgoing", 1, 2, 2)
	tests := []struct {
		name   string
		mutate func(*graphstore.DriverQuery)
	}{
		{name: "invalid organization", mutate: func(value *graphstore.DriverQuery) { value.OrganizationID = "invalid" }},
		{name: "invalid workspace", mutate: func(value *graphstore.DriverQuery) { value.WorkspaceID = "invalid" }},
		{name: "invalid environment", mutate: func(value *graphstore.DriverQuery) { value.EnvironmentID = "invalid" }},
		{name: "invalid root", mutate: func(value *graphstore.DriverQuery) { value.RootID = "invalid" }},
		{name: "invalid direction", mutate: func(value *graphstore.DriverQuery) { value.Direction = "sideways" }},
		{name: "negative depth", mutate: func(value *graphstore.DriverQuery) { value.MaximumDepth = -1 }},
		{name: "excess depth", mutate: func(value *graphstore.DriverQuery) { value.MaximumDepth = 9 }},
		{name: "zero nodes", mutate: func(value *graphstore.DriverQuery) { value.MaximumNodes = 0 }},
		{name: "excess nodes", mutate: func(value *graphstore.DriverQuery) { value.MaximumNodes = 1001 }},
		{name: "zero edges", mutate: func(value *graphstore.DriverQuery) { value.MaximumEdges = 0 }},
		{name: "excess edges", mutate: func(value *graphstore.DriverQuery) { value.MaximumEdges = 2001 }},
		{name: "wrong node sort", mutate: func(value *graphstore.DriverQuery) { value.NodeSort = "kind" }},
		{name: "wrong edge sort", mutate: func(value *graphstore.DriverQuery) { value.EdgeSort = "kind" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			provider := &fakeProvider{session: readSession(rootRecord(nodeAID, "cloud_account"))}
			adapter, _ := newAdapterForProvider(provider, databaseName)
			got, err := adapter.Read(context.Background(), candidate)
			if !errors.Is(err, ErrRead) || got.Nodes != nil || got.Edges != nil || provider.calls != 0 {
				t.Fatalf("Read = (%#v, %v), provider calls %d", got, err, provider.calls)
			}
		})
	}
}

func TestReadRejectsMalformedProviderRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeSession)
	}{
		{name: "root extra record", mutate: func(session *fakeSession) {
			session.tx.results[0].records = append(session.tx.results[0].records, session.tx.results[0].records[0])
		}},
		{name: "root extra key", mutate: func(session *fakeSession) {
			node := providerNode(nodeAID, "cloud_account")
			node["element_id"] = "provider"
			session.tx.results[0].records[0].Values[0] = node
		}},
		{name: "root extra label", mutate: func(session *fakeSession) {
			node := providerNode(nodeAID, "cloud_account")
			node["labels"] = []any{nodeLabel, "Foreign"}
			session.tx.results[0].records[0].Values[0] = node
		}},
		{name: "foreign node scope", mutate: func(session *fakeSession) {
			node := providerNode(nodeBID, "identity_role")
			node["properties"].(map[string]any)["organization_id"] = nodeCID
			session.tx.results[1].records[0].Values[0] = node
		}},
		{name: "wrong node scalar", mutate: func(session *fakeSession) {
			node := providerNode(nodeBID, "identity_role")
			node["properties"].(map[string]any)["node_id"] = int64(4)
			session.tx.results[1].records[0].Values[0] = node
		}},
		{name: "wrong node version", mutate: func(session *fakeSession) {
			node := providerNode(nodeBID, "identity_role")
			node["properties"].(map[string]any)["schema_version"] = int64(2)
			session.tx.results[1].records[0].Values[0] = node
		}},
		{name: "wrong edge type", mutate: func(session *fakeSession) {
			edge := providerEdge(edgeID, "contains_identity", nodeAID, nodeBID)
			edge["type"] = "FOREIGN"
			session.tx.results[1].records[0].Values[1] = edge
		}},
		{name: "provider edge id", mutate: func(session *fakeSession) {
			edge := providerEdge(edgeID, "contains_identity", nodeAID, nodeBID)
			edge["element_id"] = "provider"
			session.tx.results[1].records[0].Values[1] = edge
		}},
		{name: "direction drift", mutate: func(session *fakeSession) {
			edge := providerEdge(edgeID, "contains_identity", nodeBID, nodeAID)
			session.tx.results[1].records[0].Values[1] = edge
		}},
		{name: "missing endpoint", mutate: func(session *fakeSession) {
			edge := providerEdge(edgeID, "contains_identity", nodeAID, nodeCID)
			session.tx.results[1].records[0].Values[1] = edge
		}},
		{name: "unordered rows", mutate: func(session *fakeSession) {
			session.tx.results[1].records = []graphRecord{adjacentRecord(nodeCID, "identity_role", edgeBID, "contains_identity", nodeAID, nodeCID), adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)}
		}},
		{name: "edge limit drift", mutate: func(session *fakeSession) {
			session.tx.results[1].records = append(session.tx.results[1].records, adjacentRecord(nodeCID, "identity_role", edgeBID, "contains_identity", nodeAID, nodeCID))
			session.tx.results[1].records = append(session.tx.results[1].records, adjacentRecord(nodeDID, "identity_role", edgeCID, "contains_identity", nodeAID, nodeDID))
		}},
		{name: "cursor error", mutate: func(session *fakeSession) { session.tx.results[1].cursorErr = errors.New(seededProviderDetail) }},
		{name: "consume error", mutate: func(session *fakeSession) { session.tx.results[1].consumeErr = errors.New(seededProviderDetail) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := readSession(rootRecord(nodeAID, "cloud_account"), []graphRecord{adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)})
			test.mutate(session)
			adapter, _ := newAdapterForProvider(&fakeProvider{session: session}, databaseName)
			got, err := adapter.Read(context.Background(), validReadQuery(nodeAID, "outgoing", 1, 3, 2))
			if !errors.Is(err, ErrRead) || strings.Contains(err.Error(), seededProviderDetail) || got.Nodes != nil || got.Edges != nil {
				t.Fatalf("Read = (%#v, %v), want fixed failure", got, err)
			}
			if session.tx.commitCalls != 0 || session.tx.rollbackCalls != 1 || session.closeCalls != 1 {
				t.Fatalf("settlement commit=%d rollback=%d close=%d", session.tx.commitCalls, session.tx.rollbackCalls, session.closeCalls)
			}
		})
	}
}

func TestReadContainsFailuresAndSupportsConcurrentCalls(t *testing.T) {
	t.Run("provider failures", func(t *testing.T) {
		tests := []struct {
			name   string
			ctx    func() context.Context
			mutate func(*fakeSession)
		}{
			{name: "canceled", ctx: canceledContext, mutate: func(*fakeSession) {}},
			{name: "expired", ctx: expiredContext, mutate: func(*fakeSession) {}},
			{name: "begin error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.beginErr = errors.New(seededProviderDetail) }},
			{name: "run error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.runErrorAt = 2 }},
			{name: "panic", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.results[1].nextPanic = true }},
			{name: "commit error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.tx.commitErr = errors.New(seededProviderDetail) }},
			{name: "rollback error", ctx: backgroundContext, mutate: func(session *fakeSession) {
				session.tx.runErrorAt = 2
				session.tx.rollbackErr = errors.New(seededProviderDetail)
			}},
			{name: "close error", ctx: backgroundContext, mutate: func(session *fakeSession) { session.closeErr = errors.New(seededProviderDetail) }},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				session := readSession(rootRecord(nodeAID, "cloud_account"), []graphRecord{adjacentRecord(nodeBID, "identity_role", edgeID, "contains_identity", nodeAID, nodeBID)})
				test.mutate(session)
				provider := &fakeProvider{session: session}
				adapter, _ := newAdapterForProvider(provider, databaseName)
				got, err := adapter.Read(test.ctx(), validReadQuery(nodeAID, "outgoing", 1, 2, 1))
				if !errors.Is(err, ErrRead) || strings.Contains(err.Error(), seededProviderDetail) || got.Nodes != nil {
					t.Fatalf("Read = (%#v, %v)", got, err)
				}
			})
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		const calls = 16
		sessions := make([]graphSession, calls)
		for index := range sessions {
			sessions[index] = readSession(rootRecord(nodeAID, "cloud_account"))
		}
		provider := &fakeProvider{sessions: sessions}
		adapter, _ := newAdapterForProvider(&synchronizedProvider{provider: provider}, databaseName)
		var wait sync.WaitGroup
		errorsFound := make(chan error, calls)
		for index := 0; index < calls; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				got, err := adapter.Read(context.Background(), validReadQuery(nodeAID, "both", 0, 1, 1))
				if err != nil || len(got.Nodes) != 1 || len(got.Edges) != 0 {
					errorsFound <- errors.New("concurrent read failed")
				}
			}()
		}
		wait.Wait()
		close(errorsFound)
		for err := range errorsFound {
			t.Fatal(err)
		}
	})
}

func validReadQuery(root, direction string, depth, nodes, edges int) graphstore.DriverQuery {
	return graphstore.DriverQuery{
		OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
		RootID: root, Direction: direction, MaximumDepth: depth, MaximumNodes: nodes, MaximumEdges: edges,
		NodeSort: "node_id", EdgeSort: "edge_id",
	}
}

func readSession(records ...any) *fakeSession {
	results := make([]*fakeResult, 0, len(records))
	if len(records) == 0 {
		results = append(results, &fakeResult{keys: []string{"node"}, records: []graphRecord{}})
	} else {
		root, _ := records[0].(graphRecord)
		rootRecords := []graphRecord{}
		if len(root.Keys) != 0 {
			rootRecords = append(rootRecords, root)
		}
		results = append(results, &fakeResult{keys: []string{"node"}, records: rootRecords})
		for _, value := range records[1:] {
			rows, _ := value.([]graphRecord)
			results = append(results, &fakeResult{keys: []string{"node", "edge"}, records: rows})
		}
	}
	return &fakeSession{tx: &fakeTransaction{results: results}}
}

func rootRecord(id, kind string) graphRecord {
	return graphRecord{Keys: []string{"node"}, Values: []any{providerNode(id, kind)}}
}

func adjacentRecord(nodeID, nodeKind, relationshipID, relationshipKind, sourceID, targetID string) graphRecord {
	return graphRecord{
		Keys: []string{"node", "edge"},
		Values: []any{
			providerNode(nodeID, nodeKind),
			providerEdge(relationshipID, relationshipKind, sourceID, targetID),
		},
	}
}

func providerNode(id, kind string) map[string]any {
	return map[string]any{
		"labels": []any{nodeLabel},
		"properties": map[string]any{
			"organization_id": organizationID, "workspace_id": workspaceID, "environment_id": environmentID,
			"node_id": id, "kind": kind, "schema_version": int64(1),
		},
	}
}

func providerEdge(id, kind, sourceID, targetID string) map[string]any {
	return map[string]any{
		"type": edgeType,
		"properties": map[string]any{
			"organization_id": organizationID, "workspace_id": workspaceID, "environment_id": environmentID,
			"edge_id": id, "kind": kind, "schema_version": int64(1),
		},
		"source_id": sourceID,
		"target_id": targetID,
	}
}

func readLevelParameters(frontier []string, remainingNodes, remainingEdges int) map[string]any {
	values := make([]any, len(frontier))
	for index, item := range frontier {
		values[index] = item
	}
	return map[string]any{
		"organization_id": organizationID, "workspace_id": workspaceID, "environment_id": environmentID,
		"frontier": values, "remaining_nodes": int64(remainingNodes), "remaining_edges": int64(remainingEdges),
		"schema_version": int64(1),
	}
}

type synchronizedProvider struct {
	mu       sync.Mutex
	provider *fakeProvider
}

func (provider *synchronizedProvider) NewSession(ctx context.Context, config sessionConfig) graphSession {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.provider.NewSession(ctx, config)
}

func TestReadCleanupUsesIndependentContextAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := readSession(rootRecord(nodeAID, "cloud_account"))
	session.tx.results[0].onNext = cancel
	provider := &fakeProvider{session: session}
	adapter, _ := newAdapterForProvider(provider, databaseName)
	_, err := adapter.Read(ctx, validReadQuery(nodeAID, "outgoing", 1, 2, 1))
	if !errors.Is(err, ErrRead) || provider.calls != 1 || session.tx.rollbackCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("canceled Read = %v, calls=%d rollback=%d close=%d", err, provider.calls, session.tx.rollbackCalls, session.closeCalls)
	}
	if session.tx.rollbackContextErr != nil || session.closeContextErr != nil {
		t.Fatalf("cleanup inherited cancellation: rollback=%v close=%v", session.tx.rollbackContextErr, session.closeContextErr)
	}
}
