package graphstore

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type functionDriver struct {
	upsert func(context.Context, DriverProjection) (DriverUpserted, error)
	read   func(context.Context, DriverQuery) (DriverProjection, error)
}

type scopedMemoryDriver struct {
	mu          sync.Mutex
	projections map[string]DriverProjection
}

func newScopedMemoryDriver() *scopedMemoryDriver {
	return &scopedMemoryDriver{projections: make(map[string]DriverProjection)}
}

func (driver *scopedMemoryDriver) Upsert(_ context.Context, projection DriverProjection) (DriverUpserted, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	organizationID := projection.Nodes[0].OrganizationID
	driver.projections[organizationID] = cloneDriverProjection(projection)
	nodeIDs := make([]string, len(projection.Nodes))
	for index, node := range projection.Nodes {
		nodeIDs[index] = node.NodeID
	}
	edgeIDs := make([]string, len(projection.Edges))
	for index, edge := range projection.Edges {
		edgeIDs[index] = edge.EdgeID
	}
	return DriverUpserted{NodeIDs: nodeIDs, EdgeIDs: edgeIDs}, nil
}

func (driver *scopedMemoryDriver) Read(_ context.Context, query DriverQuery) (DriverProjection, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	projection := driver.projections[query.OrganizationID]
	if len(projection.Nodes) == 0 || projection.Nodes[0].WorkspaceID != query.WorkspaceID ||
		projection.Nodes[0].EnvironmentID != query.EnvironmentID {
		return DriverProjection{Nodes: []DriverNode{}, Edges: []DriverEdge{}}, nil
	}
	return cloneDriverProjection(projection), nil
}

func (driver functionDriver) Upsert(ctx context.Context, projection DriverProjection) (DriverUpserted, error) {
	return driver.upsert(ctx, projection)
}

func (driver functionDriver) Read(ctx context.Context, query DriverQuery) (DriverProjection, error) {
	return driver.read(ctx, query)
}

func TestStoreUpsertsAndReadsExactScopedProjection(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	nodeA := Node{Scope: scope, NodeID: fixtureID(t, "4"), Kind: "cloud_account"}
	nodeB := Node{Scope: scope, NodeID: fixtureID(t, "5"), Kind: "identity_role"}
	edge := Edge{
		Scope: scope, EdgeID: fixtureID(t, "6"), Kind: "contains_identity",
		SourceID: nodeA.NodeID, TargetID: nodeB.NodeID,
	}
	input := Projection{Nodes: []Node{nodeB, nodeA}, Edges: []Edge{edge}}
	wantDriverProjection := DriverProjection{
		Nodes: []DriverNode{
			driverNode(scope, nodeA),
			driverNode(scope, nodeB),
		},
		Edges: []DriverEdge{driverEdge(scope, edge)},
	}
	wantQuery := DriverQuery{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		RootID:         nodeA.NodeID.String(),
		Direction:      "outgoing",
		MaximumDepth:   1,
		MaximumNodes:   2,
		MaximumEdges:   1,
		NodeSort:       "node_id",
		EdgeSort:       "edge_id",
	}

	var upserts, reads atomic.Int64
	driver := functionDriver{
		upsert: func(ctx context.Context, projection DriverProjection) (DriverUpserted, error) {
			requireDeadline(t, ctx)
			upserts.Add(1)
			if !reflect.DeepEqual(projection, wantDriverProjection) {
				t.Fatalf("Upsert projection = %#v", projection)
			}
			return DriverUpserted{
				NodeIDs: []string{nodeA.NodeID.String(), nodeB.NodeID.String()},
				EdgeIDs: []string{edge.EdgeID.String()},
			}, nil
		},
		read: func(ctx context.Context, query DriverQuery) (DriverProjection, error) {
			requireDeadline(t, ctx)
			reads.Add(1)
			if !reflect.DeepEqual(query, wantQuery) {
				t.Fatalf("Read query = %#v", query)
			}
			return copyDriverProjection(wantDriverProjection), nil
		},
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	var contract GraphStore = store

	if err := contract.Upsert(context.Background(), scope, input); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	if err := contract.Upsert(context.Background(), scope, input); err != nil {
		t.Fatalf("replayed Upsert returned error: %v", err)
	}
	if input.Nodes[0] != nodeB || input.Nodes[1] != nodeA {
		t.Fatalf("Upsert mutated caller order: %#v", input.Nodes)
	}

	result, err := contract.Read(context.Background(), scope, ReadRequest{
		RootID: nodeA.NodeID, Direction: DirectionOutgoing, MaximumDepth: 1,
		MaximumNodes: 2, MaximumEdges: 1,
	})
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	wantResult := Projection{Nodes: []Node{nodeA, nodeB}, Edges: []Edge{edge}}
	if !reflect.DeepEqual(result, wantResult) {
		t.Fatalf("Read result = %#v", result)
	}
	result.Nodes[0] = Node{}
	result.Edges[0] = Edge{}
	if !reflect.DeepEqual(wantDriverProjection.Nodes[0], driverNode(scope, nodeA)) ||
		!reflect.DeepEqual(wantDriverProjection.Edges[0], driverEdge(scope, edge)) {
		t.Fatal("caller mutation changed driver-owned state")
	}
	if upserts.Load() != 2 || reads.Load() != 1 {
		t.Fatalf("calls = upsert %d read %d", upserts.Load(), reads.Load())
	}
}

func TestScopedBuildersRequireExactOrganizationBeforeDriverIO(t *testing.T) {
	t.Parallel()
	organizationA := fixtureScope(t, "1", "2", "3")
	organizationB := fixtureScope(t, "7", "2", "3")
	projection := fixtureProjection(t, organizationA)
	config := validConfig()

	driverProjection, nodeIDs, edgeIDs, ok := buildDriverProjection(organizationA, projection, config)
	if !ok || !reflect.DeepEqual(driverProjection, projectionToDriver(projection)) ||
		!reflect.DeepEqual(nodeIDs, []string{projection.Nodes[0].NodeID.String(), projection.Nodes[1].NodeID.String()}) ||
		!reflect.DeepEqual(edgeIDs, []string{projection.Edges[0].EdgeID.String()}) {
		t.Fatalf("buildDriverProjection = %#v, %#v, %#v, %v", driverProjection, nodeIDs, edgeIDs, ok)
	}

	request := ReadRequest{
		RootID: projection.Nodes[0].NodeID, Direction: DirectionOutgoing,
		MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1,
	}
	query, ok := buildDriverQuery(organizationA, request, config)
	if !ok || query.OrganizationID != organizationA.OrganizationID().String() ||
		query.WorkspaceID != organizationA.WorkspaceID().String() ||
		query.EnvironmentID != organizationA.EnvironmentID().String() || query.RootID != request.RootID.String() ||
		query.Direction != "outgoing" || query.MaximumDepth != 1 || query.MaximumNodes != 2 ||
		query.MaximumEdges != 1 || query.NodeSort != "node_id" || query.EdgeSort != "edge_id" {
		t.Fatalf("buildDriverQuery = %#v, %v", query, ok)
	}

	foreignNode := mutateProjection(projection, func(value *Projection) { value.Nodes[0].Scope = organizationB })
	foreignEdge := mutateProjection(projection, func(value *Projection) { value.Edges[0].Scope = organizationB })
	for name, candidate := range map[string]Projection{"foreign node": foreignNode, "foreign edge": foreignEdge} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, accepted := buildDriverProjection(organizationA, candidate, config); accepted {
				t.Fatalf("buildDriverProjection accepted %s", name)
			}
		})
	}
	if _, _, _, accepted := buildDriverProjection(domain.Scope{}, projection, config); accepted {
		t.Fatal("buildDriverProjection accepted zero scope")
	}
	if _, accepted := buildDriverQuery(domain.Scope{}, request, config); accepted {
		t.Fatal("buildDriverQuery accepted zero scope")
	}
}

func TestOrganizationAPathCannotTraverseOrganizationBFixture(t *testing.T) {
	t.Parallel()
	organizationA := fixtureScope(t, "1", "2", "3")
	organizationB := fixtureScope(t, "7", "2", "3")
	projectionA := fixtureProjection(t, organizationA)
	projectionB := fixtureProjection(t, organizationB)
	driver := newScopedMemoryDriver()
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Upsert(context.Background(), organizationA, projectionA); err != nil {
		t.Fatalf("Organization A Upsert error = %v", err)
	}
	if err := store.Upsert(context.Background(), organizationB, projectionB); err != nil {
		t.Fatalf("Organization B Upsert error = %v", err)
	}
	request := ReadRequest{
		RootID: projectionA.Nodes[0].NodeID, Direction: DirectionOutgoing,
		MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1,
	}
	got, err := store.Read(context.Background(), organizationA, request)
	if err != nil || !reflect.DeepEqual(got, projectionA) {
		t.Fatalf("Organization A Read = %#v, %v", got, err)
	}
	for _, node := range got.Nodes {
		if node.Scope != organizationA || node.Scope == organizationB {
			t.Fatalf("Organization A path contained foreign node %#v", node)
		}
	}
	for _, edge := range got.Edges {
		if edge.Scope != organizationA || edge.Scope == organizationB {
			t.Fatalf("Organization A path contained foreign edge %#v", edge)
		}
	}

	hostile := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
		read: func(context.Context, DriverQuery) (DriverProjection, error) {
			return projectionToDriver(projectionB), nil
		},
	}
	hostileStore, err := New(hostile, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if returned, readErr := hostileStore.Read(context.Background(), organizationA, request); !errors.Is(readErr, ErrRead) || returned.Nodes != nil || returned.Edges != nil {
		t.Fatalf("foreign provider projection = %#v, %v", returned, readErr)
	}
}

func TestStoreSeparatesConcurrentOrganizations(t *testing.T) {
	t.Parallel()
	organizationA := fixtureScope(t, "1", "2", "3")
	organizationB := fixtureScope(t, "7", "2", "3")
	projections := []Projection{fixtureProjection(t, organizationA), fixtureProjection(t, organizationB)}
	scopes := []domain.Scope{organizationA, organizationB}
	driver := newScopedMemoryDriver()
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	for index := range scopes {
		if err := store.Upsert(context.Background(), scopes[index], projections[index]); err != nil {
			t.Fatal(err)
		}
	}

	var wait sync.WaitGroup
	var failed atomic.Bool
	for index := 0; index < 64; index++ {
		selected := index % len(scopes)
		wait.Add(1)
		go func() {
			defer wait.Done()
			if upsertErr := store.Upsert(context.Background(), scopes[selected], projections[selected]); upsertErr != nil {
				failed.Store(true)
				return
			}
			request := ReadRequest{
				RootID: projections[selected].Nodes[0].NodeID, Direction: DirectionOutgoing,
				MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1,
			}
			got, readErr := store.Read(context.Background(), scopes[selected], request)
			if readErr != nil || !reflect.DeepEqual(got, projections[selected]) {
				failed.Store(true)
			}
		}()
	}
	wait.Wait()
	if failed.Load() {
		t.Fatal("concurrent Organization reads crossed scope")
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	driver := noCallDriver()
	var typedNil *functionDriver
	for name, candidate := range map[string]struct {
		driver Driver
		config Config
	}{
		"nil driver":       {driver: nil, config: validConfig()},
		"typed nil driver": {driver: typedNil, config: validConfig()},
		"zero timeout":     {driver: driver, config: func() Config { value := validConfig(); value.OperationTimeout = 0; return value }()},
		"long timeout": {driver: driver, config: func() Config {
			value := validConfig()
			value.OperationTimeout = 30*time.Second + time.Nanosecond
			return value
		}()},
		"zero nodes":     {driver: driver, config: func() Config { value := validConfig(); value.MaximumNodes = 0; return value }()},
		"too many nodes": {driver: driver, config: func() Config { value := validConfig(); value.MaximumNodes = 1001; return value }()},
		"zero edges":     {driver: driver, config: func() Config { value := validConfig(); value.MaximumEdges = 0; return value }()},
		"too many edges": {driver: driver, config: func() Config { value := validConfig(); value.MaximumEdges = 2001; return value }()},
		"zero depth":     {driver: driver, config: func() Config { value := validConfig(); value.MaximumDepth = 0; return value }()},
		"too much depth": {driver: driver, config: func() Config { value := validConfig(); value.MaximumDepth = 9; return value }()},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := New(candidate.driver, candidate.config)
			if store != nil || !errors.Is(err, ErrConfiguration) {
				t.Fatalf("New = %#v, %v", store, err)
			}
		})
	}
}

func TestStoreRejectsInvalidProjectionBeforeDriverIO(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	foreign := fixtureScope(t, "7", "8", "9")
	projection := fixtureProjection(t, scope)
	var calls atomic.Int64
	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) {
			calls.Add(1)
			return DriverUpserted{}, nil
		},
		read: func(context.Context, DriverQuery) (DriverProjection, error) {
			calls.Add(1)
			return DriverProjection{}, nil
		},
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}

	invalid := map[string]Projection{
		"empty":              {},
		"foreign node scope": mutateProjection(projection, func(value *Projection) { value.Nodes[0].Scope = foreign }),
		"foreign edge scope": mutateProjection(projection, func(value *Projection) { value.Edges[0].Scope = foreign }),
		"zero node ID":       mutateProjection(projection, func(value *Projection) { value.Nodes[0].NodeID = domain.ProductID{} }),
		"zero edge ID":       mutateProjection(projection, func(value *Projection) { value.Edges[0].EdgeID = domain.ProductID{} }),
		"zero source":        mutateProjection(projection, func(value *Projection) { value.Edges[0].SourceID = domain.ProductID{} }),
		"zero target":        mutateProjection(projection, func(value *Projection) { value.Edges[0].TargetID = domain.ProductID{} }),
		"bad node kind":      mutateProjection(projection, func(value *Projection) { value.Nodes[0].Kind = "CloudAccount" }),
		"provider node kind": mutateProjection(projection, func(value *Projection) { value.Nodes[0].Kind = "aws_role" }),
		"provider edge kind": mutateProjection(projection, func(value *Projection) { value.Edges[0].Kind = "neo4j_edge" }),
		"duplicate node":     mutateProjection(projection, func(value *Projection) { value.Nodes[1].NodeID = value.Nodes[0].NodeID }),
		"duplicate edge ID":  mutateProjection(projection, func(value *Projection) { value.Edges = append(value.Edges, value.Edges[0]) }),
		"duplicate semantic": mutateProjection(projection, addDuplicateSemanticEdge(t, scope)),
		"self edge":          mutateProjection(projection, func(value *Projection) { value.Edges[0].TargetID = value.Edges[0].SourceID }),
		"dangling source":    mutateProjection(projection, func(value *Projection) { value.Edges[0].SourceID = fixtureID(t, "a") }),
		"dangling target":    mutateProjection(projection, func(value *Projection) { value.Edges[0].TargetID = fixtureID(t, "b") }),
		"too many nodes": mutateProjection(projection, func(value *Projection) {
			value.Nodes = append(value.Nodes, Node{Scope: scope, NodeID: fixtureID(t, "c"), Kind: "runtime"})
		}),
		"too many edges": mutateProjection(projection, addTooManyEdges(t, scope)),
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := store.Upsert(context.Background(), scope, value); !errors.Is(err, ErrProjection) {
				t.Fatalf("Upsert error = %v", err)
			}
		})
	}
	if err := store.Upsert(context.Background(), domain.Scope{}, projection); !errors.Is(err, ErrProjection) {
		t.Fatalf("zero scope error = %v", err)
	}
	if err := store.Upsert(nil, scope, projection); !errors.Is(err, ErrUpsert) {
		t.Fatalf("nil context error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid input reached driver %d times", calls.Load())
	}
}

func TestStoreRejectsInvalidReadRequestBeforeDriverIO(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	root := fixtureID(t, "4")
	var calls atomic.Int64
	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) {
			calls.Add(1)
			return DriverUpserted{}, nil
		},
		read: func(context.Context, DriverQuery) (DriverProjection, error) {
			calls.Add(1)
			return DriverProjection{}, nil
		},
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	valid := ReadRequest{RootID: root, Direction: DirectionOutgoing, MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1}
	invalid := map[string]ReadRequest{
		"zero":              {},
		"zero root":         mutateRequest(valid, func(value *ReadRequest) { value.RootID = domain.ProductID{} }),
		"zero direction":    mutateRequest(valid, func(value *ReadRequest) { value.Direction = 0 }),
		"unknown direction": mutateRequest(valid, func(value *ReadRequest) { value.Direction = 4 }),
		"negative depth":    mutateRequest(valid, func(value *ReadRequest) { value.MaximumDepth = -1 }),
		"deep":              mutateRequest(valid, func(value *ReadRequest) { value.MaximumDepth = 3 }),
		"zero nodes":        mutateRequest(valid, func(value *ReadRequest) { value.MaximumNodes = 0 }),
		"too many nodes":    mutateRequest(valid, func(value *ReadRequest) { value.MaximumNodes = 3 }),
		"zero edges":        mutateRequest(valid, func(value *ReadRequest) { value.MaximumEdges = 0 }),
		"too many edges":    mutateRequest(valid, func(value *ReadRequest) { value.MaximumEdges = 3 }),
	}
	for name, request := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Read(context.Background(), scope, request); !errors.Is(err, ErrReadRequest) {
				t.Fatalf("Read error = %v", err)
			}
		})
	}
	if _, err := store.Read(context.Background(), domain.Scope{}, valid); !errors.Is(err, ErrReadRequest) {
		t.Fatalf("zero scope error = %v", err)
	}
	if _, err := store.Read(nil, scope, valid); !errors.Is(err, ErrRead) {
		t.Fatalf("nil context error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid input reached driver %d times", calls.Load())
	}
}

func TestStoreRejectsMalformedAcknowledgementsAndDriverFailures(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	projection := fixtureProjection(t, scope)
	nodeA, nodeB := projection.Nodes[0].NodeID.String(), projection.Nodes[1].NodeID.String()
	edge := projection.Edges[0].EdgeID.String()
	providerErr := errors.New("provider detail")
	acknowledgements := map[string]DriverUpserted{
		"empty":          {},
		"missing node":   {NodeIDs: []string{nodeA}, EdgeIDs: []string{edge}},
		"foreign node":   {NodeIDs: []string{nodeA, fixtureID(t, "a").String()}, EdgeIDs: []string{edge}},
		"duplicate node": {NodeIDs: []string{nodeA, nodeA}, EdgeIDs: []string{edge}},
		"reversed nodes": {NodeIDs: []string{nodeB, nodeA}, EdgeIDs: []string{edge}},
		"missing edge":   {NodeIDs: []string{nodeA, nodeB}},
		"foreign edge":   {NodeIDs: []string{nodeA, nodeB}, EdgeIDs: []string{fixtureID(t, "a").String()}},
	}
	for name, acknowledgement := range acknowledgements {
		t.Run(name, func(t *testing.T) {
			driver := functionDriver{
				upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return acknowledgement, nil },
				read:   func(context.Context, DriverQuery) (DriverProjection, error) { return DriverProjection{}, nil },
			}
			store, err := New(driver, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Upsert(context.Background(), scope, projection); !errors.Is(err, ErrUpsert) {
				t.Fatalf("Upsert error = %v", err)
			}
		})
	}

	for name, behavior := range map[string]func(context.Context) error{
		"error":    func(context.Context) error { return providerErr },
		"panic":    func(context.Context) error { panic("provider panic detail") },
		"deadline": func(ctx context.Context) error { <-ctx.Done(); return nil },
	} {
		t.Run(name, func(t *testing.T) {
			driver := functionDriver{
				upsert: func(ctx context.Context, _ DriverProjection) (DriverUpserted, error) {
					return DriverUpserted{NodeIDs: []string{nodeA, nodeB}, EdgeIDs: []string{edge}}, behavior(ctx)
				},
				read: func(ctx context.Context, _ DriverQuery) (DriverProjection, error) {
					return DriverProjection{}, behavior(ctx)
				},
			}
			config := validConfig()
			config.OperationTimeout = 5 * time.Millisecond
			store, err := New(driver, config)
			if err != nil {
				t.Fatal(err)
			}
			if returned, panicked := captureError(func() error { return store.Upsert(context.Background(), scope, projection) }); panicked || !errors.Is(returned, ErrUpsert) || errors.Is(returned, providerErr) {
				t.Fatalf("Upsert = %v, panicked=%v", returned, panicked)
			}
			request := ReadRequest{RootID: projection.Nodes[0].NodeID, Direction: DirectionOutgoing, MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1}
			if returned, panicked := captureError(func() error { _, readErr := store.Read(context.Background(), scope, request); return readErr }); panicked || !errors.Is(returned, ErrRead) || errors.Is(returned, providerErr) {
				t.Fatalf("Read = %v, panicked=%v", returned, panicked)
			}
		})
	}
}

func TestStoreRejectsMalformedReadResults(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	foreign := fixtureScope(t, "7", "8", "9")
	projection := fixtureProjection(t, scope)
	valid := projectionToDriver(projection)
	request := ReadRequest{RootID: projection.Nodes[0].NodeID, Direction: DirectionOutgoing, MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1}

	cases := map[string]DriverProjection{
		"foreign node scope": mutateDriverProjection(valid, func(value *DriverProjection) { value.Nodes[0].OrganizationID = foreign.OrganizationID().String() }),
		"foreign edge scope": mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges[0].WorkspaceID = foreign.WorkspaceID().String() }),
		"malformed node ID":  mutateDriverProjection(valid, func(value *DriverProjection) { value.Nodes[0].NodeID = "provider-id" }),
		"malformed edge ID":  mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges[0].EdgeID = "provider-id" }),
		"bad node kind":      mutateDriverProjection(valid, func(value *DriverProjection) { value.Nodes[0].Kind = "AWSRole" }),
		"bad edge kind":      mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges[0].Kind = "neo4j_edge" }),
		"duplicate node":     mutateDriverProjection(valid, func(value *DriverProjection) { value.Nodes[1] = value.Nodes[0] }),
		"unsorted nodes":     mutateDriverProjection(valid, func(value *DriverProjection) { value.Nodes[0], value.Nodes[1] = value.Nodes[1], value.Nodes[0] }),
		"duplicate edge":     mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges = append(value.Edges, value.Edges[0]) }),
		"dangling edge":      mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges[0].TargetID = fixtureID(t, "a").String() }),
		"self edge":          mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges[0].TargetID = value.Edges[0].SourceID }),
		"root missing":       mutateDriverProjection(valid, func(value *DriverProjection) { value.Nodes = value.Nodes[1:]; value.Edges = nil }),
		"oversized nodes":    mutateDriverProjection(valid, addUnreachableDriverNode(t, scope)),
	}
	for name, returned := range cases {
		t.Run(name, func(t *testing.T) {
			driver := functionDriver{
				upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
				read:   func(context.Context, DriverQuery) (DriverProjection, error) { return returned, nil },
			}
			store, err := New(driver, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Read(context.Background(), scope, request); !errors.Is(err, ErrRead) {
				t.Fatalf("Read error = %v", err)
			}
		})
	}

	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
		read:   func(context.Context, DriverQuery) (DriverProjection, error) { return DriverProjection{}, nil },
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Read(context.Background(), scope, request); err != nil || result.Nodes == nil || result.Edges == nil || len(result.Nodes) != 0 || len(result.Edges) != 0 {
		t.Fatalf("empty Read = %#v, %v", result, err)
	}
}

func TestReadRejectsOversizedDriverResultBeforeCopyingIt(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	projection := fixtureProjection(t, scope)
	oversized := DriverProjection{Nodes: make([]DriverNode, 4_096)}
	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
		read:   func(context.Context, DriverQuery) (DriverProjection, error) { return oversized, nil },
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	request := ReadRequest{
		RootID: projection.Nodes[0].NodeID, Direction: DirectionOutgoing,
		MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1,
	}
	measurement := testing.Benchmark(func(benchmark *testing.B) {
		for index := 0; index < benchmark.N; index++ {
			if _, err := store.Read(context.Background(), scope, request); !errors.Is(err, ErrRead) {
				benchmark.Fatalf("Read error = %v", err)
			}
		}
	})
	if measurement.AllocedBytesPerOp() > 32*1_024 {
		t.Fatalf("oversized rejection allocated %d bytes per operation", measurement.AllocedBytesPerOp())
	}
}

func TestStoreEnforcesDirectionAndDepth(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	nodeA := Node{Scope: scope, NodeID: fixtureID(t, "4"), Kind: "cloud_account"}
	nodeB := Node{Scope: scope, NodeID: fixtureID(t, "5"), Kind: "identity_role"}
	edge := Edge{Scope: scope, EdgeID: fixtureID(t, "6"), Kind: "contains_identity", SourceID: nodeA.NodeID, TargetID: nodeB.NodeID}
	returned := projectionToDriver(Projection{Nodes: []Node{nodeA, nodeB}, Edges: []Edge{edge}})
	for name, candidate := range map[string]struct {
		root      domain.ProductID
		direction Direction
		depth     int
		wantError bool
	}{
		"outgoing":             {root: nodeA.NodeID, direction: DirectionOutgoing, depth: 1},
		"incoming":             {root: nodeB.NodeID, direction: DirectionIncoming, depth: 1},
		"both from source":     {root: nodeA.NodeID, direction: DirectionBoth, depth: 1},
		"both from target":     {root: nodeB.NodeID, direction: DirectionBoth, depth: 1},
		"wrong outgoing":       {root: nodeB.NodeID, direction: DirectionOutgoing, depth: 1, wantError: true},
		"wrong incoming":       {root: nodeA.NodeID, direction: DirectionIncoming, depth: 1, wantError: true},
		"depth zero with edge": {root: nodeA.NodeID, direction: DirectionOutgoing, depth: 0, wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			driver := functionDriver{
				upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
				read:   func(context.Context, DriverQuery) (DriverProjection, error) { return returned, nil },
			}
			store, err := New(driver, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.Read(context.Background(), scope, ReadRequest{
				RootID: candidate.root, Direction: candidate.direction, MaximumDepth: candidate.depth,
				MaximumNodes: 2, MaximumEdges: 1,
			})
			if candidate.wantError != errors.Is(err, ErrRead) {
				t.Fatalf("Read error = %v, wantError=%v", err, candidate.wantError)
			}
		})
	}
}

func TestStoreRejectsUnreachableAndNoncanonicalMultiEdgeResults(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	nodeA := Node{Scope: scope, NodeID: fixtureID(t, "4"), Kind: "cloud_account"}
	nodeB := Node{Scope: scope, NodeID: fixtureID(t, "5"), Kind: "identity_role"}
	nodeC := Node{Scope: scope, NodeID: fixtureID(t, "a"), Kind: "runtime"}
	edgeA := Edge{Scope: scope, EdgeID: fixtureID(t, "6"), Kind: "contains_identity", SourceID: nodeA.NodeID, TargetID: nodeB.NodeID}
	edgeB := Edge{Scope: scope, EdgeID: fixtureID(t, "b"), Kind: "runs_on", SourceID: nodeB.NodeID, TargetID: nodeC.NodeID}
	valid := projectionToDriver(Projection{Nodes: []Node{nodeA, nodeB, nodeC}, Edges: []Edge{edgeA, edgeB}})
	config := validConfig()
	config.MaximumNodes = 3
	request := ReadRequest{RootID: nodeA.NodeID, Direction: DirectionOutgoing, MaximumDepth: 2, MaximumNodes: 3, MaximumEdges: 2}

	cases := map[string]DriverProjection{
		"unreachable within depth": mutateDriverProjection(valid, func(value *DriverProjection) { value.Edges = value.Edges[:1] }),
		"unsorted edges": mutateDriverProjection(valid, func(value *DriverProjection) {
			value.Edges[0], value.Edges[1] = value.Edges[1], value.Edges[0]
		}),
		"duplicate edge ID": mutateDriverProjection(valid, func(value *DriverProjection) {
			value.Edges[1] = value.Edges[0]
		}),
		"duplicate semantic edge": mutateDriverProjection(valid, func(value *DriverProjection) {
			value.Edges[1].Kind = value.Edges[0].Kind
			value.Edges[1].SourceID = value.Edges[0].SourceID
			value.Edges[1].TargetID = value.Edges[0].TargetID
		}),
	}
	for name, returned := range cases {
		t.Run(name, func(t *testing.T) {
			driver := functionDriver{
				upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
				read:   func(context.Context, DriverQuery) (DriverProjection, error) { return returned, nil },
			}
			store, err := New(driver, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Read(context.Background(), scope, request); !errors.Is(err, ErrRead) {
				t.Fatalf("Read error = %v", err)
			}
		})
	}

	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { return DriverUpserted{}, nil },
		read:   func(context.Context, DriverQuery) (DriverProjection, error) { return valid, nil },
	}
	store, err := New(driver, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(context.Background(), scope, request); err != nil {
		t.Fatalf("two-depth Read error = %v", err)
	}
}

func TestStoreRejectsCanceledAndNilReceiversWithoutDriverIO(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	projection := fixtureProjection(t, scope)
	request := ReadRequest{RootID: projection.Nodes[0].NodeID, Direction: DirectionOutgoing, MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1}
	var calls atomic.Int64
	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) {
			calls.Add(1)
			return DriverUpserted{}, nil
		},
		read: func(context.Context, DriverQuery) (DriverProjection, error) {
			calls.Add(1)
			return DriverProjection{}, nil
		},
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Upsert(canceled, scope, projection); !errors.Is(err, ErrUpsert) {
		t.Fatalf("canceled Upsert error = %v", err)
	}
	if _, err := store.Read(canceled, scope, request); !errors.Is(err, ErrRead) {
		t.Fatalf("canceled Read error = %v", err)
	}
	var nilStore *Store
	if err := nilStore.Upsert(context.Background(), scope, projection); !errors.Is(err, ErrUpsert) {
		t.Fatalf("nil Upsert error = %v", err)
	}
	if _, err := nilStore.Read(context.Background(), scope, request); !errors.Is(err, ErrRead) {
		t.Fatalf("nil Read error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("canceled input reached driver %d times", calls.Load())
	}
}

func TestUpsertDefendsCallerProjectionFromDriverMutation(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	projection := fixtureProjection(t, scope)
	want := mutateProjection(projection, func(*Projection) {})
	driver := functionDriver{
		upsert: func(_ context.Context, received DriverProjection) (DriverUpserted, error) {
			nodeIDs := []string{received.Nodes[0].NodeID, received.Nodes[1].NodeID}
			edgeIDs := []string{received.Edges[0].EdgeID}
			received.Nodes[0] = DriverNode{}
			received.Edges[0] = DriverEdge{}
			return DriverUpserted{NodeIDs: nodeIDs, EdgeIDs: edgeIDs}, nil
		},
		read: func(context.Context, DriverQuery) (DriverProjection, error) { return DriverProjection{}, nil },
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(context.Background(), scope, projection); err != nil {
		t.Fatalf("Upsert error = %v", err)
	}
	if !reflect.DeepEqual(projection, want) {
		t.Fatalf("driver mutation changed caller projection: %#v", projection)
	}
}

func TestStoreSupportsConcurrentIndependentCalls(t *testing.T) {
	t.Parallel()
	scope := fixtureScope(t, "1", "2", "3")
	projection := fixtureProjection(t, scope)
	driverProjection := projectionToDriver(projection)
	var calls atomic.Int64
	driver := functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) {
			calls.Add(1)
			return DriverUpserted{
				NodeIDs: []string{projection.Nodes[0].NodeID.String(), projection.Nodes[1].NodeID.String()},
				EdgeIDs: []string{projection.Edges[0].EdgeID.String()},
			}, nil
		},
		read: func(context.Context, DriverQuery) (DriverProjection, error) {
			calls.Add(1)
			return copyDriverProjection(driverProjection), nil
		},
	}
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	request := ReadRequest{RootID: projection.Nodes[0].NodeID, Direction: DirectionOutgoing, MaximumDepth: 1, MaximumNodes: 2, MaximumEdges: 1}
	var wait sync.WaitGroup
	var failed atomic.Bool
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := store.Upsert(context.Background(), scope, projection); err != nil {
				failed.Store(true)
			}
			if _, err := store.Read(context.Background(), scope, request); err != nil {
				failed.Store(true)
			}
		}()
	}
	wait.Wait()
	if failed.Load() || calls.Load() != 64 {
		t.Fatalf("concurrent calls failed=%v calls=%d", failed.Load(), calls.Load())
	}
}

func validConfig() Config {
	return Config{OperationTimeout: time.Second, MaximumNodes: 2, MaximumEdges: 2, MaximumDepth: 2}
}

func noCallDriver() Driver {
	return functionDriver{
		upsert: func(context.Context, DriverProjection) (DriverUpserted, error) { panic("unexpected Upsert") },
		read:   func(context.Context, DriverQuery) (DriverProjection, error) { panic("unexpected Read") },
	}
}

func fixtureScope(t *testing.T, organization, workspace, environment string) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureID(t, organization), fixtureID(t, workspace), fixtureID(t, environment))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func fixtureID(t *testing.T, suffix string) domain.ProductID {
	t.Helper()
	value := "pid_" + suffix + "0000000-0000-4000-8000-00000000000" + suffix
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatalf("ParseProductID(%q): %v", value, err)
	}
	return id
}

func fixtureProjection(t *testing.T, scope domain.Scope) Projection {
	t.Helper()
	nodeA := Node{Scope: scope, NodeID: fixtureID(t, "4"), Kind: "cloud_account"}
	nodeB := Node{Scope: scope, NodeID: fixtureID(t, "5"), Kind: "identity_role"}
	return Projection{
		Nodes: []Node{nodeA, nodeB},
		Edges: []Edge{{
			Scope: scope, EdgeID: fixtureID(t, "6"), Kind: "contains_identity",
			SourceID: nodeA.NodeID, TargetID: nodeB.NodeID,
		}},
	}
}

func driverNode(scope domain.Scope, node Node) DriverNode {
	return DriverNode{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(),
		EnvironmentID: scope.EnvironmentID().String(), NodeID: node.NodeID.String(), Kind: node.Kind,
	}
}

func driverEdge(scope domain.Scope, edge Edge) DriverEdge {
	return DriverEdge{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(),
		EnvironmentID: scope.EnvironmentID().String(), EdgeID: edge.EdgeID.String(), Kind: edge.Kind,
		SourceID: edge.SourceID.String(), TargetID: edge.TargetID.String(),
	}
}

func projectionToDriver(projection Projection) DriverProjection {
	nodes := make([]DriverNode, len(projection.Nodes))
	for index, node := range projection.Nodes {
		nodes[index] = driverNode(node.Scope, node)
	}
	edges := make([]DriverEdge, len(projection.Edges))
	for index, edge := range projection.Edges {
		edges[index] = driverEdge(edge.Scope, edge)
	}
	return DriverProjection{Nodes: nodes, Edges: edges}
}

func copyDriverProjection(value DriverProjection) DriverProjection {
	return DriverProjection{
		Nodes: append([]DriverNode(nil), value.Nodes...),
		Edges: append([]DriverEdge(nil), value.Edges...),
	}
}

func mutateProjection(value Projection, mutate func(*Projection)) Projection {
	copy := Projection{Nodes: append([]Node(nil), value.Nodes...), Edges: append([]Edge(nil), value.Edges...)}
	mutate(&copy)
	return copy
}

func mutateDriverProjection(value DriverProjection, mutate func(*DriverProjection)) DriverProjection {
	copy := copyDriverProjection(value)
	mutate(&copy)
	return copy
}

func mutateRequest(value ReadRequest, mutate func(*ReadRequest)) ReadRequest {
	mutate(&value)
	return value
}

func addDuplicateSemanticEdge(t *testing.T, scope domain.Scope) func(*Projection) {
	t.Helper()
	return func(value *Projection) {
		copy := value.Edges[0]
		copy.EdgeID = fixtureID(t, "a")
		copy.Scope = scope
		value.Edges = append(value.Edges, copy)
	}
}

func addTooManyEdges(t *testing.T, scope domain.Scope) func(*Projection) {
	t.Helper()
	return func(value *Projection) {
		value.Edges = append(value.Edges,
			Edge{
				Scope: scope, EdgeID: fixtureID(t, "a"), Kind: "can_assume",
				SourceID: value.Nodes[1].NodeID, TargetID: value.Nodes[0].NodeID,
			},
			Edge{
				Scope: scope, EdgeID: fixtureID(t, "b"), Kind: "related_to",
				SourceID: value.Nodes[0].NodeID, TargetID: value.Nodes[1].NodeID,
			},
		)
	}
}

func addUnreachableDriverNode(t *testing.T, scope domain.Scope) func(*DriverProjection) {
	t.Helper()
	return func(value *DriverProjection) {
		value.Nodes = append(value.Nodes, DriverNode{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(),
			EnvironmentID: scope.EnvironmentID().String(), NodeID: fixtureID(t, "a").String(), Kind: "runtime",
		})
	}
}

func requireDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
		t.Fatalf("operation context deadline = %v, %v", deadline, ok)
	}
}

func captureError(call func() error) (returned error, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return call(), false
}
