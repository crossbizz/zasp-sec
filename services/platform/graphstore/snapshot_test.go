package graphstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type snapshotFunctionDriver struct {
	Driver
	replace func(context.Context, DriverSnapshotProjection) (DriverSnapshotReplaced, error)
}

func (driver *snapshotFunctionDriver) ReplaceSnapshot(ctx context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
	return driver.replace(ctx, input)
}

func TestStoreAppliesCanonicalCompleteSnapshotWithoutBreakingLegacyDriver(t *testing.T) {
	t.Parallel()

	snapshot := fixtureCompleteSnapshot(t, 7, "7")
	wantDigest := [sha256.Size]byte{0x08, 0xb8, 0xea, 0xc5, 0x7d, 0x72, 0x0d, 0x4f, 0x4c, 0x33, 0x3c, 0x12, 0x5f, 0xad, 0xe1, 0xb1, 0x4a, 0x40, 0xc9, 0xd9, 0x8f, 0xf4, 0x28, 0x60, 0x51, 0x2e, 0x13, 0xcf, 0x67, 0xdf, 0xee, 0xd6}
	driver := &snapshotFunctionDriver{Driver: noCallDriver()}
	driver.replace = func(ctx context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
		requireDeadline(t, ctx)
		wantBinding := DriverSnapshot{OrganizationID: snapshot.Scope.OrganizationID().String(), WorkspaceID: snapshot.Scope.WorkspaceID().String(), EnvironmentID: snapshot.Scope.EnvironmentID().String(), IntegrationID: snapshot.IntegrationID.String(), SnapshotID: snapshot.SnapshotID.String(), Generation: 7, InputDigest: snapshot.InputDigest, ContentDigest: wantDigest}
		if input.Snapshot != wantBinding || len(input.Nodes) != 2 || len(input.Edges) != 1 || input.Nodes[0].NodeID != snapshot.Projection.Nodes[1].NodeID.String() || input.Nodes[1].NodeID != snapshot.Projection.Nodes[0].NodeID.String() || input.Edges[0].EdgeID != snapshot.Projection.Edges[0].EdgeID.String() {
			t.Fatalf("ReplaceSnapshot input = %#v", input)
		}
		for _, node := range input.Nodes {
			if node.Snapshot != input.Snapshot {
				t.Fatalf("node binding = %#v", node)
			}
		}
		for _, edge := range input.Edges {
			if edge.Snapshot != input.Snapshot {
				t.Fatalf("edge binding = %#v", edge)
			}
		}
		return DriverSnapshotReplaced{ActiveSnapshot: input.Snapshot, NodeIDs: driverSnapshotNodeIDs(input.Nodes), EdgeIDs: driverSnapshotEdgeIDs(input.Edges), RemovedNodes: 2, RemovedEdges: 3}, nil
	}
	store := mustGraphStore(t, driver)
	result, err := store.ApplySnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("ApplySnapshot() error = %v", err)
	}
	if result.SnapshotID != snapshot.SnapshotID || result.Generation != snapshot.Generation || result.InputDigest != snapshot.InputDigest || result.ContentDigest != wantDigest || result.Replayed || result.RemovedNodes != 2 || result.RemovedEdges != 3 {
		t.Fatalf("ApplySnapshot() = %#v", result)
	}
}

func TestStoreCompleteSnapshotAcceptsEmptyAndCanonicalizesEquivalentOrder(t *testing.T) {
	t.Parallel()

	original := fixtureCompleteSnapshot(t, 7, "7")
	reordered := original
	reordered.Projection.Nodes = append([]Node(nil), original.Projection.Nodes...)
	reordered.Projection.Nodes[0], reordered.Projection.Nodes[1] = reordered.Projection.Nodes[1], reordered.Projection.Nodes[0]
	empty := fixtureCompleteSnapshot(t, 8, "8")
	empty.Projection = Projection{Nodes: []Node{}, Edges: []Edge{}}
	digests := make([][sha256.Size]byte, 0, 3)
	driver := &snapshotFunctionDriver{Driver: noCallDriver()}
	driver.replace = func(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
		digests = append(digests, input.Snapshot.ContentDigest)
		return DriverSnapshotReplaced{ActiveSnapshot: input.Snapshot, NodeIDs: driverSnapshotNodeIDs(input.Nodes), EdgeIDs: driverSnapshotEdgeIDs(input.Edges)}, nil
	}
	store := mustGraphStore(t, driver)
	for _, snapshot := range []CompleteSnapshot{original, reordered, empty} {
		if _, err := store.ApplySnapshot(context.Background(), snapshot); err != nil {
			t.Fatalf("ApplySnapshot() error = %v", err)
		}
	}
	if digests[0] != digests[1] || digests[0] == digests[2] {
		t.Fatalf("content digests = %x / %x / %x", digests[0], digests[1], digests[2])
	}
}

func TestStoreSnapshotGenerationAndDriftErrorsRemainStableAndRedacted(t *testing.T) {
	t.Parallel()

	for _, stable := range []error{ErrSnapshotCanceled, ErrSnapshotRetryable, ErrSnapshotUnknownOutcome, ErrSnapshotStale, ErrSnapshotDrift, ErrSnapshotDenied, ErrSnapshotUnavailable} {
		driver := &snapshotFunctionDriver{Driver: noCallDriver(), replace: func(context.Context, DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
			return DriverSnapshotReplaced{}, errors.Join(stable, errors.New("password=must-not-escape"))
		}}
		if _, err := mustGraphStore(t, driver).ApplySnapshot(context.Background(), fixtureCompleteSnapshot(t, 7, "7")); !errors.Is(err, stable) || err.Error() != stable.Error() {
			t.Fatalf("ApplySnapshot(%v) error = %q", stable, err)
		}
	}
}

func TestStoreRejectsHostileSnapshotAcknowledgementAndLegacyOnlyDriver(t *testing.T) {
	t.Parallel()

	snapshot := fixtureCompleteSnapshot(t, 7, "7")
	driver := &snapshotFunctionDriver{Driver: noCallDriver()}
	driver.replace = func(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
		input.Snapshot.ContentDigest[0] ^= 0xff
		return DriverSnapshotReplaced{ActiveSnapshot: input.Snapshot, NodeIDs: driverSnapshotNodeIDs(input.Nodes), EdgeIDs: driverSnapshotEdgeIDs(input.Edges)}, nil
	}
	if _, err := mustGraphStore(t, driver).ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrSnapshotDrift) {
		t.Fatalf("ApplySnapshot(hostile ACK) error = %v", err)
	}
	legacy := mustGraphStore(t, noCallDriver())
	if _, err := legacy.ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatalf("ApplySnapshot(legacy-only driver) error = %v", err)
	}
}

func TestSnapshotStateMachineRejectsOlderAndSameGenerationDriftAtomically(t *testing.T) {
	t.Parallel()

	driver := newSnapshotMemoryDriver()
	store := mustGraphStore(t, driver)
	newer := fixtureCompleteSnapshot(t, 8, "8")
	newerResult, err := store.ApplySnapshot(context.Background(), newer)
	if err != nil {
		t.Fatalf("ApplySnapshot(newer) error = %v", err)
	}
	older := fixtureCompleteSnapshot(t, 7, "7")
	if _, err := store.ApplySnapshot(context.Background(), older); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("ApplySnapshot(older) error = %v", err)
	}
	drifted := fixtureCompleteSnapshot(t, 8, "9")
	if _, err := store.ApplySnapshot(context.Background(), drifted); !errors.Is(err, ErrSnapshotDrift) {
		t.Fatalf("ApplySnapshot(same generation drift) error = %v", err)
	}
	if driver.active.Generation != newer.Generation || !reflect.DeepEqual(driver.nodeIDs, newerResult.NodeIDs) || !reflect.DeepEqual(driver.edgeIDs, newerResult.EdgeIDs) {
		t.Fatalf("active state = %#v nodes=%#v edges=%#v", driver.active, driver.nodeIDs, driver.edgeIDs)
	}
}

type snapshotMemoryDriver struct {
	mu      sync.Mutex
	active  DriverSnapshot
	nodeIDs []string
	edgeIDs []string
}

func newSnapshotMemoryDriver() *snapshotMemoryDriver { return &snapshotMemoryDriver{} }

func (driver *snapshotMemoryDriver) Upsert(context.Context, DriverProjection) (DriverUpserted, error) {
	return DriverUpserted{}, errors.New("unexpected legacy upsert")
}

func (driver *snapshotMemoryDriver) Read(context.Context, DriverQuery) (DriverProjection, error) {
	return DriverProjection{}, errors.New("unexpected legacy read")
}

func (driver *snapshotMemoryDriver) ReplaceSnapshot(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.active.Generation > input.Snapshot.Generation {
		return DriverSnapshotReplaced{}, ErrSnapshotStale
	}
	if driver.active.Generation == input.Snapshot.Generation {
		if driver.active != input.Snapshot || !reflect.DeepEqual(driver.nodeIDs, driverSnapshotNodeIDs(input.Nodes)) || !reflect.DeepEqual(driver.edgeIDs, driverSnapshotEdgeIDs(input.Edges)) {
			return DriverSnapshotReplaced{}, ErrSnapshotDrift
		}
		return DriverSnapshotReplaced{ActiveSnapshot: driver.active, NodeIDs: append([]string(nil), driver.nodeIDs...), EdgeIDs: append([]string(nil), driver.edgeIDs...), Replayed: true}, nil
	}
	driver.active = input.Snapshot
	driver.nodeIDs = driverSnapshotNodeIDs(input.Nodes)
	driver.edgeIDs = driverSnapshotEdgeIDs(input.Edges)
	return DriverSnapshotReplaced{ActiveSnapshot: driver.active, NodeIDs: append([]string(nil), driver.nodeIDs...), EdgeIDs: append([]string(nil), driver.edgeIDs...)}, nil
}

func fixtureCompleteSnapshot(t *testing.T, generation int64, suffix string) CompleteSnapshot {
	t.Helper()
	scope := fixtureScope(t, "1", "2", "3")
	nodeA := Node{Scope: scope, NodeID: fixtureID(t, "4"), Kind: "cloud_account"}
	nodeB := Node{Scope: scope, NodeID: fixtureID(t, "5"), Kind: "identity_role"}
	return CompleteSnapshot{
		Scope: scope, IntegrationID: fixtureID(t, "6"), SnapshotID: fixtureID(t, suffix), Generation: generation,
		InputDigest: sha256.Sum256([]byte("graph-input-" + suffix)),
		Projection:  Projection{Nodes: []Node{nodeB, nodeA}, Edges: []Edge{{Scope: scope, EdgeID: fixtureID(t, "a"), Kind: "contains_identity", SourceID: nodeA.NodeID, TargetID: nodeB.NodeID}}},
	}
}

func mustGraphStore(t *testing.T, driver Driver) *Store {
	t.Helper()
	store, err := New(driver, validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store
}

func driverSnapshotNodeIDs(nodes []DriverSnapshotNode) []string {
	ids := make([]string, len(nodes))
	for index, node := range nodes {
		ids[index] = node.NodeID
	}
	return ids
}

func driverSnapshotEdgeIDs(edges []DriverSnapshotEdge) []string {
	ids := make([]string, len(edges))
	for index, edge := range edges {
		ids[index] = edge.EdgeID
	}
	return ids
}
