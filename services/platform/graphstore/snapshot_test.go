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
	wantDigest := [sha256.Size]byte{0xbd, 0x12, 0x5f, 0x8a, 0x3e, 0xf8, 0xbe, 0x95, 0x68, 0x47, 0x4c, 0xf5, 0xba, 0x79, 0xde, 0xf4, 0x96, 0x46, 0xaa, 0xc4, 0x3b, 0x6f, 0x0d, 0x90, 0xcb, 0x1a, 0x66, 0x31, 0xac, 0x47, 0xd9, 0x6c}
	driver := &snapshotFunctionDriver{Driver: noCallDriver()}
	driver.replace = func(ctx context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
		requireDeadline(t, ctx)
		wantBinding := DriverSnapshot{OrganizationID: snapshot.Scope.OrganizationID().String(), WorkspaceID: snapshot.Scope.WorkspaceID().String(), EnvironmentID: snapshot.Scope.EnvironmentID().String(), IntegrationID: snapshot.IntegrationID.String(), Source: snapshot.Source, SnapshotID: snapshot.SnapshotID.String(), Generation: 7, InputDigest: snapshot.InputDigest, ContentDigest: wantDigest}
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
		return durableSnapshotAcknowledgement(input, false, 2, 3), nil
	}
	store := mustGraphStore(t, driver)
	result, err := store.ApplySnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("ApplySnapshot() error = %v", err)
	}
	if result.SnapshotID != snapshot.SnapshotID || result.Source != snapshot.Source || result.Generation != snapshot.Generation || result.InputDigest != snapshot.InputDigest || result.ContentDigest != wantDigest || result.Replayed || result.RemovedNodes != 2 || result.RemovedEdges != 3 {
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
	differentSource := original
	differentSource.Source = "kubernetes"
	digests := make([][sha256.Size]byte, 0, 4)
	driver := &snapshotFunctionDriver{Driver: noCallDriver()}
	driver.replace = func(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
		digests = append(digests, input.Snapshot.ContentDigest)
		return durableSnapshotAcknowledgement(input, false, 0, 0), nil
	}
	store := mustGraphStore(t, driver)
	for _, snapshot := range []CompleteSnapshot{original, reordered, empty, differentSource} {
		if _, err := store.ApplySnapshot(context.Background(), snapshot); err != nil {
			t.Fatalf("ApplySnapshot() error = %v", err)
		}
	}
	if digests[0] != digests[1] || digests[0] == digests[2] || digests[0] == digests[3] {
		t.Fatalf("content digests = %x / %x / %x / %x", digests[0], digests[1], digests[2], digests[3])
	}
}

func TestStoreSnapshotGenerationAndDriftErrorsRemainStableAndRedacted(t *testing.T) {
	t.Parallel()

	for _, stable := range []error{ErrSnapshotCanceled, ErrSnapshotRetryable, ErrSnapshotUnknownOutcome, ErrSnapshotStale, ErrSnapshotDrift, ErrSnapshotDenied, ErrSnapshotUnavailable} {
		driver := &snapshotFunctionDriver{Driver: noCallDriver(), replace: func(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
			return noMutationSnapshotAcknowledgement(input, stable), errors.Join(stable, errors.New("password=must-not-escape"))
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
		return durableSnapshotAcknowledgement(input, false, 0, 0), nil
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
	state := driver.stateFor(snapshotGenerationKeyFromComplete(newer))
	if state.active.Generation != newer.Generation || !reflect.DeepEqual(state.nodeIDs, newerResult.NodeIDs) || !reflect.DeepEqual(state.edgeIDs, newerResult.EdgeIDs) {
		t.Fatalf("active state = %#v nodes=%#v edges=%#v", state.active, state.nodeIDs, state.edgeIDs)
	}
}

func TestSnapshotStateMachineSeparatesSourcesWithinIntegration(t *testing.T) {
	t.Parallel()

	driver := newSnapshotMemoryDriver()
	store := mustGraphStore(t, driver)
	aws := fixtureCompleteSnapshot(t, 8, "8")
	kubernetes := fixtureCompleteSnapshot(t, 7, "7")
	kubernetes.Source = "kubernetes"
	if _, err := store.ApplySnapshot(context.Background(), aws); err != nil {
		t.Fatalf("ApplySnapshot(aws) error = %v", err)
	}
	if _, err := store.ApplySnapshot(context.Background(), kubernetes); err != nil {
		t.Fatalf("ApplySnapshot(kubernetes) error = %v", err)
	}
	if driver.stateFor(snapshotGenerationKeyFromComplete(aws)).active.Source != "aws" || driver.stateFor(snapshotGenerationKeyFromComplete(kubernetes)).active.Source != "kubernetes" || len(driver.states) != 2 {
		t.Fatalf("source states = %#v", driver.states)
	}
}

func TestSnapshotMutationAmbiguityFailsUnknown(t *testing.T) {
	t.Parallel()

	snapshot := fixtureCompleteSnapshot(t, 7, "7")
	t.Run("commit then cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		driver := &snapshotFunctionDriver{Driver: noCallDriver(), replace: func(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
			cancel()
			return durableSnapshotAcknowledgement(input, false, 0, 0), nil
		}}
		if _, err := mustGraphStore(t, driver).ApplySnapshot(ctx, snapshot); !errors.Is(err, ErrSnapshotUnknownOutcome) {
			t.Fatalf("ApplySnapshot(commit then cancel) error = %v", err)
		}
	})
	t.Run("driver panic", func(t *testing.T) {
		driver := &snapshotFunctionDriver{Driver: noCallDriver(), replace: func(context.Context, DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
			panic("secret after mutation")
		}}
		if _, err := mustGraphStore(t, driver).ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrSnapshotUnknownOutcome) || err.Error() != ErrSnapshotUnknownOutcome.Error() {
			t.Fatalf("ApplySnapshot(panic) error = %v", err)
		}
	})
	t.Run("lost acknowledgement", func(t *testing.T) {
		driver := &snapshotFunctionDriver{Driver: noCallDriver(), replace: func(context.Context, DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
			return DriverSnapshotReplaced{}, errors.New("connection reset after commit")
		}}
		if _, err := mustGraphStore(t, driver).ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrSnapshotUnknownOutcome) || err.Error() != ErrSnapshotUnknownOutcome.Error() {
			t.Fatalf("ApplySnapshot(lost ACK) error = %v", err)
		}
	})
}

type snapshotMemoryDriver struct {
	mu     sync.Mutex
	states map[string]snapshotMemoryState
}

type snapshotMemoryState struct {
	active  DriverSnapshot
	nodeIDs []string
	edgeIDs []string
}

func newSnapshotMemoryDriver() *snapshotMemoryDriver {
	return &snapshotMemoryDriver{states: make(map[string]snapshotMemoryState)}
}

func (driver *snapshotMemoryDriver) Upsert(context.Context, DriverProjection) (DriverUpserted, error) {
	return DriverUpserted{}, errors.New("unexpected legacy upsert")
}

func (driver *snapshotMemoryDriver) Read(context.Context, DriverQuery) (DriverProjection, error) {
	return DriverProjection{}, errors.New("unexpected legacy read")
}

func (driver *snapshotMemoryDriver) ReplaceSnapshot(_ context.Context, input DriverSnapshotProjection) (DriverSnapshotReplaced, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	key := snapshotGenerationKey(input.Snapshot)
	state := driver.states[key]
	if state.active.Generation > input.Snapshot.Generation {
		return DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: state.active, NodeIDs: append([]string(nil), state.nodeIDs...), EdgeIDs: append([]string(nil), state.edgeIDs...), Outcome: DriverSnapshotNoMutation}, ErrSnapshotStale
	}
	if state.active.Generation == input.Snapshot.Generation {
		if state.active != input.Snapshot || !reflect.DeepEqual(state.nodeIDs, driverSnapshotNodeIDs(input.Nodes)) || !reflect.DeepEqual(state.edgeIDs, driverSnapshotEdgeIDs(input.Edges)) {
			return DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: state.active, NodeIDs: append([]string(nil), state.nodeIDs...), EdgeIDs: append([]string(nil), state.edgeIDs...), Outcome: DriverSnapshotNoMutation}, ErrSnapshotDrift
		}
		return DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: state.active, NodeIDs: append([]string(nil), state.nodeIDs...), EdgeIDs: append([]string(nil), state.edgeIDs...), Replayed: true, Outcome: DriverSnapshotDurable}, nil
	}
	state.active = input.Snapshot
	state.nodeIDs = driverSnapshotNodeIDs(input.Nodes)
	state.edgeIDs = driverSnapshotEdgeIDs(input.Edges)
	driver.states[key] = state
	return DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: state.active, NodeIDs: append([]string(nil), state.nodeIDs...), EdgeIDs: append([]string(nil), state.edgeIDs...), Outcome: DriverSnapshotDurable}, nil
}

func (driver *snapshotMemoryDriver) stateFor(key string) snapshotMemoryState {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.states[key]
}

func fixtureCompleteSnapshot(t *testing.T, generation int64, suffix string) CompleteSnapshot {
	t.Helper()
	scope := fixtureScope(t, "1", "2", "3")
	nodeA := Node{Scope: scope, NodeID: fixtureID(t, "4"), Kind: "cloud_account"}
	nodeB := Node{Scope: scope, NodeID: fixtureID(t, "5"), Kind: "identity_role"}
	return CompleteSnapshot{
		Scope: scope, IntegrationID: fixtureID(t, "6"), Source: "aws", SnapshotID: fixtureID(t, suffix), Generation: generation,
		InputDigest: sha256.Sum256([]byte("graph-input-" + suffix)),
		Projection:  Projection{Nodes: []Node{nodeB, nodeA}, Edges: []Edge{{Scope: scope, EdgeID: fixtureID(t, "a"), Kind: "contains_identity", SourceID: nodeA.NodeID, TargetID: nodeB.NodeID}}},
	}
}

func durableSnapshotAcknowledgement(input DriverSnapshotProjection, replayed bool, removedNodes, removedEdges int) DriverSnapshotReplaced {
	return DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: input.Snapshot, NodeIDs: driverSnapshotNodeIDs(input.Nodes), EdgeIDs: driverSnapshotEdgeIDs(input.Edges), Replayed: replayed, RemovedNodes: removedNodes, RemovedEdges: removedEdges, Outcome: DriverSnapshotDurable}
}

func noMutationSnapshotAcknowledgement(input DriverSnapshotProjection, stable error) DriverSnapshotReplaced {
	acknowledgement := DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, Outcome: DriverSnapshotNoMutation}
	switch stable {
	case ErrSnapshotStale:
		acknowledgement.ActiveSnapshot = input.Snapshot
		acknowledgement.ActiveSnapshot.Generation++
	case ErrSnapshotDrift:
		acknowledgement.ActiveSnapshot = input.Snapshot
		acknowledgement.ActiveSnapshot.ContentDigest[0] ^= 0xff
	}
	return acknowledgement
}

func snapshotGenerationKey(snapshot DriverSnapshot) string {
	return snapshot.OrganizationID + "\x00" + snapshot.WorkspaceID + "\x00" + snapshot.EnvironmentID + "\x00" + snapshot.IntegrationID + "\x00" + snapshot.Source
}

func snapshotGenerationKeyFromComplete(snapshot CompleteSnapshot) string {
	return snapshot.Scope.OrganizationID().String() + "\x00" + snapshot.Scope.WorkspaceID().String() + "\x00" + snapshot.Scope.EnvironmentID().String() + "\x00" + snapshot.IntegrationID.String() + "\x00" + snapshot.Source
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
