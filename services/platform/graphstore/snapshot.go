package graphstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"regexp"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const snapshotContentDigestDomain = "zasp.graph.complete-snapshot.v1"

var snapshotSourcePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

var (
	ErrSnapshotInput          = errors.New("graph snapshot input rejected")
	ErrSnapshotCanceled       = errors.New("graph snapshot operation canceled")
	ErrSnapshotRetryable      = errors.New("graph snapshot operation retryable")
	ErrSnapshotUnknownOutcome = errors.New("graph snapshot operation outcome unknown")
	ErrSnapshotStale          = errors.New("graph snapshot generation stale")
	ErrSnapshotDrift          = errors.New("graph snapshot immutable projection drift")
	ErrSnapshotDenied         = errors.New("graph snapshot authority denied")
	ErrSnapshotUnavailable    = errors.New("graph snapshot unavailable")
)

// CompleteSnapshot is a complete replacement for one integration's graph
// projection. An empty Projection removes the previously active projection.
type CompleteSnapshot struct {
	Scope         domain.Scope
	IntegrationID domain.ProductID
	Source        string
	SnapshotID    domain.ProductID
	Generation    int64
	InputDigest   [sha256.Size]byte
	Projection    Projection
}

type SnapshotApplyResult struct {
	SnapshotID    domain.ProductID
	Source        string
	Generation    int64
	InputDigest   [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	NodeIDs       []string
	EdgeIDs       []string
	Replayed      bool
	RemovedNodes  int
	RemovedEdges  int
}

type DriverSnapshot struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	IntegrationID  string
	Source         string
	SnapshotID     string
	Generation     int64
	InputDigest    [sha256.Size]byte
	ContentDigest  [sha256.Size]byte
}

type DriverSnapshotNode struct {
	Snapshot DriverSnapshot
	NodeID   string
	Kind     string
}

type DriverSnapshotEdge struct {
	Snapshot DriverSnapshot
	EdgeID   string
	Kind     string
	SourceID string
	TargetID string
}

type DriverSnapshotProjection struct {
	Snapshot DriverSnapshot
	Nodes    []DriverSnapshotNode
	Edges    []DriverSnapshotEdge
}

type DriverSnapshotReplaced struct {
	CandidateSnapshot DriverSnapshot
	ActiveSnapshot    DriverSnapshot
	NodeIDs           []string
	EdgeIDs           []string
	Replayed          bool
	RemovedNodes      int
	RemovedEdges      int
	Outcome           DriverSnapshotOutcome
}

type DriverSnapshotOutcome uint8

const (
	// DriverSnapshotNoMutation is a durable acknowledgement that the candidate
	// did not mutate projection state. It is required for terminal driver errors
	// other than an explicitly unknown outcome.
	DriverSnapshotNoMutation DriverSnapshotOutcome = iota + 1
	// DriverSnapshotDurable acknowledges that the exact complete projection and
	// marker are durable and visible to an exact replay.
	DriverSnapshotDurable
)

// SnapshotDriver is optional so legacy graph drivers and the Upsert/Read
// contract remain source-compatible. ReplaceSnapshot must atomically serialize
// on (organization, workspace, environment, integration, source), replace the
// complete projection, activate its exact immutable binding, and remove stale
// nodes and edges before returning DriverSnapshotDurable. Exact replay must
// return the same IDs with Replayed set. Older generations and same-generation
// drift must perform no candidate mutation and return DriverSnapshotNoMutation
// with ErrSnapshotStale or ErrSnapshotDrift. A cancellation, panic, lost
// response, failed rollback, or failed commit after mutation may have started
// must return ErrSnapshotUnknownOutcome; retryable/canceled/denied/unavailable
// errors are terminal only with an exact DriverSnapshotNoMutation candidate
// acknowledgement. Errors must never contain provider, query, auth, or secret
// detail.
type SnapshotDriver interface {
	ReplaceSnapshot(context.Context, DriverSnapshotProjection) (DriverSnapshotReplaced, error)
}

func (store *Store) ApplySnapshot(ctx context.Context, snapshot CompleteSnapshot) (SnapshotApplyResult, error) {
	if !store.usable() || ctx == nil {
		return SnapshotApplyResult{}, ErrSnapshotInput
	}
	if ctx.Err() != nil {
		return SnapshotApplyResult{}, ErrSnapshotCanceled
	}
	driver, ok := store.driver.(SnapshotDriver)
	if !ok || nilInterface(driver) {
		return SnapshotApplyResult{}, ErrSnapshotUnavailable
	}
	projection, nodeIDs, edgeIDs, ok := buildDriverSnapshotProjection(snapshot, store.config)
	if !ok {
		return SnapshotApplyResult{}, ErrSnapshotInput
	}

	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	acknowledged, err := replaceSnapshotDriver(driver, operationCtx, cloneDriverSnapshotProjection(projection))
	if operationCtx.Err() != nil {
		if err != nil {
			stable := sanitizeSnapshotDriverError(err)
			if !errors.Is(stable, ErrSnapshotUnknownOutcome) && validNoMutationAcknowledgement(acknowledged, projection, stable) {
				return SnapshotApplyResult{}, stable
			}
		}
		return SnapshotApplyResult{}, ErrSnapshotUnknownOutcome
	}
	if err != nil {
		stable := sanitizeSnapshotDriverError(err)
		if errors.Is(stable, ErrSnapshotUnknownOutcome) {
			return SnapshotApplyResult{}, ErrSnapshotUnknownOutcome
		}
		if !validNoMutationAcknowledgement(acknowledged, projection, stable) {
			return SnapshotApplyResult{}, ErrSnapshotUnknownOutcome
		}
		return SnapshotApplyResult{}, stable
	}
	if acknowledged.Outcome != DriverSnapshotDurable || acknowledged.CandidateSnapshot != projection.Snapshot ||
		acknowledged.ActiveSnapshot != projection.Snapshot ||
		!exactStrings(acknowledged.NodeIDs, nodeIDs) || !exactStrings(acknowledged.EdgeIDs, edgeIDs) ||
		acknowledged.RemovedNodes < 0 || acknowledged.RemovedEdges < 0 {
		return SnapshotApplyResult{}, ErrSnapshotDrift
	}
	return SnapshotApplyResult{
		SnapshotID: snapshot.SnapshotID, Source: snapshot.Source, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest,
		ContentDigest: projection.Snapshot.ContentDigest, NodeIDs: append([]string(nil), nodeIDs...),
		EdgeIDs: append([]string(nil), edgeIDs...), Replayed: acknowledged.Replayed,
		RemovedNodes: acknowledged.RemovedNodes, RemovedEdges: acknowledged.RemovedEdges,
	}, nil
}

func buildDriverSnapshotProjection(snapshot CompleteSnapshot, config Config) (DriverSnapshotProjection, []string, []string, bool) {
	if snapshot.Scope.Validate() != nil || !validSnapshotProductID(snapshot.IntegrationID) || !snapshotSourcePattern.MatchString(snapshot.Source) ||
		!validSnapshotProductID(snapshot.SnapshotID) || snapshot.Generation < 1 ||
		snapshot.InputDigest == [sha256.Size]byte{} || len(snapshot.Projection.Nodes) > config.MaximumNodes ||
		len(snapshot.Projection.Edges) > config.MaximumEdges {
		return DriverSnapshotProjection{}, nil, nil, false
	}

	nodes := append([]Node(nil), snapshot.Projection.Nodes...)
	edges := append([]Edge(nil), snapshot.Projection.Edges...)
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].NodeID.String() < nodes[right].NodeID.String() })
	sort.Slice(edges, func(left, right int) bool { return edges[left].EdgeID.String() < edges[right].EdgeID.String() })
	binding := DriverSnapshot{
		OrganizationID: snapshot.Scope.OrganizationID().String(), WorkspaceID: snapshot.Scope.WorkspaceID().String(),
		EnvironmentID: snapshot.Scope.EnvironmentID().String(), IntegrationID: snapshot.IntegrationID.String(), Source: snapshot.Source,
		SnapshotID: snapshot.SnapshotID.String(), Generation: snapshot.Generation, InputDigest: snapshot.InputDigest,
	}

	driverNodes := make([]DriverSnapshotNode, len(nodes))
	nodeIDs := make([]string, len(nodes))
	nodeSet := make(map[domain.ProductID]struct{}, len(nodes))
	for index, node := range nodes {
		if node.Scope.Validate() != nil || node.Scope != snapshot.Scope || !validSnapshotProductID(node.NodeID) || !validKind(node.Kind) {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		if _, duplicate := nodeSet[node.NodeID]; duplicate {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		nodeSet[node.NodeID] = struct{}{}
		nodeIDs[index] = node.NodeID.String()
		driverNodes[index] = DriverSnapshotNode{NodeID: node.NodeID.String(), Kind: node.Kind}
	}

	driverEdges := make([]DriverSnapshotEdge, len(edges))
	edgeIDs := make([]string, len(edges))
	edgeSet := make(map[domain.ProductID]struct{}, len(edges))
	semanticEdges := make(map[string]struct{}, len(edges))
	for index, edge := range edges {
		if edge.Scope.Validate() != nil || edge.Scope != snapshot.Scope || !validSnapshotProductID(edge.EdgeID) ||
			!validKind(edge.Kind) || !validSnapshotProductID(edge.SourceID) || !validSnapshotProductID(edge.TargetID) ||
			edge.SourceID == edge.TargetID {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		if _, exists := nodeSet[edge.SourceID]; !exists {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		if _, exists := nodeSet[edge.TargetID]; !exists {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		if _, duplicate := edgeSet[edge.EdgeID]; duplicate {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		semantic := edge.Kind + "\x00" + edge.SourceID.String() + "\x00" + edge.TargetID.String()
		if _, duplicate := semanticEdges[semantic]; duplicate {
			return DriverSnapshotProjection{}, nil, nil, false
		}
		edgeSet[edge.EdgeID] = struct{}{}
		semanticEdges[semantic] = struct{}{}
		edgeIDs[index] = edge.EdgeID.String()
		driverEdges[index] = DriverSnapshotEdge{EdgeID: edge.EdgeID.String(), Kind: edge.Kind, SourceID: edge.SourceID.String(), TargetID: edge.TargetID.String()}
	}

	binding.ContentDigest = graphSnapshotContentDigest(binding, driverNodes, driverEdges)
	for index := range driverNodes {
		driverNodes[index].Snapshot = binding
	}
	for index := range driverEdges {
		driverEdges[index].Snapshot = binding
	}
	return DriverSnapshotProjection{Snapshot: binding, Nodes: driverNodes, Edges: driverEdges}, nodeIDs, edgeIDs, true
}

func graphSnapshotContentDigest(snapshot DriverSnapshot, nodes []DriverSnapshotNode, edges []DriverSnapshotEdge) [sha256.Size]byte {
	hasher := sha256.New()
	writeGraphDigestString(hasher, snapshotContentDigestDomain)
	writeGraphDigestString(hasher, snapshot.OrganizationID)
	writeGraphDigestString(hasher, snapshot.WorkspaceID)
	writeGraphDigestString(hasher, snapshot.EnvironmentID)
	writeGraphDigestString(hasher, snapshot.IntegrationID)
	writeGraphDigestString(hasher, snapshot.Source)
	writeGraphDigestString(hasher, snapshot.SnapshotID)
	writeGraphDigestInt64(hasher, snapshot.Generation)
	writeGraphDigestBytes(hasher, snapshot.InputDigest[:])
	writeGraphDigestInt64(hasher, int64(len(nodes)))
	for _, node := range nodes {
		writeGraphDigestString(hasher, node.NodeID)
		writeGraphDigestString(hasher, node.Kind)
	}
	writeGraphDigestInt64(hasher, int64(len(edges)))
	for _, edge := range edges {
		writeGraphDigestString(hasher, edge.EdgeID)
		writeGraphDigestString(hasher, edge.Kind)
		writeGraphDigestString(hasher, edge.SourceID)
		writeGraphDigestString(hasher, edge.TargetID)
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func validSnapshotProductID(value domain.ProductID) bool {
	if value.IsZero() {
		return false
	}
	parsed, err := domain.ParseProductID(value.String())
	return err == nil && parsed == value
}

func writeGraphDigestString(hasher hash.Hash, value string) {
	writeGraphDigestBytes(hasher, []byte(value))
}

func writeGraphDigestBytes(hasher hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write(value)
}

func writeGraphDigestInt64(hasher hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = hasher.Write(encoded[:])
}

func cloneDriverSnapshotProjection(value DriverSnapshotProjection) DriverSnapshotProjection {
	return DriverSnapshotProjection{Snapshot: value.Snapshot, Nodes: append([]DriverSnapshotNode(nil), value.Nodes...), Edges: append([]DriverSnapshotEdge(nil), value.Edges...)}
}

func sanitizeSnapshotDriverError(err error) error {
	if errors.Is(err, ErrSnapshotUnknownOutcome) {
		return ErrSnapshotUnknownOutcome
	}
	var matched error
	for _, stable := range []error{ErrSnapshotCanceled, ErrSnapshotRetryable, ErrSnapshotStale, ErrSnapshotDrift, ErrSnapshotDenied, ErrSnapshotUnavailable} {
		if errors.Is(err, stable) {
			if matched != nil {
				return ErrSnapshotUnknownOutcome
			}
			matched = stable
		}
	}
	if matched != nil {
		return matched
	}
	return ErrSnapshotUnavailable
}

func validNoMutationAcknowledgement(acknowledged DriverSnapshotReplaced, projection DriverSnapshotProjection, stable error) bool {
	if acknowledged.Outcome != DriverSnapshotNoMutation || acknowledged.CandidateSnapshot != projection.Snapshot ||
		acknowledged.Replayed || acknowledged.RemovedNodes != 0 || acknowledged.RemovedEdges != 0 {
		return false
	}
	if errors.Is(stable, ErrSnapshotStale) {
		return sameSnapshotGenerationKey(acknowledged.ActiveSnapshot, projection.Snapshot) &&
			acknowledged.ActiveSnapshot.Generation > projection.Snapshot.Generation && validDriverSnapshotBinding(acknowledged.ActiveSnapshot)
	}
	if errors.Is(stable, ErrSnapshotDrift) {
		return sameSnapshotGenerationKey(acknowledged.ActiveSnapshot, projection.Snapshot) &&
			acknowledged.ActiveSnapshot.Generation == projection.Snapshot.Generation && validDriverSnapshotBinding(acknowledged.ActiveSnapshot)
	}
	return acknowledged.ActiveSnapshot == (DriverSnapshot{}) && len(acknowledged.NodeIDs) == 0 && len(acknowledged.EdgeIDs) == 0
}

func sameSnapshotGenerationKey(left, right DriverSnapshot) bool {
	return left.OrganizationID == right.OrganizationID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.IntegrationID == right.IntegrationID && left.Source == right.Source
}

func validDriverSnapshotBinding(value DriverSnapshot) bool {
	_, organizationErr := domain.ParseProductID(value.OrganizationID)
	_, workspaceErr := domain.ParseProductID(value.WorkspaceID)
	_, environmentErr := domain.ParseProductID(value.EnvironmentID)
	_, integrationErr := domain.ParseProductID(value.IntegrationID)
	_, snapshotErr := domain.ParseProductID(value.SnapshotID)
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && integrationErr == nil && snapshotErr == nil &&
		snapshotSourcePattern.MatchString(value.Source) && value.Generation >= 1 && value.InputDigest != [sha256.Size]byte{} && value.ContentDigest != [sha256.Size]byte{}
}

func replaceSnapshotDriver(driver SnapshotDriver, ctx context.Context, input DriverSnapshotProjection) (result DriverSnapshotReplaced, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverSnapshotReplaced{}
			resultErr = ErrSnapshotUnknownOutcome
		}
	}()
	return driver.ReplaceSnapshot(ctx, input)
}
