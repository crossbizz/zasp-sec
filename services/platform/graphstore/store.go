package graphstore

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumNodeCount        = 1_000
	maximumEdgeCount        = 2_000
	maximumTraversalDepth   = 8
)

var (
	ErrConfiguration = errors.New("graph store configuration rejected")
	ErrProjection    = errors.New("graph projection rejected")
	ErrReadRequest   = errors.New("graph read request rejected")
	ErrUpsert        = errors.New("graph upsert failed")
	ErrRead          = errors.New("graph read failed")
	kindPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

type Config struct {
	OperationTimeout time.Duration
	MaximumNodes     int
	MaximumEdges     int
	MaximumDepth     int
}

type Node struct {
	Scope  domain.Scope
	NodeID domain.ProductID
	Kind   string
}

type Edge struct {
	Scope    domain.Scope
	EdgeID   domain.ProductID
	Kind     string
	SourceID domain.ProductID
	TargetID domain.ProductID
}

type Projection struct {
	Nodes []Node
	Edges []Edge
}

type Direction uint8

const (
	DirectionOutgoing Direction = iota + 1
	DirectionIncoming
	DirectionBoth
)

type ReadRequest struct {
	RootID       domain.ProductID
	Direction    Direction
	MaximumDepth int
	MaximumNodes int
	MaximumEdges int
}

type DriverNode struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	NodeID         string
	Kind           string
}

type DriverEdge struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	EdgeID         string
	Kind           string
	SourceID       string
	TargetID       string
}

type DriverProjection struct {
	Nodes []DriverNode
	Edges []DriverEdge
}

type DriverUpserted struct {
	NodeIDs []string
	EdgeIDs []string
}

type DriverQuery struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	RootID         string
	Direction      string
	MaximumDepth   int
	MaximumNodes   int
	MaximumEdges   int
	NodeSort       string
	EdgeSort       string
}

type Driver interface {
	Upsert(context.Context, DriverProjection) (DriverUpserted, error)
	Read(context.Context, DriverQuery) (DriverProjection, error)
}

type GraphStore interface {
	Upsert(context.Context, domain.Scope, Projection) error
	Read(context.Context, domain.Scope, ReadRequest) (Projection, error)
}

type Store struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Store, error) {
	if nilInterface(driver) || config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout ||
		config.MaximumNodes <= 0 || config.MaximumNodes > maximumNodeCount ||
		config.MaximumEdges <= 0 || config.MaximumEdges > maximumEdgeCount ||
		config.MaximumDepth <= 0 || config.MaximumDepth > maximumTraversalDepth {
		return nil, ErrConfiguration
	}
	return &Store{driver: driver, config: config}, nil
}

func (store *Store) Upsert(ctx context.Context, scope domain.Scope, projection Projection) error {
	if !store.usable() || ctx == nil {
		return ErrUpsert
	}
	driverProjection, nodeIDs, edgeIDs, ok := buildDriverProjection(scope, projection, store.config)
	if !ok {
		return ErrProjection
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrUpsert
	}
	acknowledged, err := upsertDriver(store.driver, operationCtx, cloneDriverProjection(driverProjection))
	if err != nil || operationCtx.Err() != nil || !exactStrings(acknowledged.NodeIDs, nodeIDs) || !exactStrings(acknowledged.EdgeIDs, edgeIDs) {
		return ErrUpsert
	}
	return nil
}

func (store *Store) Read(ctx context.Context, scope domain.Scope, request ReadRequest) (Projection, error) {
	if !store.usable() || ctx == nil {
		return Projection{}, ErrRead
	}
	query, ok := buildDriverQuery(scope, request, store.config)
	if !ok {
		return Projection{}, ErrReadRequest
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return Projection{}, ErrRead
	}
	returned, err := readDriver(store.driver, operationCtx, query)
	if err != nil || operationCtx.Err() != nil {
		return Projection{}, ErrRead
	}
	projection, ok := productProjection(scope, request, returned)
	if !ok {
		return Projection{}, ErrRead
	}
	return projection, nil
}

func (store *Store) usable() bool {
	return store != nil && !nilInterface(store.driver)
}

func buildDriverProjection(scope domain.Scope, projection Projection, config Config) (DriverProjection, []string, []string, bool) {
	if scope.Validate() != nil || len(projection.Nodes) == 0 || len(projection.Nodes) > config.MaximumNodes ||
		len(projection.Edges) > config.MaximumEdges {
		return DriverProjection{}, nil, nil, false
	}
	nodes := append([]Node(nil), projection.Nodes...)
	edges := append([]Edge(nil), projection.Edges...)
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].NodeID.String() < nodes[right].NodeID.String() })
	sort.Slice(edges, func(left, right int) bool { return edges[left].EdgeID.String() < edges[right].EdgeID.String() })

	driverNodes := make([]DriverNode, len(nodes))
	nodeIDs := make([]string, len(nodes))
	nodeSet := make(map[domain.ProductID]struct{}, len(nodes))
	for index, node := range nodes {
		if node.Scope.Validate() != nil || node.Scope != scope || node.NodeID.String() == "" || !validKind(node.Kind) {
			return DriverProjection{}, nil, nil, false
		}
		if _, duplicate := nodeSet[node.NodeID]; duplicate {
			return DriverProjection{}, nil, nil, false
		}
		nodeSet[node.NodeID] = struct{}{}
		nodeIDs[index] = node.NodeID.String()
		driverNodes[index] = DriverNode{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(),
			EnvironmentID: scope.EnvironmentID().String(), NodeID: node.NodeID.String(), Kind: node.Kind,
		}
	}

	driverEdges := make([]DriverEdge, len(edges))
	edgeIDs := make([]string, len(edges))
	edgeSet := make(map[domain.ProductID]struct{}, len(edges))
	semanticEdges := make(map[string]struct{}, len(edges))
	for index, edge := range edges {
		if edge.Scope.Validate() != nil || edge.Scope != scope || edge.EdgeID.String() == "" || !validKind(edge.Kind) ||
			edge.SourceID.String() == "" || edge.TargetID.String() == "" || edge.SourceID == edge.TargetID {
			return DriverProjection{}, nil, nil, false
		}
		if _, exists := nodeSet[edge.SourceID]; !exists {
			return DriverProjection{}, nil, nil, false
		}
		if _, exists := nodeSet[edge.TargetID]; !exists {
			return DriverProjection{}, nil, nil, false
		}
		if _, duplicate := edgeSet[edge.EdgeID]; duplicate {
			return DriverProjection{}, nil, nil, false
		}
		semantic := edge.Kind + "\x00" + edge.SourceID.String() + "\x00" + edge.TargetID.String()
		if _, duplicate := semanticEdges[semantic]; duplicate {
			return DriverProjection{}, nil, nil, false
		}
		edgeSet[edge.EdgeID] = struct{}{}
		semanticEdges[semantic] = struct{}{}
		edgeIDs[index] = edge.EdgeID.String()
		driverEdges[index] = DriverEdge{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(),
			EnvironmentID: scope.EnvironmentID().String(), EdgeID: edge.EdgeID.String(), Kind: edge.Kind,
			SourceID: edge.SourceID.String(), TargetID: edge.TargetID.String(),
		}
	}
	return DriverProjection{Nodes: driverNodes, Edges: driverEdges}, nodeIDs, edgeIDs, true
}

func buildDriverQuery(scope domain.Scope, request ReadRequest, config Config) (DriverQuery, bool) {
	direction, ok := directionName(request.Direction)
	if scope.Validate() != nil || request.RootID.String() == "" || !ok || request.MaximumDepth < 0 ||
		request.MaximumDepth > config.MaximumDepth || request.MaximumNodes <= 0 ||
		request.MaximumNodes > config.MaximumNodes || request.MaximumEdges <= 0 ||
		request.MaximumEdges > config.MaximumEdges {
		return DriverQuery{}, false
	}
	return DriverQuery{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		RootID:         request.RootID.String(),
		Direction:      direction,
		MaximumDepth:   request.MaximumDepth,
		MaximumNodes:   request.MaximumNodes,
		MaximumEdges:   request.MaximumEdges,
		NodeSort:       "node_id",
		EdgeSort:       "edge_id",
	}, true
}

func productProjection(scope domain.Scope, request ReadRequest, returned DriverProjection) (Projection, bool) {
	if len(returned.Nodes) > request.MaximumNodes || len(returned.Edges) > request.MaximumEdges ||
		(len(returned.Nodes) == 0 && len(returned.Edges) != 0) {
		return Projection{}, false
	}
	if len(returned.Nodes) == 0 {
		return Projection{Nodes: []Node{}, Edges: []Edge{}}, true
	}

	nodes := make([]Node, len(returned.Nodes))
	nodeSet := make(map[domain.ProductID]struct{}, len(returned.Nodes))
	previousID := ""
	rootPresent := false
	for index, record := range returned.Nodes {
		if !exactScopeRecord(scope, record.OrganizationID, record.WorkspaceID, record.EnvironmentID) ||
			!validKind(record.Kind) || (previousID != "" && previousID >= record.NodeID) {
			return Projection{}, false
		}
		nodeID, err := domain.ParseProductID(record.NodeID)
		if err != nil {
			return Projection{}, false
		}
		if _, duplicate := nodeSet[nodeID]; duplicate {
			return Projection{}, false
		}
		nodeSet[nodeID] = struct{}{}
		rootPresent = rootPresent || nodeID == request.RootID
		previousID = record.NodeID
		nodes[index] = Node{Scope: scope, NodeID: nodeID, Kind: record.Kind}
	}
	if !rootPresent {
		return Projection{}, false
	}

	edges := make([]Edge, len(returned.Edges))
	semanticEdges := make(map[string]struct{}, len(returned.Edges))
	previousID = ""
	for index, record := range returned.Edges {
		if !exactScopeRecord(scope, record.OrganizationID, record.WorkspaceID, record.EnvironmentID) ||
			!validKind(record.Kind) || (previousID != "" && previousID >= record.EdgeID) {
			return Projection{}, false
		}
		edgeID, edgeErr := domain.ParseProductID(record.EdgeID)
		sourceID, sourceErr := domain.ParseProductID(record.SourceID)
		targetID, targetErr := domain.ParseProductID(record.TargetID)
		if edgeErr != nil || sourceErr != nil || targetErr != nil || sourceID == targetID {
			return Projection{}, false
		}
		if _, exists := nodeSet[sourceID]; !exists {
			return Projection{}, false
		}
		if _, exists := nodeSet[targetID]; !exists {
			return Projection{}, false
		}
		semantic := record.Kind + "\x00" + record.SourceID + "\x00" + record.TargetID
		if _, duplicate := semanticEdges[semantic]; duplicate {
			return Projection{}, false
		}
		semanticEdges[semantic] = struct{}{}
		previousID = record.EdgeID
		edges[index] = Edge{
			Scope: scope, EdgeID: edgeID, Kind: record.Kind, SourceID: sourceID, TargetID: targetID,
		}
	}
	if !allReachable(request, nodes, edges) {
		return Projection{}, false
	}
	return Projection{Nodes: nodes, Edges: edges}, true
}

func allReachable(request ReadRequest, nodes []Node, edges []Edge) bool {
	distance := map[domain.ProductID]int{request.RootID: 0}
	queue := []domain.ProductID{request.RootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		depth := distance[current]
		if depth >= request.MaximumDepth {
			continue
		}
		for _, edge := range edges {
			var neighbor domain.ProductID
			switch {
			case (request.Direction == DirectionOutgoing || request.Direction == DirectionBoth) && edge.SourceID == current:
				neighbor = edge.TargetID
			case (request.Direction == DirectionIncoming || request.Direction == DirectionBoth) && edge.TargetID == current:
				neighbor = edge.SourceID
			default:
				continue
			}
			if _, seen := distance[neighbor]; !seen {
				distance[neighbor] = depth + 1
				queue = append(queue, neighbor)
			}
		}
	}
	return len(distance) == len(nodes)
}

func validKind(value string) bool {
	if !kindPattern.MatchString(value) {
		return false
	}
	for _, part := range strings.Split(value, "_") {
		switch part {
		case "aws", "github", "cartography", "neo4j":
			return false
		}
	}
	return true
}

func directionName(direction Direction) (string, bool) {
	switch direction {
	case DirectionOutgoing:
		return "outgoing", true
	case DirectionIncoming:
		return "incoming", true
	case DirectionBoth:
		return "both", true
	default:
		return "", false
	}
}

func exactScopeRecord(scope domain.Scope, organizationID, workspaceID, environmentID string) bool {
	return organizationID == scope.OrganizationID().String() && workspaceID == scope.WorkspaceID().String() &&
		environmentID == scope.EnvironmentID().String()
}

func exactStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func cloneDriverProjection(value DriverProjection) DriverProjection {
	return DriverProjection{
		Nodes: append([]DriverNode(nil), value.Nodes...),
		Edges: append([]DriverEdge(nil), value.Edges...),
	}
}

func upsertDriver(driver Driver, ctx context.Context, projection DriverProjection) (result DriverUpserted, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverUpserted{}
			resultErr = ErrUpsert
		}
	}()
	return driver.Upsert(ctx, projection)
}

func readDriver(driver Driver, ctx context.Context, query DriverQuery) (result DriverProjection, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverProjection{}
			resultErr = ErrRead
		}
	}()
	return driver.Read(ctx, query)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
