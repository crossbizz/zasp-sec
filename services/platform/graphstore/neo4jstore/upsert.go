package neo4jstore

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const (
	maximumUpsertNodes = 1_000
	maximumUpsertEdges = 2_000

	upsertNodesQuery    = "UNWIND $nodes AS input MERGE (node:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, node_id: input.node_id}) ON CREATE SET node.kind = input.kind, node.schema_version = $schema_version WITH node, input WHERE size(keys(node)) = 6 AND all(key IN keys(node) WHERE key IN ['organization_id', 'workspace_id', 'environment_id', 'node_id', 'kind', 'schema_version']) AND node.kind = input.kind AND node.schema_version = $schema_version RETURN count(node) AS matched"
	upsertEdgesQuery    = "UNWIND $edges AS input MATCH (source:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, node_id: input.source_id}) MATCH (target:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, node_id: input.target_id}) MERGE (source)-[edge:ZASP_GRAPH_EDGE {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, edge_id: input.edge_id}]->(target) ON CREATE SET edge.kind = input.kind, edge.schema_version = $schema_version WITH edge, input WHERE size(keys(edge)) = 6 AND all(key IN keys(edge) WHERE key IN ['organization_id', 'workspace_id', 'environment_id', 'edge_id', 'kind', 'schema_version']) AND edge.kind = input.kind AND edge.schema_version = $schema_version RETURN count(edge) AS matched"
	readbackUpsertQuery = "MATCH (node:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id}) WHERE node.node_id IN [input IN $nodes | input.node_id] WITH node ORDER BY node.node_id WITH collect({organization_id: node.organization_id, workspace_id: node.workspace_id, environment_id: node.environment_id, node_id: node.node_id, kind: node.kind, schema_version: node.schema_version}) AS nodes OPTIONAL MATCH (source:ZaspGraphNode)-[edge:ZASP_GRAPH_EDGE]->(target:ZaspGraphNode) WHERE edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.edge_id IN [input IN $edges | input.edge_id] WITH nodes, edge, source, target ORDER BY edge.edge_id RETURN nodes, collect(CASE WHEN edge IS NULL THEN null ELSE {organization_id: edge.organization_id, workspace_id: edge.workspace_id, environment_id: edge.environment_id, edge_id: edge.edge_id, kind: edge.kind, source_id: source.node_id, target_id: target.node_id, schema_version: edge.schema_version} END) AS edges"
)

var adapterKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func (adapter *Adapter) Upsert(ctx context.Context, projection graphstore.DriverProjection) (graphstore.DriverUpserted, error) {
	if adapter == nil || ctx == nil || nilInterface(adapter.provider) || adapter.database != databaseName || ctx.Err() != nil {
		return graphstore.DriverUpserted{}, ErrUpsert
	}
	parameters, expected, ok := canonicalUpsert(projection)
	if !ok {
		return graphstore.DriverUpserted{}, ErrUpsert
	}
	err := executeTransaction(ctx, adapter.provider, sessionConfig{Database: adapter.database, Access: accessWrite}, ErrUpsert, func(transaction graphTransaction) error {
		if !runMatched(ctx, transaction, upsertNodesQuery, parameters, int64(len(expected.NodeIDs))) {
			return ErrUpsert
		}
		if !runMatched(ctx, transaction, upsertEdgesQuery, parameters, int64(len(expected.EdgeIDs))) {
			return ErrUpsert
		}
		result, runErr := transaction.Run(ctx, readbackUpsertQuery, parameters)
		if runErr != nil || nilInterface(result) {
			return ErrUpsert
		}
		readback, readOK := readUpsertProjection(ctx, result)
		if !readOK || !exactDriverProjection(readback, projection) {
			return ErrUpsert
		}
		return nil
	})
	if err != nil {
		return graphstore.DriverUpserted{}, ErrUpsert
	}
	return graphstore.DriverUpserted{
		NodeIDs: append([]string(nil), expected.NodeIDs...),
		EdgeIDs: append([]string(nil), expected.EdgeIDs...),
	}, nil
}

func canonicalUpsert(projection graphstore.DriverProjection) (map[string]any, graphstore.DriverUpserted, bool) {
	if len(projection.Nodes) == 0 || len(projection.Nodes) > maximumUpsertNodes || len(projection.Edges) > maximumUpsertEdges {
		return nil, graphstore.DriverUpserted{}, false
	}
	first := projection.Nodes[0]
	if !validProductID(first.OrganizationID) || !validProductID(first.WorkspaceID) || !validProductID(first.EnvironmentID) {
		return nil, graphstore.DriverUpserted{}, false
	}
	nodes := make([]any, len(projection.Nodes))
	nodeIDs := make([]string, len(projection.Nodes))
	nodeSet := make(map[string]struct{}, len(projection.Nodes))
	previous := ""
	for index, node := range projection.Nodes {
		if !sameScope(first, node.OrganizationID, node.WorkspaceID, node.EnvironmentID) || !validProductID(node.NodeID) ||
			!validAdapterKind(node.Kind) || (previous != "" && previous >= node.NodeID) {
			return nil, graphstore.DriverUpserted{}, false
		}
		previous = node.NodeID
		nodeIDs[index] = node.NodeID
		nodeSet[node.NodeID] = struct{}{}
		nodes[index] = map[string]any{"node_id": node.NodeID, "kind": node.Kind}
	}

	edges := make([]any, len(projection.Edges))
	edgeIDs := make([]string, len(projection.Edges))
	semantic := make(map[string]struct{}, len(projection.Edges))
	previous = ""
	for index, edge := range projection.Edges {
		if !sameScope(first, edge.OrganizationID, edge.WorkspaceID, edge.EnvironmentID) || !validProductID(edge.EdgeID) ||
			!validProductID(edge.SourceID) || !validProductID(edge.TargetID) || !validAdapterKind(edge.Kind) ||
			edge.SourceID == edge.TargetID || (previous != "" && previous >= edge.EdgeID) {
			return nil, graphstore.DriverUpserted{}, false
		}
		if _, present := nodeSet[edge.SourceID]; !present {
			return nil, graphstore.DriverUpserted{}, false
		}
		if _, present := nodeSet[edge.TargetID]; !present {
			return nil, graphstore.DriverUpserted{}, false
		}
		semanticKey := edge.Kind + "\x00" + edge.SourceID + "\x00" + edge.TargetID
		if _, duplicate := semantic[semanticKey]; duplicate {
			return nil, graphstore.DriverUpserted{}, false
		}
		semantic[semanticKey] = struct{}{}
		previous = edge.EdgeID
		edgeIDs[index] = edge.EdgeID
		edges[index] = map[string]any{
			"edge_id": edge.EdgeID, "kind": edge.Kind, "source_id": edge.SourceID, "target_id": edge.TargetID,
		}
	}
	return map[string]any{
		"organization_id": first.OrganizationID,
		"workspace_id":    first.WorkspaceID,
		"environment_id":  first.EnvironmentID,
		"nodes":           nodes,
		"edges":           edges,
		"schema_version":  schemaVersion,
	}, graphstore.DriverUpserted{NodeIDs: nodeIDs, EdgeIDs: edgeIDs}, true
}

func runMatched(ctx context.Context, transaction graphTransaction, query string, parameters map[string]any, expected int64) bool {
	result, err := transaction.Run(ctx, query, parameters)
	if err != nil || nilInterface(result) {
		return false
	}
	record, ok := singleRecord(ctx, result, []string{"matched"})
	if !ok || len(record.Values) != 1 {
		return false
	}
	matched, ok := record.Values[0].(int64)
	return ok && matched == expected
}

func readUpsertProjection(ctx context.Context, result graphResult) (graphstore.DriverProjection, bool) {
	record, ok := singleRecord(ctx, result, []string{"nodes", "edges"})
	if !ok || len(record.Values) != 2 {
		return graphstore.DriverProjection{}, false
	}
	nodes, ok := parseNodeMaps(record.Values[0])
	if !ok {
		return graphstore.DriverProjection{}, false
	}
	edges, ok := parseEdgeMaps(record.Values[1])
	if !ok {
		return graphstore.DriverProjection{}, false
	}
	return graphstore.DriverProjection{Nodes: nodes, Edges: edges}, true
}

func singleRecord(ctx context.Context, result graphResult, expectedKeys []string) (graphRecord, bool) {
	keys, err := result.Keys()
	if err != nil || !slices.Equal(keys, expectedKeys) || !result.Next(ctx) {
		return graphRecord{}, false
	}
	record := result.Record()
	if !slices.Equal(record.Keys, expectedKeys) || result.Next(ctx) || result.Err() != nil || result.Consume(ctx) != nil {
		return graphRecord{}, false
	}
	return graphRecord{Keys: append([]string(nil), record.Keys...), Values: append([]any(nil), record.Values...)}, true
}

func parseNodeMaps(value any) ([]graphstore.DriverNode, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	nodes := make([]graphstore.DriverNode, len(items))
	for index, item := range items {
		properties, ok := item.(map[string]any)
		if !ok || !exactMapKeys(properties, []string{"environment_id", "kind", "node_id", "organization_id", "schema_version", "workspace_id"}) {
			return nil, false
		}
		organization, organizationOK := properties["organization_id"].(string)
		workspace, workspaceOK := properties["workspace_id"].(string)
		environment, environmentOK := properties["environment_id"].(string)
		nodeID, nodeOK := properties["node_id"].(string)
		kind, kindOK := properties["kind"].(string)
		version, versionOK := properties["schema_version"].(int64)
		if !organizationOK || !workspaceOK || !environmentOK || !nodeOK || !kindOK || !versionOK || version != schemaVersion {
			return nil, false
		}
		nodes[index] = graphstore.DriverNode{OrganizationID: organization, WorkspaceID: workspace, EnvironmentID: environment, NodeID: nodeID, Kind: kind}
	}
	return nodes, true
}

func parseEdgeMaps(value any) ([]graphstore.DriverEdge, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	edges := make([]graphstore.DriverEdge, len(items))
	for index, item := range items {
		properties, ok := item.(map[string]any)
		if !ok || !exactMapKeys(properties, []string{"edge_id", "environment_id", "kind", "organization_id", "schema_version", "source_id", "target_id", "workspace_id"}) {
			return nil, false
		}
		organization, organizationOK := properties["organization_id"].(string)
		workspace, workspaceOK := properties["workspace_id"].(string)
		environment, environmentOK := properties["environment_id"].(string)
		edgeID, edgeOK := properties["edge_id"].(string)
		kind, kindOK := properties["kind"].(string)
		sourceID, sourceOK := properties["source_id"].(string)
		targetID, targetOK := properties["target_id"].(string)
		version, versionOK := properties["schema_version"].(int64)
		if !organizationOK || !workspaceOK || !environmentOK || !edgeOK || !kindOK || !sourceOK || !targetOK || !versionOK || version != schemaVersion {
			return nil, false
		}
		edges[index] = graphstore.DriverEdge{
			OrganizationID: organization, WorkspaceID: workspace, EnvironmentID: environment,
			EdgeID: edgeID, Kind: kind, SourceID: sourceID, TargetID: targetID,
		}
	}
	return edges, true
}

func exactDriverProjection(left, right graphstore.DriverProjection) bool {
	return slices.Equal(left.Nodes, right.Nodes) && slices.Equal(left.Edges, right.Edges)
}

func exactMapKeys(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, present := value[key]; !present {
			return false
		}
	}
	return true
}

func validProductID(value string) bool {
	id, err := domain.ParseProductID(value)
	return err == nil && id.String() == value
}

func validAdapterKind(value string) bool {
	if !adapterKindPattern.MatchString(value) {
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

func sameScope(first graphstore.DriverNode, organization, workspace, environment string) bool {
	return organization == first.OrganizationID && workspace == first.WorkspaceID && environment == first.EnvironmentID
}
