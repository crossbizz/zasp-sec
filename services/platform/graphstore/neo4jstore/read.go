package neo4jstore

import (
	"context"
	"slices"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const (
	maximumReadDepth = 8
	maximumReadNodes = 1_000
	maximumReadEdges = 2_000

	readRootQuery     = "MATCH (node:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, node_id: $root_id}) WHERE node.schema_version = $schema_version RETURN {labels: labels(node), properties: properties(node)} AS node LIMIT 2"
	readOutgoingQuery = "UNWIND $frontier AS root_id MATCH (source:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, node_id: root_id})-[edge:ZASP_GRAPH_EDGE]->(target:ZaspGraphNode) WHERE source.schema_version = $schema_version AND edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.schema_version = $schema_version AND target.organization_id = $organization_id AND target.workspace_id = $workspace_id AND target.environment_id = $environment_id AND target.schema_version = $schema_version WITH target AS node, edge, source, target ORDER BY edge.edge_id, node.node_id LIMIT $remaining_edges RETURN {labels: labels(node), properties: properties(node)} AS node, {type: type(edge), properties: properties(edge), source_id: source.node_id, target_id: target.node_id} AS edge"
	readIncomingQuery = "UNWIND $frontier AS root_id MATCH (source:ZaspGraphNode)-[edge:ZASP_GRAPH_EDGE]->(target:ZaspGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, node_id: root_id}) WHERE target.schema_version = $schema_version AND edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.schema_version = $schema_version AND source.organization_id = $organization_id AND source.workspace_id = $workspace_id AND source.environment_id = $environment_id AND source.schema_version = $schema_version WITH source AS node, edge, source, target ORDER BY edge.edge_id, node.node_id LIMIT $remaining_edges RETURN {labels: labels(node), properties: properties(node)} AS node, {type: type(edge), properties: properties(edge), source_id: source.node_id, target_id: target.node_id} AS edge"
	readBothQuery     = "UNWIND $frontier AS root_id MATCH (source:ZaspGraphNode)-[edge:ZASP_GRAPH_EDGE]->(target:ZaspGraphNode) WHERE (source.node_id = root_id OR target.node_id = root_id) AND source.organization_id = $organization_id AND source.workspace_id = $workspace_id AND source.environment_id = $environment_id AND source.schema_version = $schema_version AND target.organization_id = $organization_id AND target.workspace_id = $workspace_id AND target.environment_id = $environment_id AND target.schema_version = $schema_version AND edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.schema_version = $schema_version WITH CASE WHEN source.node_id = root_id THEN target ELSE source END AS node, edge, source, target ORDER BY edge.edge_id, node.node_id LIMIT $remaining_edges RETURN {labels: labels(node), properties: properties(node)} AS node, {type: type(edge), properties: properties(edge), source_id: source.node_id, target_id: target.node_id} AS edge"
)

func (adapter *Adapter) Read(ctx context.Context, query graphstore.DriverQuery) (graphstore.DriverProjection, error) {
	if adapter == nil || ctx == nil || nilInterface(adapter.provider) || adapter.database != databaseName || ctx.Err() != nil || !validReadRequest(query) {
		return graphstore.DriverProjection{}, ErrRead
	}
	var projection graphstore.DriverProjection
	err := executeTransaction(ctx, adapter.provider, sessionConfig{Database: adapter.database, Access: accessRead}, ErrRead, func(transaction graphTransaction) error {
		root, found, ok := readRoot(ctx, transaction, query)
		if !ok {
			return ErrRead
		}
		if !found {
			projection = graphstore.DriverProjection{Nodes: []graphstore.DriverNode{}, Edges: []graphstore.DriverEdge{}}
			return nil
		}
		nodes := map[string]graphstore.DriverNode{root.NodeID: root}
		edges := make(map[string]graphstore.DriverEdge)
		frontier := []string{root.NodeID}
		for depth := 0; depth < query.MaximumDepth && len(frontier) != 0 && len(nodes) < query.MaximumNodes && len(edges) < query.MaximumEdges; depth++ {
			remainingNodes := query.MaximumNodes - len(nodes)
			remainingEdges := query.MaximumEdges - len(edges)
			rows, ok := readLevel(ctx, transaction, query, frontier, remainingNodes, remainingEdges)
			if !ok {
				return ErrRead
			}
			next := make(map[string]struct{})
			for _, row := range rows {
				knownNode, nodeSeen := nodes[row.node.NodeID]
				if nodeSeen && knownNode != row.node {
					return ErrRead
				}
				knownEdge, edgeSeen := edges[row.edge.EdgeID]
				if edgeSeen && knownEdge != row.edge {
					return ErrRead
				}
				if edgeSeen {
					continue
				}
				if !nodeSeen && len(nodes) >= query.MaximumNodes {
					break
				}
				if len(edges) >= query.MaximumEdges {
					break
				}
				if !nodeSeen {
					nodes[row.node.NodeID] = row.node
					next[row.node.NodeID] = struct{}{}
				}
				edges[row.edge.EdgeID] = row.edge
			}
			frontier = sortedSet(next)
		}
		projection = sortedProjection(nodes, edges)
		if !projectionEndpointsPresent(projection) {
			return ErrRead
		}
		return nil
	})
	if err != nil {
		return graphstore.DriverProjection{}, ErrRead
	}
	return graphstore.DriverProjection{
		Nodes: append([]graphstore.DriverNode{}, projection.Nodes...),
		Edges: append([]graphstore.DriverEdge{}, projection.Edges...),
	}, nil
}

func validReadRequest(query graphstore.DriverQuery) bool {
	return validProductID(query.OrganizationID) && validProductID(query.WorkspaceID) && validProductID(query.EnvironmentID) &&
		validProductID(query.RootID) && (query.Direction == "outgoing" || query.Direction == "incoming" || query.Direction == "both") &&
		query.MaximumDepth >= 0 && query.MaximumDepth <= maximumReadDepth && query.MaximumNodes > 0 && query.MaximumNodes <= maximumReadNodes &&
		query.MaximumEdges > 0 && query.MaximumEdges <= maximumReadEdges && query.NodeSort == "node_id" && query.EdgeSort == "edge_id"
}

func readRoot(ctx context.Context, transaction graphTransaction, query graphstore.DriverQuery) (graphstore.DriverNode, bool, bool) {
	result, err := transaction.Run(ctx, readRootQuery, map[string]any{
		"organization_id": query.OrganizationID, "workspace_id": query.WorkspaceID, "environment_id": query.EnvironmentID,
		"root_id": query.RootID, "schema_version": schemaVersion,
	})
	if err != nil || nilInterface(result) {
		return graphstore.DriverNode{}, false, false
	}
	records, ok := allRecords(ctx, result, []string{"node"}, 1)
	if !ok {
		return graphstore.DriverNode{}, false, false
	}
	if len(records) == 0 {
		return graphstore.DriverNode{}, false, true
	}
	if len(records[0].Values) != 1 {
		return graphstore.DriverNode{}, false, false
	}
	node, ok := parseProviderNode(records[0].Values[0], query)
	if !ok || node.NodeID != query.RootID {
		return graphstore.DriverNode{}, false, false
	}
	return node, true, true
}

type adjacency struct {
	node graphstore.DriverNode
	edge graphstore.DriverEdge
}

func readLevel(
	ctx context.Context,
	transaction graphTransaction,
	query graphstore.DriverQuery,
	frontier []string,
	remainingNodes int,
	remainingEdges int,
) ([]adjacency, bool) {
	statement := readOutgoingQuery
	if query.Direction == "incoming" {
		statement = readIncomingQuery
	} else if query.Direction == "both" {
		statement = readBothQuery
	}
	frontierValues := make([]any, len(frontier))
	frontierSet := make(map[string]struct{}, len(frontier))
	for index, value := range frontier {
		frontierValues[index] = value
		frontierSet[value] = struct{}{}
	}
	result, err := transaction.Run(ctx, statement, map[string]any{
		"organization_id": query.OrganizationID, "workspace_id": query.WorkspaceID, "environment_id": query.EnvironmentID,
		"frontier": frontierValues, "remaining_nodes": int64(remainingNodes), "remaining_edges": int64(remainingEdges),
		"schema_version": schemaVersion,
	})
	if err != nil || nilInterface(result) {
		return nil, false
	}
	records, ok := allRecords(ctx, result, []string{"node", "edge"}, remainingEdges)
	if !ok {
		return nil, false
	}
	rows := make([]adjacency, len(records))
	previous := ""
	for index, record := range records {
		if len(record.Values) != 2 {
			return nil, false
		}
		node, nodeOK := parseProviderNode(record.Values[0], query)
		edge, edgeOK := parseProviderEdge(record.Values[1], query)
		if !nodeOK || !edgeOK || !validDirection(query.Direction, frontierSet, node.NodeID, edge) {
			return nil, false
		}
		orderKey := edge.EdgeID + "\x00" + node.NodeID
		if previous > orderKey {
			return nil, false
		}
		previous = orderKey
		rows[index] = adjacency{node: node, edge: edge}
	}
	return rows, true
}

func allRecords(ctx context.Context, result graphResult, expectedKeys []string, maximum int) ([]graphRecord, bool) {
	keys, err := result.Keys()
	if err != nil || !slices.Equal(keys, expectedKeys) {
		return nil, false
	}
	records := make([]graphRecord, 0)
	for result.Next(ctx) {
		if len(records) >= maximum {
			return nil, false
		}
		record := result.Record()
		if !slices.Equal(record.Keys, expectedKeys) {
			return nil, false
		}
		records = append(records, graphRecord{Keys: append([]string(nil), record.Keys...), Values: append([]any(nil), record.Values...)})
	}
	if result.Err() != nil || result.Consume(ctx) != nil {
		return nil, false
	}
	return records, true
}

func parseProviderNode(value any, query graphstore.DriverQuery) (graphstore.DriverNode, bool) {
	providerNode, ok := value.(map[string]any)
	if !ok || !exactMapKeys(providerNode, []string{"labels", "properties"}) {
		return graphstore.DriverNode{}, false
	}
	labels, ok := exactStringList(providerNode["labels"])
	if !ok || !slices.Equal(labels, []string{nodeLabel}) {
		return graphstore.DriverNode{}, false
	}
	nodes, ok := parseNodeMaps([]any{providerNode["properties"]})
	if !ok || len(nodes) != 1 {
		return graphstore.DriverNode{}, false
	}
	node := nodes[0]
	if node.OrganizationID != query.OrganizationID || node.WorkspaceID != query.WorkspaceID || node.EnvironmentID != query.EnvironmentID ||
		!validProductID(node.NodeID) || !validAdapterKind(node.Kind) {
		return graphstore.DriverNode{}, false
	}
	return node, true
}

func parseProviderEdge(value any, query graphstore.DriverQuery) (graphstore.DriverEdge, bool) {
	providerEdge, ok := value.(map[string]any)
	if !ok || !exactMapKeys(providerEdge, []string{"properties", "source_id", "target_id", "type"}) || providerEdge["type"] != edgeType {
		return graphstore.DriverEdge{}, false
	}
	properties, ok := providerEdge["properties"].(map[string]any)
	if !ok || !exactMapKeys(properties, []string{"edge_id", "environment_id", "kind", "organization_id", "schema_version", "workspace_id"}) {
		return graphstore.DriverEdge{}, false
	}
	organization, organizationOK := properties["organization_id"].(string)
	workspace, workspaceOK := properties["workspace_id"].(string)
	environment, environmentOK := properties["environment_id"].(string)
	edgeID, edgeOK := properties["edge_id"].(string)
	kind, kindOK := properties["kind"].(string)
	version, versionOK := properties["schema_version"].(int64)
	sourceID, sourceOK := providerEdge["source_id"].(string)
	targetID, targetOK := providerEdge["target_id"].(string)
	if !organizationOK || !workspaceOK || !environmentOK || !edgeOK || !kindOK || !versionOK || !sourceOK || !targetOK ||
		organization != query.OrganizationID || workspace != query.WorkspaceID || environment != query.EnvironmentID || version != schemaVersion ||
		!validProductID(edgeID) || !validAdapterKind(kind) || !validProductID(sourceID) || !validProductID(targetID) || sourceID == targetID {
		return graphstore.DriverEdge{}, false
	}
	return graphstore.DriverEdge{
		OrganizationID: organization, WorkspaceID: workspace, EnvironmentID: environment,
		EdgeID: edgeID, Kind: kind, SourceID: sourceID, TargetID: targetID,
	}, true
}

func validDirection(direction string, frontier map[string]struct{}, nodeID string, edge graphstore.DriverEdge) bool {
	_, sourceInFrontier := frontier[edge.SourceID]
	_, targetInFrontier := frontier[edge.TargetID]
	switch direction {
	case "outgoing":
		return sourceInFrontier && edge.TargetID == nodeID
	case "incoming":
		return targetInFrontier && edge.SourceID == nodeID
	case "both":
		return (sourceInFrontier && edge.TargetID == nodeID) || (targetInFrontier && edge.SourceID == nodeID)
	default:
		return false
	}
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedProjection(nodes map[string]graphstore.DriverNode, edges map[string]graphstore.DriverEdge) graphstore.DriverProjection {
	projection := graphstore.DriverProjection{Nodes: make([]graphstore.DriverNode, 0, len(nodes)), Edges: make([]graphstore.DriverEdge, 0, len(edges))}
	for _, node := range nodes {
		projection.Nodes = append(projection.Nodes, node)
	}
	for _, edge := range edges {
		projection.Edges = append(projection.Edges, edge)
	}
	sort.Slice(projection.Nodes, func(left, right int) bool { return projection.Nodes[left].NodeID < projection.Nodes[right].NodeID })
	sort.Slice(projection.Edges, func(left, right int) bool { return projection.Edges[left].EdgeID < projection.Edges[right].EdgeID })
	return projection
}

func projectionEndpointsPresent(projection graphstore.DriverProjection) bool {
	nodes := make(map[string]struct{}, len(projection.Nodes))
	for _, node := range projection.Nodes {
		nodes[node.NodeID] = struct{}{}
	}
	for _, edge := range projection.Edges {
		if _, present := nodes[edge.SourceID]; !present {
			return false
		}
		if _, present := nodes[edge.TargetID]; !present {
			return false
		}
	}
	return true
}
