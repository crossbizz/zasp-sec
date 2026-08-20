package neo4jstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
)

const (
	maximumSnapshotNodes = 1_000
	maximumSnapshotEdges = 2_000
	snapshotQueryTimeout = 30 * time.Second
	snapshotNodeLabel    = "ZaspInventoryGraphNode"
	snapshotEdgeType     = "ZASP_INVENTORY_GRAPH_EDGE"
	snapshotMarkerLabel  = "ZaspGraphProjection"

	lockSnapshotQuery        = "MERGE (marker:ZaspGraphProjection {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source}) ON CREATE SET marker.snapshot_id = '', marker.generation = 0, marker.input_digest = $zero_digest, marker.content_digest = $zero_digest, marker.node_ids = [], marker.edge_ids = [], marker.schema_version = $schema_version, marker.lock_version = 0 SET marker.lock_version = marker.lock_version + 1 WITH marker WHERE size(keys(marker)) = 13 AND all(key IN keys(marker) WHERE key IN ['organization_id', 'workspace_id', 'environment_id', 'integration_id', 'source', 'snapshot_id', 'generation', 'input_digest', 'content_digest', 'node_ids', 'edge_ids', 'schema_version', 'lock_version']) AND marker.schema_version = $schema_version RETURN marker.generation AS generation, marker.snapshot_id AS snapshot_id, marker.input_digest AS input_digest, marker.content_digest AS content_digest, size(marker.node_ids) AS marker_node_count, marker.node_ids[0..$node_limit] AS node_ids, size(marker.edge_ids) AS marker_edge_count, marker.edge_ids[0..$edge_limit] AS edge_ids, keys(marker) AS marker_property_keys"
	removeSnapshotEdgesQuery = "MATCH ()-[edge:ZASP_INVENTORY_GRAPH_EDGE]->() WHERE edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.integration_id = $integration_id AND edge.source = $source AND NOT any(input IN $edges WHERE input.edge_id = edge.edge_id AND input.kind = edge.kind AND input.source_id = startNode(edge).node_id AND input.target_id = endNode(edge).node_id AND startNode(edge).organization_id = $organization_id AND startNode(edge).workspace_id = $workspace_id AND startNode(edge).environment_id = $environment_id AND startNode(edge).integration_id = $integration_id AND startNode(edge).source = $source AND endNode(edge).organization_id = $organization_id AND endNode(edge).workspace_id = $workspace_id AND endNode(edge).environment_id = $environment_id AND endNode(edge).integration_id = $integration_id AND endNode(edge).source = $source) DELETE edge RETURN count(edge) AS removed"
	removeSnapshotNodesQuery = "MATCH (node:ZaspInventoryGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source}) WHERE NOT node.node_id IN $node_ids DETACH DELETE node RETURN count(node) AS removed"
	upsertSnapshotNodesQuery = "UNWIND $nodes AS input MERGE (node:ZaspInventoryGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source, node_id: input.node_id}) SET node.kind = input.kind, node.snapshot_id = $snapshot_id, node.generation = $generation, node.input_digest = $input_digest, node.content_digest = $content_digest, node.schema_version = $schema_version WITH node, input WHERE size(keys(node)) = 12 AND all(key IN keys(node) WHERE key IN ['organization_id', 'workspace_id', 'environment_id', 'integration_id', 'source', 'node_id', 'kind', 'snapshot_id', 'generation', 'input_digest', 'content_digest', 'schema_version']) AND node.kind = input.kind AND node.snapshot_id = $snapshot_id AND node.generation = $generation AND node.input_digest = $input_digest AND node.content_digest = $content_digest AND node.schema_version = $schema_version RETURN count(node) AS matched"
	upsertSnapshotEdgesQuery = "UNWIND $edges AS input MATCH (source:ZaspInventoryGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source, node_id: input.source_id}) MATCH (target:ZaspInventoryGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source, node_id: input.target_id}) MERGE (source)-[edge:ZASP_INVENTORY_GRAPH_EDGE {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source, edge_id: input.edge_id}]->(target) SET edge.kind = input.kind, edge.snapshot_id = $snapshot_id, edge.generation = $generation, edge.input_digest = $input_digest, edge.content_digest = $content_digest, edge.schema_version = $schema_version WITH edge, input WHERE size(keys(edge)) = 12 AND all(key IN keys(edge) WHERE key IN ['organization_id', 'workspace_id', 'environment_id', 'integration_id', 'source', 'edge_id', 'kind', 'snapshot_id', 'generation', 'input_digest', 'content_digest', 'schema_version']) AND edge.kind = input.kind AND edge.snapshot_id = $snapshot_id AND edge.generation = $generation AND edge.input_digest = $input_digest AND edge.content_digest = $content_digest AND edge.schema_version = $schema_version RETURN count(edge) AS matched"
	activateSnapshotQuery    = "MATCH (marker:ZaspGraphProjection {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source}) SET marker.snapshot_id = $snapshot_id, marker.generation = $generation, marker.input_digest = $input_digest, marker.content_digest = $content_digest, marker.node_ids = $node_ids, marker.edge_ids = $edge_ids, marker.schema_version = $schema_version WITH marker WHERE size(keys(marker)) = 13 AND all(key IN keys(marker) WHERE key IN ['organization_id', 'workspace_id', 'environment_id', 'integration_id', 'source', 'snapshot_id', 'generation', 'input_digest', 'content_digest', 'node_ids', 'edge_ids', 'schema_version', 'lock_version']) AND marker.snapshot_id = $snapshot_id AND marker.generation = $generation AND marker.input_digest = $input_digest AND marker.content_digest = $content_digest AND marker.node_ids = $node_ids AND marker.edge_ids = $edge_ids AND marker.schema_version = $schema_version RETURN count(marker) AS activated"
	readbackSnapshotQuery    = "MATCH (marker:ZaspGraphProjection {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source}) CALL { WITH marker MATCH (node:ZaspInventoryGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source}) RETURN count(node) AS node_count } CALL { WITH marker MATCH (node:ZaspInventoryGraphNode {organization_id: $organization_id, workspace_id: $workspace_id, environment_id: $environment_id, integration_id: $integration_id, source: $source}) WITH node ORDER BY node.node_id LIMIT $node_limit RETURN collect({organization_id: node.organization_id, workspace_id: node.workspace_id, environment_id: node.environment_id, integration_id: node.integration_id, source: node.source, node_id: node.node_id, kind: node.kind, snapshot_id: node.snapshot_id, generation: node.generation, input_digest: node.input_digest, content_digest: node.content_digest, schema_version: node.schema_version, property_keys: keys(node)}) AS nodes } CALL { WITH marker MATCH ()-[edge:ZASP_INVENTORY_GRAPH_EDGE]->() WHERE edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.integration_id = $integration_id AND edge.source = $source AND startNode(edge).organization_id = $organization_id AND startNode(edge).workspace_id = $workspace_id AND startNode(edge).environment_id = $environment_id AND startNode(edge).integration_id = $integration_id AND startNode(edge).source = $source AND endNode(edge).organization_id = $organization_id AND endNode(edge).workspace_id = $workspace_id AND endNode(edge).environment_id = $environment_id AND endNode(edge).integration_id = $integration_id AND endNode(edge).source = $source RETURN count(edge) AS edge_count } CALL { WITH marker MATCH ()-[edge:ZASP_INVENTORY_GRAPH_EDGE]->() WHERE edge.organization_id = $organization_id AND edge.workspace_id = $workspace_id AND edge.environment_id = $environment_id AND edge.integration_id = $integration_id AND edge.source = $source AND startNode(edge).organization_id = $organization_id AND startNode(edge).workspace_id = $workspace_id AND startNode(edge).environment_id = $environment_id AND startNode(edge).integration_id = $integration_id AND startNode(edge).source = $source AND endNode(edge).organization_id = $organization_id AND endNode(edge).workspace_id = $workspace_id AND endNode(edge).environment_id = $environment_id AND endNode(edge).integration_id = $integration_id AND endNode(edge).source = $source WITH edge ORDER BY edge.edge_id LIMIT $edge_limit RETURN collect({organization_id: edge.organization_id, workspace_id: edge.workspace_id, environment_id: edge.environment_id, integration_id: edge.integration_id, source: edge.source, edge_id: edge.edge_id, kind: edge.kind, source_id: startNode(edge).node_id, target_id: endNode(edge).node_id, snapshot_id: edge.snapshot_id, generation: edge.generation, input_digest: edge.input_digest, content_digest: edge.content_digest, schema_version: edge.schema_version, property_keys: keys(edge)}) AS edges } RETURN marker.generation AS generation, marker.snapshot_id AS snapshot_id, marker.input_digest AS input_digest, marker.content_digest AS content_digest, size(marker.node_ids) AS marker_node_count, marker.node_ids[0..$node_limit] AS node_ids, size(marker.edge_ids) AS marker_edge_count, marker.edge_ids[0..$edge_limit] AS edge_ids, keys(marker) AS marker_property_keys, node_count, nodes, edge_count, edges"
)

var (
	snapshotMarkerKeys       = []string{"generation", "snapshot_id", "input_digest", "content_digest", "marker_node_count", "node_ids", "marker_edge_count", "edge_ids", "marker_property_keys"}
	snapshotReadbackKeys     = []string{"generation", "snapshot_id", "input_digest", "content_digest", "marker_node_count", "node_ids", "marker_edge_count", "edge_ids", "marker_property_keys", "node_count", "nodes", "edge_count", "edges"}
	snapshotMarkerProperties = []string{"content_digest", "edge_ids", "environment_id", "generation", "input_digest", "integration_id", "lock_version", "node_ids", "organization_id", "schema_version", "snapshot_id", "source", "workspace_id"}
	snapshotNodeProperties   = []string{"content_digest", "environment_id", "generation", "input_digest", "integration_id", "kind", "node_id", "organization_id", "schema_version", "snapshot_id", "source", "workspace_id"}
	snapshotEdgeProperties   = []string{"content_digest", "edge_id", "environment_id", "generation", "input_digest", "integration_id", "kind", "organization_id", "schema_version", "snapshot_id", "source", "workspace_id"}
)

type snapshotMarkerState struct {
	Snapshot graphstore.DriverSnapshot
	NodeIDs  []string
	EdgeIDs  []string
}

func (adapter *Adapter) ReplaceSnapshot(ctx context.Context, projection graphstore.DriverSnapshotProjection) (graphstore.DriverSnapshotReplaced, error) {
	if adapter == nil || ctx == nil || nilInterface(adapter.provider) || adapter.database != databaseName {
		return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotUnavailable
	}
	if ctx.Err() != nil {
		return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotCanceled
	}
	parameters, expected, ok := canonicalSnapshotProjection(projection)
	if !ok {
		return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotUnavailable
	}
	operationCtx, cancel := context.WithTimeout(ctx, snapshotQueryTimeout)
	defer cancel()
	return adapter.replaceSnapshot(operationCtx, projection, parameters, expected)
}

func (adapter *Adapter) replaceSnapshot(ctx context.Context, projection graphstore.DriverSnapshotProjection, parameters map[string]any, expected graphstore.DriverSnapshotReplaced) (graphstore.DriverSnapshotReplaced, error) {
	session, ok := newSnapshotSession(ctx, adapter.provider, sessionConfig{Database: adapter.database, Access: accessWrite})
	if !ok {
		return noMutationSnapshotResult(projection), snapshotContextError(ctx, graphstore.ErrSnapshotRetryable)
	}
	closed := false
	defer func() {
		if !closed {
			closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			_ = safeClose(closeCtx, session)
			cancel()
		}
	}()
	transaction, ok := beginSnapshotTransaction(ctx, session)
	if !ok {
		if !nilInterface(transaction) {
			rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			rolledBack := safeRollback(rollbackCtx, transaction)
			rollbackCancel()
			if !rolledBack {
				return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotUnknownOutcome
			}
		}
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		_ = safeClose(closeCtx, session)
		cancel()
		closed = true
		return noMutationSnapshotResult(projection), snapshotContextError(ctx, graphstore.ErrSnapshotRetryable)
	}

	marker, err := readSnapshotMarker(ctx, transaction, lockSnapshotQuery, parameters)
	if err != nil {
		return settledSnapshotResult(ctx, transaction, projection, err)
	}
	decision := compareSnapshotMarker(marker, projection.Snapshot, expected.NodeIDs, expected.EdgeIDs)
	switch decision {
	case graphstore.ErrSnapshotStale, graphstore.ErrSnapshotDrift:
		if ctx.Err() != nil {
			return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotCanceled)
		}
		if !rollbackSnapshotTransaction(ctx, transaction) {
			return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotUnknownOutcome
		}
		return graphstore.DriverSnapshotReplaced{CandidateSnapshot: projection.Snapshot, ActiveSnapshot: marker.Snapshot, NodeIDs: append([]string(nil), marker.NodeIDs...), EdgeIDs: append([]string(nil), marker.EdgeIDs...), Outcome: graphstore.DriverSnapshotNoMutation}, decision
	case nil:
		readback, readErr := readSnapshotProjection(ctx, transaction, parameters)
		if readErr != nil || !exactSnapshotProjection(readback, projection) {
			return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotDrift)
		}
		if ctx.Err() != nil {
			return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotCanceled)
		}
		if !rollbackSnapshotTransaction(ctx, transaction) {
			return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotUnknownOutcome
		}
		expected.Replayed = true
		return expected, nil
	}

	removedEdges, err := runSnapshotCount(ctx, transaction, removeSnapshotEdgesQuery, parameters, "removed")
	if err != nil {
		return settledSnapshotResult(ctx, transaction, projection, err)
	}
	removedNodes, err := runSnapshotCount(ctx, transaction, removeSnapshotNodesQuery, parameters, "removed")
	if err != nil {
		return settledSnapshotResult(ctx, transaction, projection, err)
	}
	matchedNodes, err := runSnapshotCount(ctx, transaction, upsertSnapshotNodesQuery, parameters, "matched")
	if err != nil || matchedNodes != int64(len(projection.Nodes)) {
		return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotDrift)
	}
	matchedEdges, err := runSnapshotCount(ctx, transaction, upsertSnapshotEdgesQuery, parameters, "matched")
	if err != nil || matchedEdges != int64(len(projection.Edges)) {
		return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotDrift)
	}
	activated, err := runSnapshotCount(ctx, transaction, activateSnapshotQuery, parameters, "activated")
	if err != nil || activated != 1 {
		return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotDrift)
	}
	readback, err := readSnapshotProjection(ctx, transaction, parameters)
	if err != nil || !exactSnapshotProjection(readback, projection) {
		return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotDrift)
	}
	expected.RemovedNodes = int(removedNodes)
	expected.RemovedEdges = int(removedEdges)
	if ctx.Err() != nil {
		return settledSnapshotResult(ctx, transaction, projection, graphstore.ErrSnapshotCanceled)
	}
	if commitSnapshotTransaction(ctx, transaction) {
		return expected, nil
	}
	reconciled, ok := adapter.reconcileSnapshot(ctx, projection, parameters, expected)
	if ok {
		return reconciled, nil
	}
	return graphstore.DriverSnapshotReplaced{}, graphstore.ErrSnapshotUnknownOutcome
}

func canonicalSnapshotProjection(projection graphstore.DriverSnapshotProjection) (map[string]any, graphstore.DriverSnapshotReplaced, bool) {
	binding := projection.Snapshot
	if !validSnapshotBinding(binding) || len(projection.Nodes) > maximumSnapshotNodes || len(projection.Edges) > maximumSnapshotEdges {
		return nil, graphstore.DriverSnapshotReplaced{}, false
	}
	nodes := make([]any, len(projection.Nodes))
	nodeIDs := make([]string, len(projection.Nodes))
	nodeSet := make(map[string]struct{}, len(projection.Nodes))
	previous := ""
	for index, node := range projection.Nodes {
		if node.Snapshot != binding || !validProductID(node.NodeID) || !validAdapterKind(node.Kind) || previous >= node.NodeID && previous != "" {
			return nil, graphstore.DriverSnapshotReplaced{}, false
		}
		if _, duplicate := nodeSet[node.NodeID]; duplicate {
			return nil, graphstore.DriverSnapshotReplaced{}, false
		}
		previous = node.NodeID
		nodeSet[node.NodeID] = struct{}{}
		nodeIDs[index] = node.NodeID
		nodes[index] = map[string]any{"node_id": node.NodeID, "kind": node.Kind}
	}
	edges := make([]any, len(projection.Edges))
	edgeIDs := make([]string, len(projection.Edges))
	semantic := make(map[string]struct{}, len(projection.Edges))
	previous = ""
	for index, edge := range projection.Edges {
		if edge.Snapshot != binding || !validProductID(edge.EdgeID) || !validProductID(edge.SourceID) || !validProductID(edge.TargetID) ||
			!validAdapterKind(edge.Kind) || edge.SourceID == edge.TargetID || previous >= edge.EdgeID && previous != "" {
			return nil, graphstore.DriverSnapshotReplaced{}, false
		}
		if _, present := nodeSet[edge.SourceID]; !present {
			return nil, graphstore.DriverSnapshotReplaced{}, false
		}
		if _, present := nodeSet[edge.TargetID]; !present {
			return nil, graphstore.DriverSnapshotReplaced{}, false
		}
		key := edge.Kind + "\x00" + edge.SourceID + "\x00" + edge.TargetID
		if _, duplicate := semantic[key]; duplicate {
			return nil, graphstore.DriverSnapshotReplaced{}, false
		}
		semantic[key] = struct{}{}
		previous = edge.EdgeID
		edgeIDs[index] = edge.EdgeID
		edges[index] = map[string]any{"edge_id": edge.EdgeID, "kind": edge.Kind, "source_id": edge.SourceID, "target_id": edge.TargetID}
	}
	if binding.ContentDigest != graphstore.CanonicalSnapshotContentDigest(binding, projection.Nodes, projection.Edges) {
		return nil, graphstore.DriverSnapshotReplaced{}, false
	}
	parameters := snapshotParameters(projection)
	parameters["nodes"] = nodes
	parameters["edges"] = edges
	parameters["node_ids"] = append([]string(nil), nodeIDs...)
	parameters["edge_ids"] = append([]string(nil), edgeIDs...)
	return parameters, graphstore.DriverSnapshotReplaced{CandidateSnapshot: binding, ActiveSnapshot: binding, NodeIDs: nodeIDs, EdgeIDs: edgeIDs, Outcome: graphstore.DriverSnapshotDurable}, true
}

func snapshotParameters(projection graphstore.DriverSnapshotProjection) map[string]any {
	binding := projection.Snapshot
	nodes := make([]any, len(projection.Nodes))
	for index, node := range projection.Nodes {
		nodes[index] = map[string]any{"node_id": node.NodeID, "kind": node.Kind}
	}
	edges := make([]any, len(projection.Edges))
	for index, edge := range projection.Edges {
		edges[index] = map[string]any{"edge_id": edge.EdgeID, "kind": edge.Kind, "source_id": edge.SourceID, "target_id": edge.TargetID}
	}
	return map[string]any{
		"organization_id": binding.OrganizationID, "workspace_id": binding.WorkspaceID,
		"environment_id": binding.EnvironmentID, "integration_id": binding.IntegrationID, "source": binding.Source,
		"snapshot_id": binding.SnapshotID, "generation": binding.Generation,
		"input_digest": hex.EncodeToString(binding.InputDigest[:]), "content_digest": hex.EncodeToString(binding.ContentDigest[:]),
		"node_ids": snapshotNodeIDs(projection), "edge_ids": snapshotEdgeIDs(projection),
		"nodes": nodes, "edges": edges, "schema_version": schemaVersion,
		"node_limit": maximumSnapshotNodes + 1, "edge_limit": maximumSnapshotEdges + 1,
		"zero_digest": hex.EncodeToString(make([]byte, sha256.Size)),
	}
}

func validSnapshotBinding(binding graphstore.DriverSnapshot) bool {
	return validProductID(binding.OrganizationID) && validProductID(binding.WorkspaceID) && validProductID(binding.EnvironmentID) &&
		validProductID(binding.IntegrationID) && adapterKindPattern.MatchString(binding.Source) && validProductID(binding.SnapshotID) && binding.Generation >= 1 &&
		binding.InputDigest != [sha256.Size]byte{} && binding.ContentDigest != [sha256.Size]byte{}
}

func compareSnapshotMarker(marker snapshotMarkerState, binding graphstore.DriverSnapshot, nodeIDs, edgeIDs []string) error {
	if marker.Snapshot.Generation > binding.Generation {
		return graphstore.ErrSnapshotStale
	}
	if marker.Snapshot.Generation < binding.Generation {
		return errors.New("apply")
	}
	if marker.Snapshot != binding || !slices.Equal(marker.NodeIDs, nodeIDs) || !slices.Equal(marker.EdgeIDs, edgeIDs) {
		return graphstore.ErrSnapshotDrift
	}
	return nil
}

func readSnapshotMarker(ctx context.Context, transaction graphTransaction, query string, parameters map[string]any) (snapshotMarkerState, error) {
	result, err := runSnapshotQuery(ctx, transaction, query, parameters)
	if err != nil {
		return snapshotMarkerState{}, err
	}
	record, ok := safeSingleRecord(ctx, result, snapshotMarkerKeys)
	if !ok {
		return snapshotMarkerState{}, graphstore.ErrSnapshotDrift
	}
	marker, ok := parseSnapshotMarker(record.Values, snapshotKeyFromParameters(parameters))
	if !ok {
		return snapshotMarkerState{}, graphstore.ErrSnapshotDrift
	}
	return marker, nil
}

func readSnapshotProjection(ctx context.Context, transaction graphTransaction, parameters map[string]any) (graphstore.DriverSnapshotProjection, error) {
	result, err := runSnapshotQuery(ctx, transaction, readbackSnapshotQuery, parameters)
	if err != nil {
		return graphstore.DriverSnapshotProjection{}, err
	}
	record, ok := safeSingleRecord(ctx, result, snapshotReadbackKeys)
	if !ok || len(record.Values) != len(snapshotReadbackKeys) {
		return graphstore.DriverSnapshotProjection{}, graphstore.ErrSnapshotDrift
	}
	marker, ok := parseSnapshotMarker(record.Values[:len(snapshotMarkerKeys)], snapshotKeyFromParameters(parameters))
	if !ok {
		return graphstore.DriverSnapshotProjection{}, graphstore.ErrSnapshotDrift
	}
	nodeCount, nodeCountOK := record.Values[9].(int64)
	nodes, ok := parseSnapshotNodes(record.Values[10], marker.Snapshot)
	if !ok || !nodeCountOK || nodeCount < 0 || nodeCount > maximumSnapshotNodes || nodeCount != int64(len(nodes)) {
		return graphstore.DriverSnapshotProjection{}, graphstore.ErrSnapshotDrift
	}
	edgeCount, edgeCountOK := record.Values[11].(int64)
	edges, ok := parseSnapshotEdges(record.Values[12], marker.Snapshot)
	if !ok || !edgeCountOK || edgeCount < 0 || edgeCount > maximumSnapshotEdges || edgeCount != int64(len(edges)) {
		return graphstore.DriverSnapshotProjection{}, graphstore.ErrSnapshotDrift
	}
	if !slices.Equal(marker.NodeIDs, snapshotNodeIDs(graphstore.DriverSnapshotProjection{Nodes: nodes})) ||
		!slices.Equal(marker.EdgeIDs, snapshotEdgeIDs(graphstore.DriverSnapshotProjection{Edges: edges})) {
		return graphstore.DriverSnapshotProjection{}, graphstore.ErrSnapshotDrift
	}
	return graphstore.DriverSnapshotProjection{Snapshot: marker.Snapshot, Nodes: nodes, Edges: edges}, nil
}

func parseSnapshotMarker(values []any, binding graphstore.DriverSnapshot) (snapshotMarkerState, bool) {
	if len(values) != len(snapshotMarkerKeys) {
		return snapshotMarkerState{}, false
	}
	generation, generationOK := values[0].(int64)
	snapshotID, snapshotOK := values[1].(string)
	inputText, inputOK := values[2].(string)
	contentText, contentOK := values[3].(string)
	nodeCount, nodeCountOK := values[4].(int64)
	nodeIDs, nodeOK := exactSortedProductIDs(values[5], maximumSnapshotNodes)
	edgeCount, edgeCountOK := values[6].(int64)
	edgeIDs, edgeOK := exactSortedProductIDs(values[7], maximumSnapshotEdges)
	propertyKeys, propertyOK := exactStringList(values[8])
	inputDigest, inputDigestOK := decodeSnapshotDigest(inputText)
	contentDigest, contentDigestOK := decodeSnapshotDigest(contentText)
	if !generationOK || !snapshotOK || !inputOK || !contentOK || !nodeCountOK || !nodeOK || !edgeCountOK || !edgeOK || !propertyOK || !inputDigestOK || !contentDigestOK ||
		nodeCount < 0 || nodeCount > maximumSnapshotNodes || nodeCount != int64(len(nodeIDs)) || edgeCount < 0 || edgeCount > maximumSnapshotEdges || edgeCount != int64(len(edgeIDs)) ||
		!sameStringSet(propertyKeys, snapshotMarkerProperties) || generation < 0 {
		return snapshotMarkerState{}, false
	}
	if generation == 0 {
		if snapshotID != "" || inputDigest != [sha256.Size]byte{} || contentDigest != [sha256.Size]byte{} || len(nodeIDs) != 0 || len(edgeIDs) != 0 {
			return snapshotMarkerState{}, false
		}
		binding.SnapshotID = ""
		binding.Generation = 0
		binding.InputDigest = [sha256.Size]byte{}
		binding.ContentDigest = [sha256.Size]byte{}
		return snapshotMarkerState{Snapshot: binding, NodeIDs: []string{}, EdgeIDs: []string{}}, true
	}
	if !validProductID(snapshotID) || inputDigest == [sha256.Size]byte{} || contentDigest == [sha256.Size]byte{} {
		return snapshotMarkerState{}, false
	}
	binding.SnapshotID = snapshotID
	binding.Generation = generation
	binding.InputDigest = inputDigest
	binding.ContentDigest = contentDigest
	return snapshotMarkerState{Snapshot: binding, NodeIDs: nodeIDs, EdgeIDs: edgeIDs}, true
}

func parseSnapshotNodes(value any, binding graphstore.DriverSnapshot) ([]graphstore.DriverSnapshotNode, bool) {
	items, ok := value.([]any)
	if !ok || len(items) > maximumSnapshotNodes {
		return nil, false
	}
	nodes := make([]graphstore.DriverSnapshotNode, len(items))
	previous := ""
	for index, item := range items {
		properties, ok := item.(map[string]any)
		if !ok || !sameSnapshotRecord(properties, binding, snapshotNodeProperties) {
			return nil, false
		}
		nodeID, nodeOK := properties["node_id"].(string)
		kind, kindOK := properties["kind"].(string)
		if !nodeOK || !kindOK || !validProductID(nodeID) || !validAdapterKind(kind) || previous != "" && previous >= nodeID {
			return nil, false
		}
		previous = nodeID
		nodes[index] = graphstore.DriverSnapshotNode{Snapshot: binding, NodeID: nodeID, Kind: kind}
	}
	return nodes, true
}

func parseSnapshotEdges(value any, binding graphstore.DriverSnapshot) ([]graphstore.DriverSnapshotEdge, bool) {
	items, ok := value.([]any)
	if !ok || len(items) > maximumSnapshotEdges {
		return nil, false
	}
	edges := make([]graphstore.DriverSnapshotEdge, len(items))
	previous := ""
	for index, item := range items {
		properties, ok := item.(map[string]any)
		if !ok || !sameSnapshotRecord(properties, binding, snapshotEdgeProperties) {
			return nil, false
		}
		edgeID, edgeOK := properties["edge_id"].(string)
		kind, kindOK := properties["kind"].(string)
		sourceID, sourceOK := properties["source_id"].(string)
		targetID, targetOK := properties["target_id"].(string)
		if !edgeOK || !kindOK || !sourceOK || !targetOK || !validProductID(edgeID) || !validProductID(sourceID) || !validProductID(targetID) ||
			!validAdapterKind(kind) || sourceID == targetID || previous != "" && previous >= edgeID {
			return nil, false
		}
		previous = edgeID
		edges[index] = graphstore.DriverSnapshotEdge{Snapshot: binding, EdgeID: edgeID, Kind: kind, SourceID: sourceID, TargetID: targetID}
	}
	return edges, true
}

func sameSnapshotRecord(properties map[string]any, binding graphstore.DriverSnapshot, expectedKeys []string) bool {
	resultKeys := append(append([]string(nil), expectedKeys...), "property_keys")
	if _, edge := properties["edge_id"]; edge {
		resultKeys = append(resultKeys, "source_id", "target_id")
	}
	if !exactMapKeys(properties, resultKeys) {
		return false
	}
	organization, organizationOK := properties["organization_id"].(string)
	workspace, workspaceOK := properties["workspace_id"].(string)
	environment, environmentOK := properties["environment_id"].(string)
	integration, integrationOK := properties["integration_id"].(string)
	source, sourceOK := properties["source"].(string)
	snapshotID, snapshotOK := properties["snapshot_id"].(string)
	generation, generationOK := properties["generation"].(int64)
	inputDigest, inputOK := properties["input_digest"].(string)
	contentDigest, contentOK := properties["content_digest"].(string)
	version, versionOK := properties["schema_version"].(int64)
	propertyKeys, propertyOK := exactStringList(properties["property_keys"])
	return organizationOK && workspaceOK && environmentOK && integrationOK && sourceOK && snapshotOK && generationOK && inputOK && contentOK && versionOK && propertyOK &&
		organization == binding.OrganizationID && workspace == binding.WorkspaceID && environment == binding.EnvironmentID && integration == binding.IntegrationID &&
		source == binding.Source && snapshotID == binding.SnapshotID && generation == binding.Generation && inputDigest == hex.EncodeToString(binding.InputDigest[:]) &&
		contentDigest == hex.EncodeToString(binding.ContentDigest[:]) && version == schemaVersion && sameStringSet(propertyKeys, expectedKeys)
}

func exactSnapshotProjection(left, right graphstore.DriverSnapshotProjection) bool {
	return left.Snapshot == right.Snapshot && slices.Equal(left.Nodes, right.Nodes) && slices.Equal(left.Edges, right.Edges)
}

func exactSortedProductIDs(value any, maximum int) ([]string, bool) {
	items, ok := exactStringList(value)
	if !ok || len(items) > maximum {
		return nil, false
	}
	for index, item := range items {
		if !validProductID(item) || index > 0 && items[index-1] >= item {
			return nil, false
		}
	}
	return items, true
}

func sameStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualCopy := append([]string(nil), actual...)
	sort.Strings(actualCopy)
	return slices.Equal(actualCopy, expected)
}

func decodeSnapshotDigest(value string) ([sha256.Size]byte, bool) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(value) != value {
		return [sha256.Size]byte{}, false
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result, true
}

func runSnapshotCount(ctx context.Context, transaction graphTransaction, query string, parameters map[string]any, key string) (int64, error) {
	result, err := runSnapshotQuery(ctx, transaction, query, parameters)
	if err != nil {
		return 0, err
	}
	record, ok := safeSingleRecord(ctx, result, []string{key})
	if !ok || len(record.Values) != 1 {
		return 0, graphstore.ErrSnapshotDrift
	}
	count, ok := record.Values[0].(int64)
	if !ok || count < 0 || count > maximumSnapshotNodes+maximumSnapshotEdges {
		return 0, graphstore.ErrSnapshotDrift
	}
	return count, nil
}

func runSnapshotQuery(ctx context.Context, transaction graphTransaction, query string, parameters map[string]any) (result graphResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = graphstore.ErrSnapshotRetryable
		}
	}()
	result, err := transaction.Run(ctx, query, parameters)
	if err != nil || nilInterface(result) {
		return nil, graphstore.ErrSnapshotRetryable
	}
	return result, nil
}

func safeSingleRecord(ctx context.Context, result graphResult, keys []string) (record graphRecord, ok bool) {
	defer func() {
		if recover() != nil {
			record = graphRecord{}
			ok = false
		}
	}()
	return singleRecord(ctx, result, keys)
}

func settleSnapshotFailure(ctx context.Context, transaction graphTransaction, cause error) error {
	if !rollbackSnapshotTransaction(ctx, transaction) {
		return graphstore.ErrSnapshotUnknownOutcome
	}
	if ctx.Err() != nil || errors.Is(cause, graphstore.ErrSnapshotCanceled) {
		return graphstore.ErrSnapshotCanceled
	}
	if errors.Is(cause, graphstore.ErrSnapshotDrift) {
		return graphstore.ErrSnapshotDrift
	}
	return graphstore.ErrSnapshotRetryable
}

func rollbackSnapshotTransaction(ctx context.Context, transaction graphTransaction) bool {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	return safeRollback(rollbackCtx, transaction)
}

func settledSnapshotResult(ctx context.Context, transaction graphTransaction, projection graphstore.DriverSnapshotProjection, cause error) (graphstore.DriverSnapshotReplaced, error) {
	settled := settleSnapshotFailure(ctx, transaction, cause)
	if errors.Is(settled, graphstore.ErrSnapshotUnknownOutcome) {
		return graphstore.DriverSnapshotReplaced{}, settled
	}
	return noMutationSnapshotResult(projection), settled
}

func noMutationSnapshotResult(projection graphstore.DriverSnapshotProjection) graphstore.DriverSnapshotReplaced {
	return graphstore.DriverSnapshotReplaced{CandidateSnapshot: projection.Snapshot, Outcome: graphstore.DriverSnapshotNoMutation}
}

func snapshotKeyFromParameters(parameters map[string]any) graphstore.DriverSnapshot {
	organization, _ := parameters["organization_id"].(string)
	workspace, _ := parameters["workspace_id"].(string)
	environment, _ := parameters["environment_id"].(string)
	integration, _ := parameters["integration_id"].(string)
	source, _ := parameters["source"].(string)
	return graphstore.DriverSnapshot{OrganizationID: organization, WorkspaceID: workspace, EnvironmentID: environment, IntegrationID: integration, Source: source}
}

func snapshotContextError(ctx context.Context, fallback error) error {
	if ctx.Err() != nil {
		return graphstore.ErrSnapshotCanceled
	}
	return fallback
}

func newSnapshotSession(ctx context.Context, provider sessionProvider, config sessionConfig) (session graphSession, ok bool) {
	defer func() {
		if recover() != nil {
			session = nil
			ok = false
		}
	}()
	session = provider.NewSession(ctx, config)
	return session, !nilInterface(session)
}

func beginSnapshotTransaction(ctx context.Context, session graphSession) (transaction graphTransaction, ok bool) {
	defer func() {
		if recover() != nil {
			transaction = nil
			ok = false
		}
	}()
	transaction, err := session.Begin(ctx)
	return transaction, err == nil && !nilInterface(transaction)
}

func commitSnapshotTransaction(ctx context.Context, transaction graphTransaction) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return transaction.Commit(ctx) == nil
}

func (adapter *Adapter) reconcileSnapshot(ctx context.Context, projection graphstore.DriverSnapshotProjection, parameters map[string]any, expected graphstore.DriverSnapshotReplaced) (graphstore.DriverSnapshotReplaced, bool) {
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	session, ok := newSnapshotSession(reconcileCtx, adapter.provider, sessionConfig{Database: adapter.database, Access: accessRead})
	if !ok {
		return graphstore.DriverSnapshotReplaced{}, false
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.WithoutCancel(reconcileCtx), cleanupTimeout)
		_ = safeClose(closeCtx, session)
		closeCancel()
	}()
	transaction, ok := beginSnapshotTransaction(reconcileCtx, session)
	if !ok {
		return graphstore.DriverSnapshotReplaced{}, false
	}
	readback, err := readSnapshotProjection(reconcileCtx, transaction, parameters)
	if err != nil || !exactSnapshotProjection(readback, projection) {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(reconcileCtx), cleanupTimeout)
		_ = safeRollback(rollbackCtx, transaction)
		rollbackCancel()
		return graphstore.DriverSnapshotReplaced{}, false
	}
	if !commitSnapshotTransaction(reconcileCtx, transaction) {
		return graphstore.DriverSnapshotReplaced{}, false
	}
	expected.Replayed = true
	return expected, true
}

func snapshotNodeIDs(input graphstore.DriverSnapshotProjection) []string {
	result := make([]string, len(input.Nodes))
	for index, node := range input.Nodes {
		result[index] = node.NodeID
	}
	return result
}

func snapshotEdgeIDs(input graphstore.DriverSnapshotProjection) []string {
	result := make([]string, len(input.Edges))
	for index, edge := range input.Edges {
		result[index] = edge.EdgeID
	}
	return result
}
