package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

type runtimeProjectionExecutorConfig struct {
	Reader                runtimeArchivedBatchReader
	Receipts              artifactstore.ObjectReferencingArtifactStore
	Graph                 runtimeCorrelationGraphStore
	ImplementationVersion string
}

type runtimeProjectionExecutor struct {
	config runtimeProjectionExecutorConfig
}

func newRuntimeProjectionExecutor(config runtimeProjectionExecutorConfig) (*runtimeProjectionExecutor, error) {
	if nilWorkerDependency(config.Reader) || nilWorkerDependency(config.Receipts) || nilWorkerDependency(config.Graph) || config.ImplementationVersion != "runtime-projection-v1" {
		return nil, errRuntimeUnavailable
	}
	return &runtimeProjectionExecutor{config: config}, nil
}

func (executor *runtimeProjectionExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageProject) || lease.ImplementationVersion != executor.config.ImplementationVersion {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	locator, ok := runtimeReceiptLocator(lease.Scope, lease.InputReference, lease.InputVersionID)
	if !ok {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	artifact, err := executor.config.Receipts.Get(ctx, locator)
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageRetryable
	}
	if !exactRuntimeReceiptArtifact(artifact, locator) {
		clear(artifact.Body)
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	objectReference, err := executor.config.Receipts.ObjectReference(artifact.Locator)
	if err != nil || objectReference != lease.InputReference {
		clear(artifact.Body)
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	correlationReceipt, err := runtimecorrelation.DecodeReceipt(artifact.Body)
	clear(artifact.Body)
	if err != nil || correlationReceipt.Scope != lease.Scope || correlationReceipt.BatchID != lease.BatchID || correlationReceipt.Generation != lease.Generation || correlationReceipt.EffectDigest != lease.InputDigest || correlationReceipt.ImplementationVersion != "runtime-correlation-v1" {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	archiveLease := lease
	archiveLease.Stage = runtimeevent.RuntimeStageIndex
	archiveLease.ImplementationVersion = "runtime-index-v1"
	archiveLease.InputReference = correlationReceipt.ArchiveReference
	archiveLease.InputVersionID = correlationReceipt.ArchiveVersionID
	archiveLease.InputDigest = correlationReceipt.ArchiveDigest
	body, err := executor.config.Reader.Read(ctx, archiveLease)
	if err != nil {
		return runtimeStageEffect{}, err
	}
	defer clear(body)
	if sha256.Sum256(body) != correlationReceipt.ArchiveDigest {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	projectionBody := bytes.Clone(body)
	defer clear(projectionBody)
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveReference: correlationReceipt.ArchiveReference, ArchiveVersionID: correlationReceipt.ArchiveVersionID, ArchiveDigest: correlationReceipt.ArchiveDigest, Body: projectionBody, Correlations: correlationReceipt.Results})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	snapshot, nodeIDs, edgeIDs, ok := runtimeProjectionRiskGraphSnapshot(lease, projected)
	if !ok {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	applied, err := executor.config.Graph.ApplySnapshot(ctx, snapshot)
	if err != nil {
		return runtimeStageEffect{}, runtimeCorrelationGraphError(ctx, err)
	}
	if applied.SnapshotID != snapshot.SnapshotID || applied.Source != snapshot.Source || applied.Generation != snapshot.Generation || applied.InputDigest != snapshot.InputDigest || applied.ContentDigest == ([sha256.Size]byte{}) || !slices.Equal(applied.NodeIDs, nodeIDs) || !slices.Equal(applied.EdgeIDs, edgeIDs) || applied.RemovedNodes < 0 || applied.RemovedEdges < 0 {
		return runtimeStageEffect{}, errWorkerExecution
	}
	receiptBody, receiptDigest, reference, err := runtimeprojection.EncodeReceipt(runtimeprojection.Receipt{ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: correlationReceipt.ArchiveReference, ArchiveVersionID: correlationReceipt.ArchiveVersionID, ArchiveDigest: correlationReceipt.ArchiveDigest, EffectDigest: projected.ContentDigest, Items: projected.Items})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	stored, err := executor.config.Receipts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(receiptBody)})
	if err != nil || stored.Scope != lease.Scope || stored.Reference != reference || stored.VersionID == "" || stored.MediaType != "application/json" || stored.Size != int64(len(receiptBody)) || stored.SHA256 != receiptDigest || !bytes.Equal(stored.Body, receiptBody) {
		return runtimeStageEffect{}, errWorkerExecution
	}
	resultReference, err := executor.config.Receipts.ObjectReference(stored.Locator)
	if err != nil || resultReference == "" {
		return runtimeStageEffect{}, errWorkerExecution
	}
	return runtimeStageEffect{EffectDigest: projected.ContentDigest, ResultReference: resultReference, ResultVersionID: stored.VersionID, ResultDigest: receiptDigest}, nil
}

func runtimeProjectionRiskGraphSnapshot(lease runtimeevent.StageLease, projected runtimeprojection.ProjectedBatch) (graphstore.CompleteSnapshot, []string, []string, bool) {
	if !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageProject) || projected.BatchID != lease.BatchID || projected.Generation != lease.Generation || projected.ContentDigest == ([sha256.Size]byte{}) || len(projected.Items) < 1 || len(projected.Items) > 1000 {
		return graphstore.CompleteSnapshot{}, nil, nil, false
	}
	nodeKinds := make(map[domain.ProductID]string, len(projected.Items)*2)
	edges := make([]graphstore.Edge, 0, len(projected.Items))
	addNode := func(identifier domain.ProductID, kind string) bool {
		if identifier.IsZero() {
			return false
		}
		if existing, present := nodeKinds[identifier]; present && existing != kind {
			return false
		}
		nodeKinds[identifier] = kind
		return true
	}
	for _, item := range projected.Items {
		riskID, err := runtimeRiskGraphNodeID(lease.Scope, lease.BatchID, item.ID)
		if err != nil || !addNode(riskID, "runtime_risk") || !addNode(item.EventID, "runtime_event") {
			return graphstore.CompleteSnapshot{}, nil, nil, false
		}
		edgeID, err := runtimeCorrelationGraphEdgeID(lease.Scope, lease.BatchID, "evidenced_by", riskID, item.EventID)
		if err != nil {
			return graphstore.CompleteSnapshot{}, nil, nil, false
		}
		edges = append(edges, graphstore.Edge{Scope: lease.Scope, EdgeID: edgeID, Kind: "evidenced_by", SourceID: riskID, TargetID: item.EventID})
	}
	nodes := make([]graphstore.Node, 0, len(nodeKinds))
	for identifier, kind := range nodeKinds {
		nodes = append(nodes, graphstore.Node{Scope: lease.Scope, NodeID: identifier, Kind: kind})
	}
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].NodeID.String() < nodes[right].NodeID.String() })
	sort.Slice(edges, func(left, right int) bool { return edges[left].EdgeID.String() < edges[right].EdgeID.String() })
	nodeIDs := make([]string, len(nodes))
	for index, node := range nodes {
		nodeIDs[index] = node.NodeID.String()
	}
	edgeIDs := make([]string, len(edges))
	for index, edge := range edges {
		edgeIDs[index] = edge.EdgeID.String()
	}
	return graphstore.CompleteSnapshot{Scope: lease.Scope, IntegrationID: lease.BatchID, Source: "runtime_risk", SnapshotID: lease.BatchID, Generation: lease.Generation, InputDigest: projected.ContentDigest, Projection: graphstore.Projection{Nodes: nodes, Edges: edges}}, nodeIDs, edgeIDs, true
}

func runtimeRiskGraphNodeID(scope domain.Scope, batchID domain.ProductID, riskID string) (domain.ProductID, error) {
	digest := sha256.Sum256([]byte("zasp.runtime-risk.graph-node.v1\x00" + scope.OrganizationID().String() + "\x00" + scope.WorkspaceID().String() + "\x00" + scope.EnvironmentID().String() + "\x00" + batchID.String() + "\x00" + riskID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	encoded := hex.EncodeToString(digest[:16])
	return domain.ParseProductID(fmt.Sprintf("pid_%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]))
}

var _ runtimeStageExecutor = (*runtimeProjectionExecutor)(nil)
