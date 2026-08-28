package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type runtimeCorrelationGraphStore interface {
	ApplySnapshot(context.Context, graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error)
}

type runtimeCorrelationExecutorConfig struct {
	Reader                runtimeArchivedBatchReader
	Receipts              artifactstore.ObjectReferencingArtifactStore
	Graph                 runtimeCorrelationGraphStore
	ImplementationVersion string
}

type runtimeCorrelationExecutor struct {
	config runtimeCorrelationExecutorConfig
}

func newRuntimeCorrelationExecutor(config runtimeCorrelationExecutorConfig) (*runtimeCorrelationExecutor, error) {
	if nilWorkerDependency(config.Reader) || nilWorkerDependency(config.Receipts) || nilWorkerDependency(config.Graph) || config.ImplementationVersion != "runtime-correlation-v1" {
		return nil, errRuntimeUnavailable
	}
	return &runtimeCorrelationExecutor{config: config}, nil
}

func (executor *runtimeCorrelationExecutor) Execute(ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	if executor == nil || ctx == nil || ctx.Err() != nil || !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageCorrelate) || lease.ImplementationVersion != executor.config.ImplementationVersion {
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
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	objectReference, err := executor.config.Receipts.ObjectReference(artifact.Locator)
	if err != nil || objectReference != lease.InputReference {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	indexReceipt, err := runtimeevent.DecodeStageReceipt(artifact.Body)
	clear(artifact.Body)
	if err != nil || indexReceipt.Stage != runtimeevent.RuntimeStageIndex || indexReceipt.Scope != lease.Scope || indexReceipt.BatchID != lease.BatchID || indexReceipt.Generation != lease.Generation || indexReceipt.EffectDigest != lease.InputDigest || indexReceipt.ImplementationVersion != "runtime-index-v1" {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	archiveLease := lease
	archiveLease.Stage = runtimeevent.RuntimeStageIndex
	archiveLease.ImplementationVersion = indexReceipt.ImplementationVersion
	archiveLease.InputReference = indexReceipt.ArchiveReference
	archiveLease.InputVersionID = indexReceipt.ArchiveVersionID
	archiveLease.InputDigest = indexReceipt.ArchiveDigest
	body, err := executor.config.Reader.Read(ctx, archiveLease)
	if err != nil {
		return runtimeStageEffect{}, err
	}
	defer clear(body)
	if sha256.Sum256(body) != indexReceipt.ArchiveDigest {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	decoded, err := runtimeevent.DecodeArchivedBatch(lease.Scope, body)
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	candidates := trustedRuntimeCandidates(decoded)
	correlationBody := bytes.Clone(body)
	defer clear(correlationBody)
	correlated, err := runtimecorrelation.Correlate(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: indexReceipt.ArchiveDigest, Body: correlationBody, Candidates: candidates})
	if err != nil {
		return runtimeStageEffect{}, errRuntimeStageMalformed
	}
	snapshot, nodeIDs, edgeIDs, ok := runtimeCorrelationGraphSnapshot(lease, correlated)
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
	receiptBody, receiptDigest, reference, err := runtimecorrelation.EncodeReceipt(runtimecorrelation.Receipt{ImplementationVersion: lease.ImplementationVersion, Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: lease.InputReference, InputVersionID: lease.InputVersionID, InputDigest: lease.InputDigest, ArchiveReference: indexReceipt.ArchiveReference, ArchiveVersionID: indexReceipt.ArchiveVersionID, ArchiveDigest: indexReceipt.ArchiveDigest, EffectDigest: correlated.ContentDigest, Results: correlated.Results})
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
	return runtimeStageEffect{EffectDigest: correlated.ContentDigest, ResultReference: resultReference, ResultVersionID: stored.VersionID, ResultDigest: receiptDigest}, nil
}

func runtimeCorrelationGraphSnapshot(lease runtimeevent.StageLease, correlated runtimecorrelation.CorrelatedBatch) (graphstore.CompleteSnapshot, []string, []string, bool) {
	if !exactRuntimeStageLease(lease, runtimeevent.RuntimeStageCorrelate) || correlated.BatchID != lease.BatchID || correlated.Generation != lease.Generation || correlated.ContentDigest == ([sha256.Size]byte{}) || len(correlated.Results) < 1 || len(correlated.Results) > 1000 {
		return graphstore.CompleteSnapshot{}, nil, nil, false
	}
	nodeKinds := make(map[domain.ProductID]string, len(correlated.Results)*3)
	edges := make(map[string]graphstore.Edge, len(correlated.Results)*2)
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
	addEdge := func(kind string, source, target domain.ProductID) bool {
		semantic := kind + "\x00" + source.String() + "\x00" + target.String()
		if _, present := edges[semantic]; present {
			return true
		}
		identifier, err := runtimeCorrelationGraphEdgeID(lease.Scope, lease.BatchID, kind, source, target)
		if err != nil {
			return false
		}
		edges[semantic] = graphstore.Edge{Scope: lease.Scope, EdgeID: identifier, Kind: kind, SourceID: source, TargetID: target}
		return true
	}
	for _, result := range correlated.Results {
		if !addNode(result.EventID, "runtime_event") {
			return graphstore.CompleteSnapshot{}, nil, nil, false
		}
		switch result.Confidence {
		case domain.EvidenceConfidenceExact, domain.EvidenceConfidenceStrong:
			if result.AgentID == result.SessionID || !addNode(result.SessionID, "runtime_session") || !addNode(result.AgentID, "runtime_agent") || !addEdge("observed_in", result.EventID, result.SessionID) || !addEdge("owned_by", result.SessionID, result.AgentID) {
				return graphstore.CompleteSnapshot{}, nil, nil, false
			}
		case domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed:
			if !result.AgentID.IsZero() || !result.SessionID.IsZero() {
				return graphstore.CompleteSnapshot{}, nil, nil, false
			}
		default:
			return graphstore.CompleteSnapshot{}, nil, nil, false
		}
	}
	nodes := make([]graphstore.Node, 0, len(nodeKinds))
	for identifier, kind := range nodeKinds {
		nodes = append(nodes, graphstore.Node{Scope: lease.Scope, NodeID: identifier, Kind: kind})
	}
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].NodeID.String() < nodes[right].NodeID.String() })
	edgeValues := make([]graphstore.Edge, 0, len(edges))
	for _, edge := range edges {
		edgeValues = append(edgeValues, edge)
	}
	sort.Slice(edgeValues, func(left, right int) bool {
		return edgeValues[left].EdgeID.String() < edgeValues[right].EdgeID.String()
	})
	nodeIDs := make([]string, len(nodes))
	for index, node := range nodes {
		nodeIDs[index] = node.NodeID.String()
	}
	edgeIDs := make([]string, len(edgeValues))
	for index, edge := range edgeValues {
		edgeIDs[index] = edge.EdgeID.String()
	}
	return graphstore.CompleteSnapshot{Scope: lease.Scope, IntegrationID: lease.BatchID, Source: "runtime_correlation", SnapshotID: lease.BatchID, Generation: lease.Generation, InputDigest: correlated.ContentDigest, Projection: graphstore.Projection{Nodes: nodes, Edges: edgeValues}}, nodeIDs, edgeIDs, true
}

func runtimeCorrelationGraphEdgeID(scope domain.Scope, batchID domain.ProductID, kind string, source, target domain.ProductID) (domain.ProductID, error) {
	digest := sha256.Sum256([]byte("zasp.runtime-correlation.graph-edge.v1\x00" + scope.OrganizationID().String() + "\x00" + scope.WorkspaceID().String() + "\x00" + scope.EnvironmentID().String() + "\x00" + batchID.String() + "\x00" + kind + "\x00" + source.String() + "\x00" + target.String()))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	encoded := hex.EncodeToString(digest[:16])
	return domain.ParseProductID(fmt.Sprintf("pid_%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]))
}

func runtimeCorrelationGraphError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return errRuntimeStageRetryable
	}
	switch {
	case errors.Is(err, graphstore.ErrSnapshotDenied):
		return errRuntimeStageDenied
	case errors.Is(err, graphstore.ErrSnapshotInput), errors.Is(err, graphstore.ErrSnapshotStale), errors.Is(err, graphstore.ErrSnapshotDrift):
		return errRuntimeStageMalformed
	case errors.Is(err, graphstore.ErrSnapshotCanceled), errors.Is(err, graphstore.ErrSnapshotRetryable), errors.Is(err, graphstore.ErrSnapshotUnknownOutcome), errors.Is(err, graphstore.ErrSnapshotUnavailable):
		return errRuntimeStageRetryable
	default:
		return errWorkerExecution
	}
}

func trustedRuntimeCandidates(batch runtimeevent.ArchivedBatch) []runtimeevent.Candidate {
	result := make([]runtimeevent.Candidate, 0, len(batch.Records))
	seen := map[string]struct{}{}
	for _, record := range batch.Records {
		if record.AgentID.IsZero() || record.SessionID.IsZero() {
			continue
		}
		candidate := runtimeevent.Candidate{AgentID: record.AgentID, SessionID: record.SessionID, SandboxID: record.SandboxID, ContainerID: record.ContainerID, CgroupID: record.CgroupID, ProcessID: record.ProcessID}
		key := candidate.AgentID.String() + "\x00" + candidate.SessionID.String() + "\x00" + candidate.SandboxID + "\x00" + candidate.ContainerID + "\x00" + candidate.CgroupID + "\x00" + candidate.ProcessID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func runtimeReceiptLocator(scope domain.Scope, objectReference, versionID string) (artifactstore.Locator, bool) {
	parsed, err := url.Parse(objectReference)
	if err != nil || parsed.String() != objectReference || parsed.Scheme != "s3" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return artifactstore.Locator{}, false
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "organizations" || parts[1] != scope.OrganizationID().String() || parts[2] != "workspaces" || parts[3] != scope.WorkspaceID().String() || parts[4] != "environments" || parts[5] != scope.EnvironmentID().String() || parts[6] != "artifacts" {
		return artifactstore.Locator{}, false
	}
	reference, err := domain.ParseEvidenceRef(parts[7])
	if err != nil || versionID == "" {
		return artifactstore.Locator{}, false
	}
	return artifactstore.Locator{Scope: scope, Reference: reference, VersionID: versionID}, true
}

func exactRuntimeReceiptArtifact(artifact artifactstore.Artifact, locator artifactstore.Locator) bool {
	return artifact.Locator == locator && artifact.MediaType == "application/json" && artifact.Size >= 1 && artifact.Size <= 1<<20 && artifact.Size == int64(len(artifact.Body)) && artifact.SHA256 == sha256.Sum256(artifact.Body)
}

var _ runtimeStageExecutor = (*runtimeCorrelationExecutor)(nil)
