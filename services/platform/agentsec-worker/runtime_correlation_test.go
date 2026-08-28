package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeCorrelationExecutorConsumesIndexReceiptAndPersistsExactAttribution(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	indexDigest := sha256.Sum256([]byte("index-effect"))
	lease.InputDigest = indexDigest
	indexBody, indexObjectDigest, indexReference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "raw-version", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: indexDigest, ItemIDs: []string{"evt_" + repeatRuntimeHex("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputReference = "s3://zasp-evidence/organizations/" + lease.Scope.OrganizationID().String() + "/workspaces/" + lease.Scope.WorkspaceID().String() + "/environments/" + lease.Scope.EnvironmentID().String() + "/artifacts/" + indexReference.String()
	lease.InputVersionID = "index-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: indexReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: indexBody, Size: int64(len(indexBody)), SHA256: indexObjectDigest}, outputReference: "s3://zasp-evidence/organizations/" + lease.Scope.OrganizationID().String() + "/workspaces/" + lease.Scope.WorkspaceID().String() + "/environments/" + lease.Scope.EnvironmentID().String() + "/artifacts/" + mustProductID(t, "pid_00000092-0000-4000-8000-000000000092").String()}
	reader := &runtimeArchivedReaderStub{body: body}
	graph := &runtimeCorrelationGraphStoreStub{}
	executor, err := newRuntimeCorrelationExecutor(runtimeCorrelationExecutorConfig{Reader: reader, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-correlation-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil || artifacts.getCalls != 1 || artifacts.putCalls != 1 || reader.calls != 1 || graph.calls != 1 {
		t.Fatalf("effect=%#v err=%v get=%d put=%d read=%d graph=%d", effect, err, artifacts.getCalls, artifacts.putCalls, reader.calls, graph.calls)
	}
	receipt, err := runtimecorrelation.DecodeReceipt(artifacts.put.Body)
	if err != nil || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.InputReference != lease.InputReference || receipt.InputVersionID != lease.InputVersionID || receipt.InputDigest != indexDigest || receipt.ArchiveReference != "s3://zasp-evidence/runtime/v15/raw.json" || receipt.ArchiveVersionID != "raw-version" || receipt.ArchiveDigest != archiveDigest || len(receipt.Results) != 1 || receipt.Results[0].Confidence.String() != "exact" || receipt.Results[0].AgentID.IsZero() || receipt.Results[0].SessionID.IsZero() {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if effect.EffectDigest != receipt.EffectDigest || effect.ResultReference != artifacts.outputReference || effect.ResultVersionID != artifacts.output.VersionID || effect.ResultDigest != artifacts.output.SHA256 {
		t.Fatalf("effect=%#v output=%#v", effect, artifacts.output)
	}
	if graph.snapshot.Scope != lease.Scope || graph.snapshot.IntegrationID != lease.BatchID || graph.snapshot.SnapshotID != lease.BatchID || graph.snapshot.Source != "runtime_correlation" || graph.snapshot.Generation != lease.Generation || graph.snapshot.InputDigest != receipt.EffectDigest || len(graph.snapshot.Projection.Nodes) != 3 || len(graph.snapshot.Projection.Edges) != 2 {
		t.Fatalf("graph snapshot=%#v", graph.snapshot)
	}
}

func TestRuntimeCorrelationExecutorRejectsReceiptDriftBeforeArchiveRead(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	indexDigest := sha256.Sum256([]byte("index-effect"))
	lease.InputDigest = indexDigest
	indexBody, indexObjectDigest, indexReference, _ := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "raw-version", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: sha256.Sum256([]byte("drift")), ItemIDs: []string{"evt_" + repeatRuntimeHex("a", 64)}})
	lease.InputReference = "s3://zasp-evidence/organizations/" + lease.Scope.OrganizationID().String() + "/workspaces/" + lease.Scope.WorkspaceID().String() + "/environments/" + lease.Scope.EnvironmentID().String() + "/artifacts/" + indexReference.String()
	lease.InputVersionID = "index-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: indexReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: indexBody, Size: int64(len(indexBody)), SHA256: indexObjectDigest}}
	reader := &runtimeArchivedReaderStub{body: body}
	graph := &runtimeCorrelationGraphStoreStub{}
	executor, _ := newRuntimeCorrelationExecutor(runtimeCorrelationExecutorConfig{Reader: reader, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-correlation-v1"})
	if effect, err := executor.Execute(context.Background(), lease); !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || reader.calls != 0 || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v read=%d put=%d", effect, err, reader.calls, artifacts.putCalls)
	}
}

func TestRuntimeCorrelationExecutorRequiresDurableGraphBeforeReceipt(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	indexDigest := sha256.Sum256([]byte("index-effect"))
	lease.InputDigest = indexDigest
	indexBody, indexObjectDigest, indexReference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "raw-version", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: indexDigest, ItemIDs: []string{"evt_" + repeatRuntimeHex("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputReference = runtimeTestReceiptReference(lease, indexReference.String())
	lease.InputVersionID = "index-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: indexReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: indexBody, Size: int64(len(indexBody)), SHA256: indexObjectDigest}}
	graph := &runtimeCorrelationGraphStoreStub{err: graphstore.ErrSnapshotRetryable}
	executor, err := newRuntimeCorrelationExecutor(runtimeCorrelationExecutorConfig{Reader: &runtimeArchivedReaderStub{body: body}, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-correlation-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if effect, executeErr := executor.Execute(context.Background(), lease); !errors.Is(executeErr, errRuntimeStageRetryable) || effect != (runtimeStageEffect{}) || graph.calls != 1 || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v graph=%d put=%d", effect, executeErr, graph.calls, artifacts.putCalls)
	}
}

func TestRuntimeCorrelationExecutorReplaysGraphWithoutDuplicateAfterReceiptFailure(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	indexDigest := sha256.Sum256([]byte("index-effect"))
	lease.InputDigest = indexDigest
	indexBody, indexObjectDigest, indexReference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "raw-version", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: indexDigest, ItemIDs: []string{"evt_" + repeatRuntimeHex("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputReference = runtimeTestReceiptReference(lease, indexReference.String())
	lease.InputVersionID = "index-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: indexReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: indexBody, Size: int64(len(indexBody)), SHA256: indexObjectDigest}, outputReference: runtimeTestReceiptReference(lease, mustProductID(t, "pid_00000094-0000-4000-8000-000000000094").String()), putErr: artifactstore.ErrPut}
	graph := &runtimeCorrelationGraphStoreStub{}
	executor, err := newRuntimeCorrelationExecutor(runtimeCorrelationExecutorConfig{Reader: &runtimeArchivedReaderStub{body: body}, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-correlation-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if effect, executeErr := executor.Execute(context.Background(), lease); !errors.Is(executeErr, errWorkerExecution) || effect != (runtimeStageEffect{}) || graph.calls != 1 || graph.mutations != 1 || artifacts.putCalls != 1 {
		t.Fatalf("first effect=%#v err=%v graph=%d mutations=%d put=%d", effect, executeErr, graph.calls, graph.mutations, artifacts.putCalls)
	}
	artifacts.putErr = nil
	if effect, executeErr := executor.Execute(context.Background(), lease); executeErr != nil || effect.EffectDigest == ([sha256.Size]byte{}) || graph.calls != 2 || graph.mutations != 1 || artifacts.putCalls != 2 {
		t.Fatalf("replay effect=%#v err=%v graph=%d mutations=%d put=%d", effect, executeErr, graph.calls, graph.mutations, artifacts.putCalls)
	}
}

func TestRuntimeCorrelationGraphSnapshotAcceptsExactMaximumAttribution(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	results := make([]runtimecorrelation.Result, 1000)
	for index := range results {
		results[index] = runtimecorrelation.Result{
			EventID:    runtimeCorrelationBoundaryID(t, index+1),
			SessionID:  runtimeCorrelationBoundaryID(t, index+1001),
			AgentID:    runtimeCorrelationBoundaryID(t, index+2001),
			Confidence: domain.EvidenceConfidenceExact,
		}
	}
	correlated := runtimecorrelation.CorrelatedBatch{BatchID: lease.BatchID, Generation: lease.Generation, ContentDigest: sha256.Sum256([]byte("maximum-runtime-correlation")), Results: results}
	snapshot, nodes, edges, ok := runtimeCorrelationGraphSnapshot(lease, correlated)
	if !ok || len(snapshot.Projection.Nodes) != 3000 || len(snapshot.Projection.Edges) != 2000 || len(nodes) != 3000 || len(edges) != 2000 {
		t.Fatalf("ok=%t nodes=%d/%d edges=%d/%d", ok, len(snapshot.Projection.Nodes), len(nodes), len(snapshot.Projection.Edges), len(edges))
	}
	correlated.Results = append(correlated.Results, runtimecorrelation.Result{EventID: runtimeCorrelationBoundaryID(t, 3001), Confidence: domain.EvidenceConfidenceUnattributed})
	if _, _, _, accepted := runtimeCorrelationGraphSnapshot(lease, correlated); accepted {
		t.Fatal("accepted more than 1000 correlation results")
	}
}

func runtimeCorrelationBoundaryID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	return workerID(t, fmt.Sprintf("pid_%08x-0000-4000-8000-%012x", value, value))
}

type runtimeCorrelationGraphStoreStub struct {
	calls     int
	mutations int
	snapshot  graphstore.CompleteSnapshot
	err       error
}

func (stub *runtimeCorrelationGraphStoreStub) ApplySnapshot(_ context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
	stub.calls++
	if stub.err != nil {
		return graphstore.SnapshotApplyResult{}, stub.err
	}
	replayed := stub.snapshot.Scope.Validate() == nil
	if replayed && !reflect.DeepEqual(stub.snapshot, snapshot) {
		return graphstore.SnapshotApplyResult{}, graphstore.ErrSnapshotDrift
	}
	if !replayed {
		stub.snapshot = snapshot
		stub.mutations++
	}
	nodes := make([]string, len(snapshot.Projection.Nodes))
	for index, node := range snapshot.Projection.Nodes {
		nodes[index] = node.NodeID.String()
	}
	edges := make([]string, len(snapshot.Projection.Edges))
	for index, edge := range snapshot.Projection.Edges {
		edges[index] = edge.EdgeID.String()
	}
	return graphstore.SnapshotApplyResult{SnapshotID: snapshot.SnapshotID, Source: snapshot.Source, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, ContentDigest: sha256.Sum256([]byte("graph-content")), NodeIDs: nodes, EdgeIDs: edges, Replayed: replayed}, nil
}

type runtimeCorrelationArtifactStoreStub struct {
	inputReference  string
	outputReference string
	input           artifactstore.Artifact
	output          artifactstore.Artifact
	put             artifactstore.PutRequest
	getCalls        int
	putCalls        int
	putErr          error
}

func (stub *runtimeCorrelationArtifactStoreStub) Get(_ context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	stub.getCalls++
	if locator != stub.input.Locator {
		return artifactstore.Artifact{}, artifactstore.ErrGet
	}
	result := stub.input
	result.Body = bytes.Clone(result.Body)
	return result, nil
}
func (stub *runtimeCorrelationArtifactStoreStub) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	stub.putCalls++
	if stub.putErr != nil {
		return artifactstore.Artifact{}, stub.putErr
	}
	stub.put = request
	stub.put.Body = bytes.Clone(request.Body)
	stub.output = artifactstore.Artifact{Locator: request.Locator, MediaType: request.MediaType, Body: bytes.Clone(request.Body), Size: int64(len(request.Body)), SHA256: sha256.Sum256(request.Body)}
	stub.output.VersionID = "correlation-receipt-version"
	return stub.output, nil
}
func (*runtimeCorrelationArtifactStoreStub) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}
func (stub *runtimeCorrelationArtifactStoreStub) ObjectReference(locator artifactstore.Locator) (string, error) {
	if locator == stub.input.Locator {
		return stub.inputReference, nil
	}
	if locator == stub.output.Locator {
		return stub.outputReference, nil
	}
	return "", artifactstore.ErrReference
}

func runtimeOTLPIndexBody() []byte {
	return []byte(`{"source":"otlp","events":[{"event_id":"","class":"","action":"","workload_id":"","event_time":"2026-08-20T12:00:00.000Z","evidence_id":"pid_79000001-0000-4000-8000-000000000001","attributes":{"event.id":"event-1","event.class":"tool","event.action":"invoke","agent.id":"pid_79000002-0000-4000-8000-000000000002","session.id":"pid_79000003-0000-4000-8000-000000000003","task.id":"task-a","tool.id":"tool-a","sandbox.id":"sandbox-a","trace.id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","span.id":"bbbbbbbbbbbbbbbb"},"content":{}}]}`)
}

var _ artifactstore.ObjectReferencingArtifactStore = (*runtimeCorrelationArtifactStoreStub)(nil)
