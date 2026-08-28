package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

func TestRuntimeProjectionExecutorPersistsExactSourceOwnedEvidence(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageProject)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	correlated, err := runtimecorrelation.Correlate(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: archiveDigest, Body: body, Candidates: trustedRuntimeCandidates(mustArchivedBatch(t, lease, body))})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputDigest = correlated.ContentDigest
	correlationBody, correlationObjectDigest, correlationReference, err := runtimecorrelation.EncodeReceipt(runtimecorrelation.Receipt{ImplementationVersion: "runtime-correlation-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-version", InputDigest: sha256.Sum256([]byte("index")), ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: correlated.ContentDigest, Results: correlated.Results})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputReference = runtimeTestReceiptReference(lease, correlationReference.String())
	lease.InputVersionID = "correlation-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: correlationReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: correlationBody, Size: int64(len(correlationBody)), SHA256: correlationObjectDigest}, outputReference: runtimeTestReceiptReference(lease, mustProductID(t, "pid_00000093-0000-4000-8000-000000000093").String())}
	reader := &runtimeArchivedReaderStub{body: body}
	graph := &runtimeCorrelationGraphStoreStub{}
	executor, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: reader, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil || artifacts.getCalls != 1 || artifacts.putCalls != 1 || reader.calls != 1 || graph.calls != 1 {
		t.Fatalf("effect=%#v err=%v get=%d put=%d read=%d graph=%d", effect, err, artifacts.getCalls, artifacts.putCalls, reader.calls, graph.calls)
	}
	receipt, err := runtimeprojection.DecodeReceipt(artifacts.put.Body)
	if err != nil || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.InputReference != lease.InputReference || receipt.InputVersionID != lease.InputVersionID || receipt.InputDigest != correlated.ContentDigest || receipt.ArchiveDigest != archiveDigest || len(receipt.Items) != 1 || receipt.Items[0].AgentID.IsZero() || receipt.Items[0].SessionID.IsZero() || receipt.Items[0].Title != "Agent tool invocation" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if effect.EffectDigest != receipt.EffectDigest || effect.ResultReference != artifacts.outputReference || effect.ResultVersionID != artifacts.output.VersionID || effect.ResultDigest != artifacts.output.SHA256 {
		t.Fatalf("effect=%#v output=%#v", effect, artifacts.output)
	}
	if graph.snapshot.Scope != lease.Scope || graph.snapshot.IntegrationID != lease.BatchID || graph.snapshot.SnapshotID != lease.BatchID || graph.snapshot.Source != "runtime_risk" || graph.snapshot.Generation != lease.Generation || graph.snapshot.InputDigest != receipt.EffectDigest || len(graph.snapshot.Projection.Nodes) != 2 || len(graph.snapshot.Projection.Edges) != 1 {
		t.Fatalf("risk graph snapshot=%#v", graph.snapshot)
	}
	replayed, replayErr := executor.Execute(context.Background(), lease)
	if replayErr != nil || replayed != effect || graph.calls != 2 || graph.mutations != 1 || artifacts.putCalls != 2 {
		t.Fatalf("replayed=%#v err=%v graph=%d mutations=%d put=%d", replayed, replayErr, graph.calls, graph.mutations, artifacts.putCalls)
	}
}

func TestRuntimeProjectionRiskGraphSnapshotAcceptsExactMaximum(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageProject)
	items := make([]runtimeprojection.Item, 1000)
	for index := range items {
		items[index] = runtimeprojection.Item{ID: fmt.Sprintf("rsk_%064x", index+1), EventID: runtimeCorrelationBoundaryID(t, index+1)}
	}
	projected := runtimeprojection.ProjectedBatch{BatchID: lease.BatchID, Generation: lease.Generation, ContentDigest: sha256.Sum256([]byte("maximum-runtime-risk")), Items: items}
	snapshot, nodes, edges, ok := runtimeProjectionRiskGraphSnapshot(lease, projected)
	if !ok || len(snapshot.Projection.Nodes) != 2000 || len(snapshot.Projection.Edges) != 1000 || len(nodes) != 2000 || len(edges) != 1000 {
		t.Fatalf("ok=%t nodes=%d/%d edges=%d/%d", ok, len(snapshot.Projection.Nodes), len(nodes), len(snapshot.Projection.Edges), len(edges))
	}
	projected.Items = append(projected.Items, runtimeprojection.Item{ID: fmt.Sprintf("rsk_%064x", 1001), EventID: runtimeCorrelationBoundaryID(t, 1001)})
	if _, _, _, accepted := runtimeProjectionRiskGraphSnapshot(lease, projected); accepted {
		t.Fatal("accepted more than 1000 risk projection items")
	}
}

func TestRuntimeProjectionExecutorRejectsCorrelationDriftBeforeArchiveRead(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageProject)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	correlated, err := runtimecorrelation.Correlate(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: archiveDigest, Body: body, Candidates: trustedRuntimeCandidates(mustArchivedBatch(t, lease, body))})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputDigest = sha256.Sum256([]byte("drift"))
	correlationBody, correlationObjectDigest, correlationReference, _ := runtimecorrelation.EncodeReceipt(runtimecorrelation.Receipt{ImplementationVersion: "runtime-correlation-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-version", InputDigest: sha256.Sum256([]byte("index")), ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: correlated.ContentDigest, Results: correlated.Results})
	lease.InputReference = runtimeTestReceiptReference(lease, correlationReference.String())
	lease.InputVersionID = "correlation-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: correlationReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: correlationBody, Size: int64(len(correlationBody)), SHA256: correlationObjectDigest}}
	reader := &runtimeArchivedReaderStub{body: body}
	executor, _ := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: reader, Receipts: artifacts, Graph: &runtimeCorrelationGraphStoreStub{}, ImplementationVersion: "runtime-projection-v1"})
	if effect, err := executor.Execute(context.Background(), lease); !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || reader.calls != 0 || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v read=%d put=%d", effect, err, reader.calls, artifacts.putCalls)
	}
}

func TestRuntimeProjectionExecutorRequiresDurableRiskGraphBeforeReceipt(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageProject)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	correlated, err := runtimecorrelation.Correlate(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: archiveDigest, Body: body, Candidates: trustedRuntimeCandidates(mustArchivedBatch(t, lease, body))})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputDigest = correlated.ContentDigest
	correlationBody, correlationObjectDigest, correlationReference, err := runtimecorrelation.EncodeReceipt(runtimecorrelation.Receipt{ImplementationVersion: "runtime-correlation-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-version", InputDigest: sha256.Sum256([]byte("index")), ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: correlated.ContentDigest, Results: correlated.Results})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputReference = runtimeTestReceiptReference(lease, correlationReference.String())
	lease.InputVersionID = "correlation-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: correlationReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: correlationBody, Size: int64(len(correlationBody)), SHA256: correlationObjectDigest}}
	graph := &runtimeCorrelationGraphStoreStub{err: graphstore.ErrSnapshotRetryable}
	executor, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: &runtimeArchivedReaderStub{body: body}, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if effect, executeErr := executor.Execute(context.Background(), lease); !errors.Is(executeErr, errRuntimeStageRetryable) || effect != (runtimeStageEffect{}) || graph.calls != 1 || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v graph=%d put=%d", effect, executeErr, graph.calls, artifacts.putCalls)
	}
}

func mustArchivedBatch(t *testing.T, lease runtimeevent.StageLease, body []byte) runtimeevent.ArchivedBatch {
	t.Helper()
	batch, err := runtimeevent.DecodeArchivedBatch(lease.Scope, body)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func runtimeTestReceiptReference(lease runtimeevent.StageLease, reference string) string {
	return "s3://zasp-evidence/organizations/" + lease.Scope.OrganizationID().String() + "/workspaces/" + lease.Scope.WorkspaceID().String() + "/environments/" + lease.Scope.EnvironmentID().String() + "/artifacts/" + reference
}
