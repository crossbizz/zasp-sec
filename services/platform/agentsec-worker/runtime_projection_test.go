package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
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
	executor, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: reader, Receipts: artifacts, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil || artifacts.getCalls != 1 || artifacts.putCalls != 1 || reader.calls != 1 {
		t.Fatalf("effect=%#v err=%v get=%d put=%d read=%d", effect, err, artifacts.getCalls, artifacts.putCalls, reader.calls)
	}
	receipt, err := runtimeprojection.DecodeReceipt(artifacts.put.Body)
	if err != nil || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.InputReference != lease.InputReference || receipt.InputVersionID != lease.InputVersionID || receipt.InputDigest != correlated.ContentDigest || receipt.ArchiveDigest != archiveDigest || len(receipt.Items) != 1 || receipt.Items[0].AgentID.IsZero() || receipt.Items[0].SessionID.IsZero() || receipt.Items[0].Title != "Agent tool invocation" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if effect.EffectDigest != receipt.EffectDigest || effect.ResultReference != artifacts.outputReference || effect.ResultVersionID != artifacts.output.VersionID || effect.ResultDigest != artifacts.output.SHA256 {
		t.Fatalf("effect=%#v output=%#v", effect, artifacts.output)
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
	executor, _ := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: reader, Receipts: artifacts, ImplementationVersion: "runtime-projection-v1"})
	if effect, err := executor.Execute(context.Background(), lease); !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || reader.calls != 0 || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v read=%d put=%d", effect, err, reader.calls, artifacts.putCalls)
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
