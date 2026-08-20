package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

func TestRuntimeCompleteExecutorSealsExactProjectionReceipt(t *testing.T) {
	lease, artifacts, projectionReceipt := runtimeCompleteFixture(t)
	executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil || artifacts.getCalls != 1 || artifacts.putCalls != 1 {
		t.Fatalf("effect=%#v err=%v get=%d put=%d", effect, err, artifacts.getCalls, artifacts.putCalls)
	}
	receipt, err := runtimeevent.DecodeStageReceipt(artifacts.put.Body)
	if err != nil || receipt.Stage != runtimeevent.RuntimeStageComplete || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.InputDigest != lease.InputDigest || receipt.ArchiveDigest != projectionReceipt.ArchiveDigest || receipt.EffectDigest != projectionReceipt.EffectDigest || len(receipt.ItemIDs) != 1 || receipt.ItemIDs[0] != projectionReceipt.Items[0].ID {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if effect.EffectDigest != receipt.EffectDigest || effect.ResultReference != artifacts.outputReference || effect.ResultVersionID != artifacts.output.VersionID || effect.ResultDigest != artifacts.output.SHA256 {
		t.Fatalf("effect=%#v output=%#v", effect, artifacts.output)
	}
}

func TestRuntimeCompleteExecutorRejectsProjectionDriftBeforeTerminalWrite(t *testing.T) {
	lease, artifacts, _ := runtimeCompleteFixture(t)
	lease.InputDigest = sha256.Sum256([]byte("drift"))
	executor, _ := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v1"})
	if effect, err := executor.Execute(context.Background(), lease); !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v put=%d", effect, err, artifacts.putCalls)
	}
}

func runtimeCompleteFixture(t *testing.T) (runtimeevent.StageLease, *runtimeCorrelationArtifactStoreStub, runtimeprojection.Receipt) {
	t.Helper()
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageComplete)
	body := runtimeOTLPIndexBody()
	archiveDigest := sha256.Sum256(body)
	batch := mustArchivedBatch(t, lease, body)
	correlated, err := runtimecorrelation.Correlate(runtimecorrelation.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveDigest: archiveDigest, Body: body, Candidates: trustedRuntimeCandidates(batch)})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, Body: body, Correlations: correlated.Results})
	if err != nil {
		t.Fatal(err)
	}
	projectionReceipt := runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-version", InputDigest: correlated.ContentDigest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: projected.ContentDigest, Items: projected.Items}
	receiptBody, objectDigest, reference, err := runtimeprojection.EncodeReceipt(projectionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	lease.InputDigest = projected.ContentDigest
	lease.InputReference = runtimeTestReceiptReference(lease, reference.String())
	lease.InputVersionID = "projection-receipt-version"
	outputID, err := domain.NewEvidenceRef(mustProductID(t, "pid_00000094-0000-4000-8000-000000000094"))
	if err != nil {
		t.Fatal(err)
	}
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: reference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: receiptBody, Size: int64(len(receiptBody)), SHA256: objectDigest}, outputReference: runtimeTestReceiptReference(lease, outputID.String())}
	return lease, artifacts, projectionReceipt
}
