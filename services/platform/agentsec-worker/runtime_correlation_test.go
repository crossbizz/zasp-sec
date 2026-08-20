package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
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
	executor, err := newRuntimeCorrelationExecutor(runtimeCorrelationExecutorConfig{Reader: reader, Receipts: artifacts, ImplementationVersion: "runtime-correlate-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil || artifacts.getCalls != 1 || artifacts.putCalls != 1 || reader.calls != 1 {
		t.Fatalf("effect=%#v err=%v get=%d put=%d read=%d", effect, err, artifacts.getCalls, artifacts.putCalls, reader.calls)
	}
	receipt, err := runtimecorrelation.DecodeReceipt(artifacts.put.Body)
	if err != nil || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.InputReference != lease.InputReference || receipt.InputVersionID != lease.InputVersionID || receipt.InputDigest != indexDigest || receipt.ArchiveReference != "s3://zasp-evidence/runtime/v15/raw.json" || receipt.ArchiveVersionID != "raw-version" || receipt.ArchiveDigest != archiveDigest || len(receipt.Results) != 1 || receipt.Results[0].Confidence.String() != "exact" || receipt.Results[0].AgentID.IsZero() || receipt.Results[0].SessionID.IsZero() {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if effect.EffectDigest != receipt.EffectDigest || effect.ResultReference != artifacts.outputReference || effect.ResultVersionID != artifacts.output.VersionID || effect.ResultDigest != artifacts.output.SHA256 {
		t.Fatalf("effect=%#v output=%#v", effect, artifacts.output)
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
	executor, _ := newRuntimeCorrelationExecutor(runtimeCorrelationExecutorConfig{Reader: reader, Receipts: artifacts, ImplementationVersion: "runtime-correlate-v1"})
	if effect, err := executor.Execute(context.Background(), lease); !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || reader.calls != 0 || artifacts.putCalls != 0 {
		t.Fatalf("effect=%#v err=%v read=%d put=%d", effect, err, reader.calls, artifacts.putCalls)
	}
}

type runtimeCorrelationArtifactStoreStub struct {
	inputReference  string
	outputReference string
	input           artifactstore.Artifact
	output          artifactstore.Artifact
	put             artifactstore.PutRequest
	getCalls        int
	putCalls        int
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
