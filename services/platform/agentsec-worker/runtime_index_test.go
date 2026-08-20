package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

func TestRuntimeIndexExecutorPersistsExactReceiptAfterDurableIndex(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageIndex)
	body := runtimeIndexBody(lease)
	lease.InputDigest = sha256.Sum256(body)
	reader := &runtimeArchivedReaderStub{body: body}
	index := &runtimeIndexStoreStub{}
	receipts := &runtimeReceiptStoreStub{}
	executor, err := newRuntimeIndexExecutor(runtimeIndexExecutorConfig{Reader: reader, Index: index, Receipts: receipts, ImplementationVersion: "runtime-index-v1"})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.Execute(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if reader.calls != 1 || index.calls != 1 || receipts.putCalls != 1 || receipts.referenceCalls != 1 || index.input.Scope != lease.Scope || index.input.BatchID != lease.BatchID || index.input.Generation != lease.Generation || index.input.InputDigest != lease.InputDigest || index.input.ArchiveReference != lease.InputReference || index.input.ArchiveVersionID != lease.InputVersionID || !bytes.Equal(index.input.Body, body) {
		t.Fatalf("reader=%d index=%d input=%#v receipt=%d/%d", reader.calls, index.calls, index.input, receipts.putCalls, receipts.referenceCalls)
	}
	receipt, err := runtimeevent.DecodeStageReceipt(receipts.put.Body)
	if err != nil || receipt.Stage != runtimeevent.RuntimeStageIndex || receipt.ImplementationVersion != lease.ImplementationVersion || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.InputReference != lease.InputReference || receipt.InputVersionID != lease.InputVersionID || receipt.InputDigest != lease.InputDigest || receipt.ArchiveReference != lease.InputReference || receipt.ArchiveVersionID != lease.InputVersionID || receipt.ArchiveDigest != lease.InputDigest || receipt.EffectDigest != index.result.ContentDigest || len(receipt.ItemIDs) != 1 || receipt.ItemIDs[0] != index.result.DocumentIDs[0] {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if effect.EffectDigest != index.result.ContentDigest || effect.ResultReference != receipts.objectReference || effect.ResultVersionID != receipts.result.VersionID || effect.ResultDigest != receipts.result.SHA256 {
		t.Fatalf("effect=%#v", effect)
	}
}

func TestRuntimeIndexExecutorFailsClosedBeforeReceipt(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageIndex)
	body := runtimeIndexBody(lease)
	lease.InputDigest = sha256.Sum256(body)
	for _, test := range []struct {
		name       string
		readerErr  error
		indexErr   error
		receiptErr error
		want       error
	}{
		{name: "archive retryable", readerErr: errRuntimeStageRetryable, want: errRuntimeStageRetryable},
		{name: "index denied", indexErr: runtimeindex.ErrDenied, want: errRuntimeStageDenied},
		{name: "index malformed", indexErr: runtimeindex.ErrDrift, want: errRuntimeStageMalformed},
		{name: "index unknown", indexErr: runtimeindex.ErrUnknownOutcome, want: errWorkerExecution},
		{name: "receipt unknown", receiptErr: artifactstore.ErrPut, want: errWorkerExecution},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &runtimeArchivedReaderStub{body: body, err: test.readerErr}
			index := &runtimeIndexStoreStub{err: test.indexErr}
			receipts := &runtimeReceiptStoreStub{err: test.receiptErr}
			executor, err := newRuntimeIndexExecutor(runtimeIndexExecutorConfig{Reader: reader, Index: index, Receipts: receipts, ImplementationVersion: "runtime-index-v1"})
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.Execute(context.Background(), lease)
			if !errors.Is(err, test.want) || effect != (runtimeStageEffect{}) {
				t.Fatalf("effect=%#v err=%v", effect, err)
			}
			if test.readerErr != nil && (index.calls != 0 || receipts.putCalls != 0) {
				t.Fatalf("index=%d receipt=%d", index.calls, receipts.putCalls)
			}
			if test.indexErr != nil && receipts.putCalls != 0 {
				t.Fatalf("receipt=%d", receipts.putCalls)
			}
		})
	}
}

type runtimeArchivedReaderStub struct {
	body  []byte
	err   error
	calls int
}

func (stub *runtimeArchivedReaderStub) Read(context.Context, runtimeevent.StageLease) ([]byte, error) {
	stub.calls++
	return bytes.Clone(stub.body), stub.err
}

type runtimeIndexStoreStub struct {
	input  runtimeindex.Batch
	result runtimeindex.ApplyResult
	err    error
	calls  int
}

func (stub *runtimeIndexStoreStub) Apply(_ context.Context, input runtimeindex.Batch) (runtimeindex.ApplyResult, error) {
	stub.calls++
	stub.input = input
	stub.input.Body = bytes.Clone(input.Body)
	if stub.err != nil {
		return runtimeindex.ApplyResult{}, stub.err
	}
	stub.result = runtimeindex.ApplyResult{BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: sha256.Sum256([]byte("index-effect")), DocumentIDs: []string{"evt_" + repeatRuntimeHex("a", 64)}}
	return stub.result, nil
}

type runtimeReceiptStoreStub struct {
	put             artifactstore.PutRequest
	result          artifactstore.Artifact
	objectReference string
	err             error
	putCalls        int
	referenceCalls  int
}

func (stub *runtimeReceiptStoreStub) Put(_ context.Context, input artifactstore.PutRequest) (artifactstore.Artifact, error) {
	stub.putCalls++
	stub.put = input
	stub.put.Body = bytes.Clone(input.Body)
	if stub.err != nil {
		return artifactstore.Artifact{}, stub.err
	}
	stub.result = artifactstore.Artifact{Locator: input.Locator, MediaType: input.MediaType, Body: bytes.Clone(input.Body), Size: int64(len(input.Body)), SHA256: sha256.Sum256(input.Body)}
	stub.result.VersionID = "receipt-version-1"
	stub.objectReference = "s3://zasp-evidence/organizations/receipt.json"
	return stub.result, nil
}
func (*runtimeReceiptStoreStub) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrGet
}
func (*runtimeReceiptStoreStub) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}
func (stub *runtimeReceiptStoreStub) ObjectReference(artifactstore.Locator) (string, error) {
	stub.referenceCalls++
	return stub.objectReference, nil
}

func runtimeIndexBody(lease runtimeevent.StageLease) []byte {
	return []byte(`{"source":"tetragon","events":[{"event_id":"event-1","class":"process","action":"exec","workload_id":"runtime-a","event_time":"2026-08-20T12:00:00.000Z","evidence_id":"pid_79000001-0000-4000-8000-000000000001","content":{"binary":"agent"}}]}`)
}

func repeatRuntimeHex(value string, count int) string {
	return string(bytes.Repeat([]byte(value), count))
}

var _ runtimeArchivedBatchReader = (*runtimeArchivedReaderStub)(nil)
var _ runtimeIndexStore = (*runtimeIndexStoreStub)(nil)
var _ artifactstore.ObjectReferencingArtifactStore = (*runtimeReceiptStoreStub)(nil)
