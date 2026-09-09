package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type sessionSearchIndexStub struct {
	calls int
	fault string
	err   error
}

func (index *sessionSearchIndexStub) Apply(_ context.Context, binding sessionsearch.ReceiptBinding, receipt, archive []byte) (opensearchdriver.SessionWriteResult, error) {
	index.calls++
	if index.err != nil {
		return opensearchdriver.SessionWriteResult{}, index.err
	}
	documents, err := sessionsearch.BuildDocuments(binding, receipt, archive)
	if err != nil {
		return opensearchdriver.SessionWriteResult{}, err
	}
	ids := make([]string, len(documents))
	for i, document := range documents {
		ids[i] = document.DocumentID
	}
	result := opensearchdriver.SessionWriteResult{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ReceiptDigest: binding.ReceiptDigest, DocumentIDs: ids}
	switch index.fault {
	case "scope":
		result.Scope = domain.Scope{}
	case "batch":
		result.BatchID = binding.Scope.OrganizationID()
	case "generation":
		result.Generation++
	case "digest":
		result.ReceiptDigest = sha256.Sum256([]byte("drift"))
	case "documents":
		result.DocumentIDs = []string{"bad"}
	}
	return result, nil
}

func sessionSearchWorkerFixture(t *testing.T) (runtimeSessionSearchLease, *runtimeCorrelationArtifactStoreStub, *runtimeArchivedReaderStub) {
	t.Helper()
	stage, artifacts, _ := runtimeCompleteFixture(t)
	lease := runtimeSessionSearchLease{Binding: sessionsearch.ReceiptBinding{Scope: stage.Scope, BatchID: stage.BatchID, Generation: stage.Generation, ReceiptDigest: artifacts.input.SHA256}, ReceiptReference: stage.InputReference, ReceiptVersion: stage.InputVersionID, Attempt: 1, LeaseUntil: time.Now().UTC().Add(30 * time.Second)}
	reader := &runtimeArchivedReaderStub{body: runtimeOTLPIndexBody()}
	documents, err := sessionsearch.BuildDocuments(lease.Binding, artifacts.input.Body, reader.body)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range documents {
		lease.DocumentIDs = append(lease.DocumentIDs, document.DocumentID)
	}
	return lease, artifacts, reader
}

func TestRuntimeSessionSearchExecutorUsesOnlyCommittedReceiptAndExactArchive(t *testing.T) {
	lease, artifacts, reader := sessionSearchWorkerFixture(t)
	index := &sessionSearchIndexStub{}
	executor, err := newRuntimeSessionSearchExecutor(reader, artifacts, index)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := executor.Execute(context.Background(), lease)
	if err != nil || !slices.Equal(ids, lease.DocumentIDs) || index.calls != 1 || reader.calls != 1 || artifacts.getCalls != 1 || artifacts.putCalls != 0 {
		t.Fatalf("ids=%v err=%v calls=%d/%d/%d", ids, err, index.calls, reader.calls, artifacts.getCalls)
	}
	if reader.lease.Stage != runtimeevent.RuntimeStageIndex || reader.lease.InputDigest != sha256.Sum256(runtimeOTLPIndexBody()) {
		t.Fatal("archive read was not bound to exact digest")
	}
}

func TestRuntimeSessionSearchExecutorRejectsReceiptDriftBeforeIndexing(t *testing.T) {
	for _, fault := range []string{"receipt bytes", "receipt digest", "scope", "reference", "document ids", "archive bytes"} {
		t.Run(fault, func(t *testing.T) {
			lease, artifacts, reader := sessionSearchWorkerFixture(t)
			index := &sessionSearchIndexStub{}
			switch fault {
			case "receipt bytes":
				artifacts.input.Body[0] = '!'
			case "receipt digest":
				lease.Binding.ReceiptDigest = sha256.Sum256([]byte("drift"))
			case "scope":
				lease.Binding.Scope = workerScope(t)
				lease.Binding.BatchID = lease.Binding.Scope.OrganizationID()
			case "reference":
				lease.ReceiptReference = "s3://foreign/receipt.json"
			case "document ids":
				lease.DocumentIDs = []string{string(make([]byte, 64))}
			case "archive bytes":
				reader.body = []byte("drift")
			}
			executor, _ := newRuntimeSessionSearchExecutor(reader, artifacts, index)
			if ids, err := executor.Execute(context.Background(), lease); err == nil || len(ids) != 0 || index.calls != 0 {
				t.Fatalf("fault=%s ids=%v err=%v index=%d", fault, ids, err, index.calls)
			}
		})
	}
}

func TestRuntimeSessionSearchExecutorRejectsForgedIndexAcknowledgement(t *testing.T) {
	for _, fault := range []string{"scope", "batch", "generation", "digest", "documents"} {
		t.Run(fault, func(t *testing.T) {
			lease, artifacts, reader := sessionSearchWorkerFixture(t)
			index := &sessionSearchIndexStub{fault: fault}
			executor, _ := newRuntimeSessionSearchExecutor(reader, artifacts, index)
			if ids, err := executor.Execute(context.Background(), lease); err == nil || len(ids) != 0 {
				t.Fatal("forged index completion accepted")
			}
		})
	}
	lease, artifacts, reader := sessionSearchWorkerFixture(t)
	executor, _ := newRuntimeSessionSearchExecutor(reader, artifacts, &sessionSearchIndexStub{err: runtimeindex.ErrUnknownOutcome})
	if _, err := executor.Execute(context.Background(), lease); !errors.Is(err, errRuntimeStageRetryable) {
		t.Fatalf("uncertain write must stay retryable: %v", err)
	}
}
