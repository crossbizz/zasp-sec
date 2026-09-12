package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// A v2 claim must process authenticated v2 receipts; legacy claims must reject
// them before archive/provider I/O. Both targets still accept historical data.
func TestSandboxSearchExecutorReceiptTarget(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v2", "runtime-correlation-v3"} {
		for _, target := range []string{"", "zasp-runtime-sessions-v2"} {
			t.Run(version+"/"+target, func(t *testing.T) {
				stage, artifacts := completeWorkerFromProjection(t, version)
				fixture := projectionWorkerFromCorrelation(t, version)
				reader := fixture.config.Reader.(*runtimeArchivedReaderStub)
				lease := runtimeSessionSearchLease{indexName: target, Binding: sessionsearch.ReceiptBinding{Scope: stage.lease.Scope, BatchID: stage.lease.BatchID, Generation: stage.lease.Generation, ReceiptDigest: artifacts.input.SHA256}, ReceiptReference: stage.lease.InputReference, ReceiptVersion: stage.lease.InputVersionID, Attempt: 1, LeaseUntil: time.Now().UTC().Add(30 * time.Second)}
				documents, err := sessionsearch.BuildDocuments(lease.Binding, artifacts.input.Body, reader.body)
				if err != nil {
					t.Fatal(err)
				}
				for _, document := range documents {
					lease.DocumentIDs = append(lease.DocumentIDs, document.DocumentID)
				}
				index := &sessionSearchIndexStub{}
				executor, err := newRuntimeSessionSearchExecutor(reader, artifacts, index)
				if err != nil {
					t.Fatal(err)
				}
				ids, err := executor.Execute(context.Background(), lease)
				if version == "runtime-correlation-v3" && target == "" {
					if err == nil || len(ids) != 0 || reader.calls != 0 || index.calls != 0 {
						t.Fatal("v2 receipt crossed legacy target", err)
					}
					return
				}
				if err != nil || !slices.Equal(ids, lease.DocumentIDs) || reader.calls != 1 || index.calls != 1 {
					t.Fatal("supported receipt didn't reach matching target", err)
				}
			})
		}
	}
}
