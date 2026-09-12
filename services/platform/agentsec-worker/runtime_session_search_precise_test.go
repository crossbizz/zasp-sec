package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
	"strings"
	"testing"
	"time"
)

type preciseSessionIndexStub struct {
	sessionSearchIndexStub
	preciseCalls int
	after        func()
	drift        bool
}

func (index *preciseSessionIndexStub) ApplyPrecise(ctx context.Context, binding sessionsearch.ReceiptBinding, receipt, archive []byte) (opensearchdriver.SessionWriteResult, error) {
	index.preciseCalls++
	documents, err := sessionsearch.BuildPreciseDocuments(binding, receipt, archive)
	if err != nil {
		return opensearchdriver.SessionWriteResult{}, err
	}
	ids := make([]string, len(documents))
	for i, doc := range documents {
		ids[i] = doc.DocumentID
	}
	if index.after != nil {
		index.after()
	}
	if index.drift {
		ids[0] = strings.Repeat("0", 64)
	}
	return opensearchdriver.SessionWriteResult{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ReceiptDigest: binding.ReceiptDigest, DocumentIDs: ids}, nil
}

func TestPreciseSessionSearchWorkerConsumesBoundProjection(t *testing.T) {
	for _, scenario := range []string{"valid", "large", "legacy target", "legacy worker", "missing capability", "cancel write", "provider drift", "document mismatch", "renewed", "lost renewal", "claimed version mismatch", "missing claimed version"} {
		t.Run(scenario, func(t *testing.T) {
			options := preciseExecutorFixtureOptions{withCandidate: true}
			if scenario == "large" {
				options = preciseExecutorFixtureOptions{eventCount: 1000, archiveVersion: strings.Repeat("<", 200)}
			}
			fixture := projectionWorkerFromCorrelation(t, "runtime-correlation-v4", options)
			projector, err := newRuntimeProjectionExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = projector.ExecuteAuthorized(context.Background(), fixture.execution)
			if err != nil {
				t.Fatal(err)
			}
			artifact := fixture.artifacts.output
			artifacts := &runtimeCorrelationArtifactStoreStub{input: artifact, inputReference: runtimeTestReceiptReference(fixture.execution.lease, artifact.Reference.String())}
			reader := fixture.config.Reader.(*runtimeArchivedReaderStub)
			reader.calls = 0
			lease := runtimeSessionSearchLease{indexName: "zasp-runtime-sessions-v2", Binding: sessionsearch.ReceiptBinding{Scope: fixture.execution.lease.Scope, BatchID: fixture.execution.lease.BatchID, Generation: fixture.execution.lease.Generation, ReceiptDigest: artifact.SHA256}, ReceiptReference: artifacts.inputReference, ReceiptVersion: artifact.VersionID, Attempt: 1, LeaseUntil: time.Now().Add(time.Minute)}
			docs, err := sessionsearch.BuildPreciseDocuments(lease.Binding, artifact.Body, reader.body)
			if err != nil {
				t.Fatal(err)
			}
			for _, doc := range docs {
				lease.DocumentIDs = append(lease.DocumentIDs, doc.DocumentID)
			}
			if scenario == "large" && len(artifact.Body) <= 1<<20 {
				t.Fatal("large fixture too small")
			}
			if scenario == "legacy target" {
				lease.indexName = ""
			}
			index := &preciseSessionIndexStub{}
			if scenario == "renewed" || scenario == "lost renewal" {
				lease.LeaseUntil = time.Now().Add(-time.Second)
				lease.renewal = &runtimeStageLeaseRenewal{expiresAt: time.Now().Add(time.Minute)}
				if scenario == "lost renewal" {
					lease.renewal.expiresAt = time.Now().Add(-time.Second)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel write" {
				index.after = cancel
			}
			if scenario == "provider drift" {
				index.drift = true
			}
			if scenario == "document mismatch" {
				lease.DocumentIDs[0] = strings.Repeat("0", 64)
			}
			lease.projectionImplementationVersion = "runtime-projection-v3"
			if scenario == "claimed version mismatch" {
				lease.projectionImplementationVersion = "runtime-projection-v2"
			}
			if scenario == "missing claimed version" {
				lease.projectionImplementationVersion = ""
			}
			executor, err := newRuntimePreciseSessionSearchExecutor(reader, artifacts, index)
			if scenario == "missing capability" {
				_, err = newRuntimePreciseSessionSearchExecutor(reader, artifacts, &sessionSearchIndexStub{})
				if err == nil {
					t.Fatal("missing precise capability accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "legacy worker" {
				executor, err = newRuntimeSessionSearchExecutor(reader, artifacts, index)
				if err != nil {
					t.Fatal(err)
				}
			}
			ids, err := executor.Execute(ctx, lease)
			if scenario == "valid" || scenario == "large" || scenario == "renewed" {
				if err != nil || len(ids) != len(docs) || index.preciseCalls != 1 || index.calls != 0 || reader.lease.ImplementationVersion != "runtime-index-v2" {
					t.Fatal("precise search failed", err)
				}
			} else if scenario == "cancel write" || scenario == "provider drift" {
				if err != errWorkerExecution || ids != nil || index.preciseCalls != 1 {
					t.Fatal("invalid provider result accepted", err)
				}
			} else if scenario == "document mismatch" {
				if err != errRuntimeStageMalformed || ids != nil || index.preciseCalls != 0 {
					t.Fatal("wrong document IDs written", err)
				}
			} else if err != errRuntimeStageMalformed || ids != nil || index.preciseCalls != 0 || reader.calls != 0 {
				t.Fatal("unsupported worker/target executed", err)
			}
		})
	}
}

func TestPreciseSessionSearchWorkerDrainsHistoricalReceipt(t *testing.T) {
	lease, artifacts, reader := sessionSearchWorkerFixture(t)
	index := &preciseSessionIndexStub{}
	executor, err := newRuntimePreciseSessionSearchExecutor(reader, artifacts, index)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := executor.Execute(context.Background(), lease)
	if err != nil || len(ids) != len(lease.DocumentIDs) || index.calls != 1 || index.preciseCalls != 0 || reader.lease.ImplementationVersion != "runtime-index-v1" {
		t.Fatal("historical drain changed", err)
	}
}
