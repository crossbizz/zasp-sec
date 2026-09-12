package main

import (
	"bytes"
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"strings"
	"testing"
	"time"
)

func TestPreciseProjectionWorkerRejectsOversizeBeforeGraph(t *testing.T) {
	f := projectionWorkerFromCorrelation(t, "runtime-correlation-v4", preciseExecutorFixtureOptions{eventCount: 1000, archiveVersion: strings.Repeat("<", 1024)})
	correlation, err := runtimecorrelation.DecodePreciseReceipt(f.artifacts.input.Body)
	if err != nil || len(correlation.Results) != 1000 {
		t.Fatal("invalid bounded predecessor", err)
	}
	body := f.config.Reader.(*runtimeArchivedReaderStub).body
	projected, err := runtimeprojection.ProjectPrecise(runtimeprojection.Batch{Scope: correlation.Scope, BatchID: correlation.BatchID, Generation: correlation.Generation, ArchiveReference: correlation.ArchiveReference, ArchiveVersionID: correlation.ArchiveVersionID, ArchiveDigest: correlation.ArchiveDigest, Body: body, Correlations: correlation.Results})
	if err != nil || len(projected.Items) != 1000 {
		t.Fatal("invalid large projection", err)
	}
	executor, err := newRuntimeProjectionExecutor(f.config)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.ExecuteAuthorized(context.Background(), f.execution)
	if err != errRuntimeStageMalformed || effect != (runtimeStageEffect{}) || f.graph.calls != 0 || f.artifacts.putCalls != 0 {
		t.Fatal("oversize rejection followed writes", err, f.graph.calls, f.artifacts.putCalls)
	}
}

func TestPreciseProjectionWorkerPreservesAdmittedBinding(t *testing.T) {
	f := projectionWorkerFromCorrelation(t, "runtime-correlation-v4")
	executor, err := newRuntimeProjectionExecutor(f.config)
	if err != nil {
		t.Fatal("precise projection worker unavailable", err)
	}
	effect, err := executor.ExecuteAuthorized(context.Background(), f.execution)
	if err != nil || !validRuntimeStageEffect(effect) {
		t.Fatal("precise projection failed", err)
	}
	receipt, err := runtimeprojection.DecodePreciseReceipt(f.artifacts.put.Body)
	if err != nil || len(receipt.Items) != 1 || receipt.EffectDigest != effect.EffectDigest {
		t.Fatal("precise receipt missing", err)
	}
	item := receipt.Items[0]
	if item.Confidence.String() != "strong" || item.AgentID.String() != "pid_79000002-0000-4000-8000-000000000002" || item.SessionID.String() != "pid_79000003-0000-4000-8000-000000000003" || item.SandboxSourceSensorID.String() != "pid_00000097-0000-4000-8000-000000000097" || item.SandboxID != strings.Repeat("<", 256) {
		t.Fatal("admitted identity lost")
	}
	if f.graph.calls != 1 || f.artifacts.putCalls != 1 {
		t.Fatal("missing effects")
	}
	if _, err := runtimeprojection.DecodeReceipt(f.artifacts.put.Body); err == nil {
		t.Fatal("legacy reader consumed precise receipt")
	}
}

func TestPreciseProjectionWorkerRejectsInvalidCapability(t *testing.T) {
	for _, scenario := range []string{"worker", "token", "predecessor", "expired", "old worker", "unprivileged"} {
		t.Run(scenario, func(t *testing.T) {
			f := projectionWorkerFromCorrelation(t, "runtime-correlation-v4")
			switch scenario {
			case "worker":
				f.execution.workerID = ""
			case "token":
				f.execution.leaseToken = ""
			case "predecessor":
				f.execution.lease.PredecessorDigest = nil
			case "expired":
				f.execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "old worker":
				f.config.ImplementationVersion = "runtime-projection-v2"
			}
			executor, err := newRuntimeProjectionExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "unprivileged" {
				_, err = executor.Execute(context.Background(), f.execution.lease)
			} else {
				_, err = executor.ExecuteAuthorized(context.Background(), f.execution)
			}
			if err != errRuntimeStageMalformed || f.artifacts.getCalls != 0 || f.graph.calls != 0 || f.artifacts.putCalls != 0 {
				t.Fatal("invalid execution performed IO", err)
			}
		})
	}
}

func TestPreciseProjectionWorkerPreservesHistoricalReceipts(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
		t.Run(version, func(t *testing.T) {
			f := projectionWorkerFromCorrelation(t, version)
			old, err := newRuntimeProjectionExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := old.ExecuteAuthorized(context.Background(), f.execution); err != nil {
				t.Fatal(err)
			}
			expected := bytes.Clone(f.artifacts.put.Body)
			f.config.ImplementationVersion = "runtime-projection-v3"
			newer, err := newRuntimeProjectionExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newer.ExecuteAuthorized(context.Background(), f.execution); err != nil || !bytes.Equal(expected, f.artifacts.put.Body) {
				t.Fatal("historical receipt changed", err)
			}
		})
	}
}

func TestPreciseProjectionWorkerCancellationFencesEffects(t *testing.T) {
	for _, phase := range []string{"graph", "receipt", "renewed"} {
		t.Run(phase, func(t *testing.T) {
			f := projectionWorkerFromCorrelation(t, "runtime-correlation-v4")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "graph" {
				f.config.Graph = frozenGraphFunc(func(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
					result, err := f.graph.ApplySnapshot(ctx, snapshot)
					cancel()
					return result, err
				})
			}
			if phase == "receipt" {
				f.config.Receipts = frozenCancelArtifactStore{f.artifacts, cancel}
			}
			if phase == "renewed" {
				f.execution.renewal = &runtimeStageLeaseRenewal{expiresAt: time.Now().Add(time.Minute)}
				f.execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			}
			executor, err := newRuntimeProjectionExecutor(f.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, f.execution)
			if phase == "renewed" {
				if err != nil || !validRuntimeStageEffect(effect) {
					t.Fatal("renewed lease rejected", err)
				}
			} else if err != errRuntimeStageRetryable || effect != (runtimeStageEffect{}) {
				t.Fatal("canceled execution completed", err)
			}
			wantPut := 1
			if phase == "graph" {
				wantPut = 0
			}
			if f.graph.calls != 1 || f.artifacts.putCalls != wantPut {
				t.Fatal("crossed cancellation fence")
			}
		})
	}
}
