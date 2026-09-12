package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

type sandboxProjectionWorkerFixture struct {
	config    runtimeProjectionExecutorConfig
	execution runtimeStageExecution
	artifacts *runtimeCorrelationArtifactStoreStub
	graph     *runtimeCorrelationGraphStoreStub
}

func TestSandboxProjectionWorkerRejectsInvalidExecutionBeforeIO(t *testing.T) {
	for _, scenario := range []string{"worker", "token", "expired", "canceled", "future", "stage", "predecessor"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := projectionWorkerFromCorrelation(t, "runtime-correlation-v3")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "worker":
				fixture.execution.workerID = ""
			case "token":
				fixture.execution.leaseToken = "invalid"
			case "expired":
				fixture.execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "canceled":
				cancel()
			case "future":
				fixture.execution.lease.ImplementationVersion = "runtime-projection-v3"
			case "stage":
				fixture.execution.lease.Stage = runtimeevent.RuntimeStageCorrelate
			case "predecessor":
				fixture.execution.lease.PredecessorDigest = nil
			}
			executor, err := newRuntimeProjectionExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, fixture.execution)
			if !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || fixture.artifacts.getCalls != 0 || fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 {
				t.Fatal("invalid execution crossed I/O boundary", err)
			}
		})
	}
}

func TestSandboxProjectionWorkerRejectsPredecessorDriftBeforeArchive(t *testing.T) {
	for _, scenario := range []string{"old-correlation", "new-correlation-old-projection", "digest", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			version := "runtime-correlation-v3"
			if scenario == "old-correlation" {
				version = "runtime-correlation-v2"
			}
			fixture := projectionWorkerFromCorrelation(t, version)
			switch scenario {
			case "old-correlation":
				fixture.execution.lease.ImplementationVersion = "runtime-projection-v2"
			case "new-correlation-old-projection":
				fixture.execution.lease.ImplementationVersion = "runtime-projection-v1"
			case "digest":
				fixture.execution.lease.InputDigest[0] ^= 1
				fixture.execution.lease.PredecessorDigest = &fixture.execution.lease.InputDigest
			case "generation":
				fixture.execution.lease.Generation++
			}
			executor, err := newRuntimeProjectionExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(context.Background(), fixture.execution)
			if !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || fixture.artifacts.getCalls != 1 || fixture.config.Reader.(*runtimeArchivedReaderStub).calls != 0 || fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 {
				t.Fatal("predecessor drift crossed archive boundary", err)
			}
		})
	}
}

func TestSandboxProjectionWorkerChecksLeaseAndCancellationAcrossEffects(t *testing.T) {
	for _, scenario := range []string{"cancel-graph", "cancel-receipt", "expire-graph", "renewed"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := projectionWorkerFromCorrelation(t, "runtime-correlation-v3")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture.execution.renewal = &runtimeStageLeaseRenewal{expiresAt: fixture.execution.lease.LeaseExpiresAt}
			if scenario == "renewed" {
				fixture.execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			}
			if scenario == "cancel-receipt" {
				fixture.config.Receipts = frozenCancelArtifactStore{fixture.artifacts, cancel}
			} else {
				fixture.config.Graph = frozenGraphFunc(func(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
					result, err := fixture.graph.ApplySnapshot(ctx, snapshot)
					if scenario == "cancel-graph" {
						cancel()
					}
					if scenario == "expire-graph" {
						fixture.execution.renewal.mu.Lock()
						fixture.execution.renewal.expiresAt = time.Now().Add(-time.Second)
						fixture.execution.renewal.mu.Unlock()
					}
					return result, err
				})
			}
			executor, err := newRuntimeProjectionExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, fixture.execution)
			if scenario == "renewed" {
				if err != nil || !validRuntimeStageEffect(effect) {
					t.Fatal("valid renewed lease rejected", err)
				}
			} else if !errors.Is(err, errRuntimeStageRetryable) || effect != (runtimeStageEffect{}) {
				t.Fatal("lost execution reported completion", err)
			}
			wantPut := 0
			if scenario == "cancel-receipt" || scenario == "renewed" {
				wantPut = 1
			}
			if fixture.graph.calls != 1 || fixture.artifacts.putCalls != wantPut {
				t.Fatal("unexpected effect boundary", fixture.graph.calls, fixture.artifacts.putCalls)
			}
		})
	}
}

func projectionWorkerFromCorrelation(t *testing.T, version string, preciseOptions ...preciseExecutorFixtureOptions) sandboxProjectionWorkerFixture {
	t.Helper()
	correlation := newFrozenExecutorFixture(t)
	if version == "runtime-correlation-v3" {
		correlation = sandboxExecutorFixture(t)
	}
	if version == "runtime-correlation-v4" {
		correlation = preciseExecutorFixture(t, 1)
		if len(preciseOptions) > 0 {
			correlation = preciseExecutorFixtureWithOptions(t, preciseOptions[0])
		}
	}
	correlation.config.ImplementationVersion = version
	correlation.execution.lease.ImplementationVersion = version
	if version == "runtime-correlation-v1" {
		correlation.config.Candidates = nil
	}
	executor, err := newRuntimeCorrelationExecutor(correlation.config)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := executor.ExecuteAuthorized(context.Background(), correlation.execution)
	if err != nil {
		t.Fatal(err)
	}
	lease := correlation.execution.lease
	lease.Stage, lease.ImplementationVersion = runtimeevent.RuntimeStageProject, "runtime-projection-v1"
	if version == "runtime-correlation-v3" {
		lease.ImplementationVersion = "runtime-projection-v2"
	}
	configured := "runtime-projection-v2"
	if version == "runtime-correlation-v4" {
		lease.ImplementationVersion, configured = "runtime-projection-v3", "runtime-projection-v3"
	}
	lease.InputDigest, lease.PredecessorDigest = effect.EffectDigest, &effect.EffectDigest
	// The boundary store uses a fixed output URI for correlation-only tests.
	// Compose using the actual content-addressed receipt locator.
	lease.InputReference, lease.InputVersionID = runtimeTestReceiptReference(lease, correlation.artifacts.output.Reference.String()), effect.ResultVersionID
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: correlation.artifacts.output, outputReference: runtimeTestReceiptReference(lease, mustProductID(t, "pid_00000096-0000-4000-8000-000000000096").String())}
	graph := &runtimeCorrelationGraphStoreStub{}
	return sandboxProjectionWorkerFixture{config: runtimeProjectionExecutorConfig{Reader: &runtimeArchivedReaderStub{body: correlation.archive}, Receipts: artifacts, Graph: graph, ImplementationVersion: configured}, execution: runtimeStageExecution{lease: lease, workerID: correlation.execution.workerID, leaseToken: correlation.execution.leaseToken}, artifacts: artifacts, graph: graph}
}

func TestSandboxProjectionWorkerPreservesVersionedReceipts(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
		t.Run(version, func(t *testing.T) {
			fixture := projectionWorkerFromCorrelation(t, version)
			executor, err := newRuntimeProjectionExecutor(fixture.config)
			if err != nil {
				t.Fatal("sandbox projection worker rejected", err)
			}
			if version == "runtime-correlation-v3" {
				if _, err := executor.Execute(context.Background(), fixture.execution.lease); !errors.Is(err, errRuntimeStageMalformed) || fixture.artifacts.getCalls != 0 {
					t.Fatal("v2 bypassed authorized execution", err)
				}
			}
			authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{fixture.execution.lease}}
			processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageProject, ImplementationVersion: "runtime-projection-v2", WorkerID: fixture.execution.workerID, LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return fixture.execution.leaseToken, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); err != nil || len(authority.finishes) != 1 || authority.finishes[0].Outcome != runtimeevent.StageOutcomeSucceeded {
				t.Fatal("projection did not finish versioned work", err, authority.finishes)
			}
			receipt, err := runtimeprojection.DecodeReceipt(fixture.artifacts.put.Body)
			if err != nil || receipt.ImplementationVersion != fixture.execution.lease.ImplementationVersion || receipt.InputDigest != fixture.execution.lease.InputDigest || len(receipt.Items) != 1 {
				t.Fatal("projection receipt lost predecessor/version", err)
			}
			if version == "runtime-correlation-v3" {
				if receipt.Items[0].SandboxID != "sandbox-a" || receipt.Items[0].SandboxSourceSensorID.String() != "pid_00000095-0000-4000-8000-000000000095" {
					t.Fatal("sandbox binding lost at worker projection")
				}
			} else {
				old := projectionWorkerFromCorrelation(t, version)
				old.config.ImplementationVersion = "runtime-projection-v1"
				legacy, err := newRuntimeProjectionExecutor(old.config)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := legacy.Execute(context.Background(), old.execution.lease); err != nil || !bytes.Equal(old.artifacts.put.Body, fixture.artifacts.put.Body) {
					t.Fatal("upgraded projector changed historical receipt bytes", err)
				}
			}
		})
	}
}
