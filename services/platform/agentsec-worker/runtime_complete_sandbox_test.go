package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

func TestSandboxCompleteWorkerRejectsInvalidExecutionBeforeIO(t *testing.T) {
	for _, scenario := range []string{"worker", "token", "expired", "canceled", "future", "stage", "predecessor", "predecessor-drift"} {
		t.Run(scenario, func(t *testing.T) {
			execution, artifacts := completeWorkerFromProjection(t, "runtime-correlation-v3")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "worker":
				execution.workerID = ""
			case "token":
				execution.leaseToken = "invalid"
			case "expired":
				execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "canceled":
				cancel()
			case "future":
				execution.lease.ImplementationVersion = "runtime-complete-v3"
			case "stage":
				execution.lease.Stage = runtimeevent.RuntimeStageProject
			case "predecessor":
				execution.lease.PredecessorDigest = nil
			case "predecessor-drift":
				execution.lease.InputDigest[0] ^= 1
			}
			executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v2"})
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, execution)
			if !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || artifacts.getCalls != 0 || artifacts.putCalls != 0 {
				t.Fatal("invalid completion crossed I/O boundary", err)
			}
		})
	}
}

func TestSandboxCompleteWorkerRejectsPredecessorDriftBeforeWrite(t *testing.T) {
	for _, scenario := range []string{"old-projection", "new-projection-old-completion", "digest", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			version := "runtime-correlation-v3"
			if scenario == "old-projection" {
				version = "runtime-correlation-v2"
			}
			execution, artifacts := completeWorkerFromProjection(t, version)
			switch scenario {
			case "old-projection":
				execution.lease.ImplementationVersion = "runtime-complete-v2"
			case "new-projection-old-completion":
				execution.lease.ImplementationVersion = "runtime-complete-v1"
			case "digest":
				execution.lease.InputDigest[0] ^= 1
				execution.lease.PredecessorDigest = &execution.lease.InputDigest
			case "generation":
				execution.lease.Generation++
			}
			executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v2"})
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(context.Background(), execution)
			if !errors.Is(err, errRuntimeStageMalformed) || effect != (runtimeStageEffect{}) || artifacts.getCalls != 1 || artifacts.putCalls != 0 {
				t.Fatal("predecessor drift crossed receipt write", err)
			}
		})
	}
}

type sandboxCompleteReadHook struct {
	*runtimeCorrelationArtifactStoreStub
	afterRead func()
}

func (store sandboxCompleteReadHook) Get(ctx context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	artifact, err := store.runtimeCorrelationArtifactStoreStub.Get(ctx, locator)
	store.afterRead()
	return artifact, err
}

func TestSandboxCompleteWorkerFencesLeaseAndCancellation(t *testing.T) {
	for _, scenario := range []string{"cancel-read", "expire-read", "cancel-write", "renewed"} {
		t.Run(scenario, func(t *testing.T) {
			execution, artifacts := completeWorkerFromProjection(t, "runtime-correlation-v3")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			execution.renewal = &runtimeStageLeaseRenewal{expiresAt: execution.lease.LeaseExpiresAt}
			config := runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v2"}
			switch scenario {
			case "cancel-write":
				config.Receipts = frozenCancelArtifactStore{artifacts, cancel}
			case "renewed":
				execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			default:
				config.Receipts = sandboxCompleteReadHook{artifacts, func() {
					if scenario == "cancel-read" {
						cancel()
					} else {
						execution.renewal.mu.Lock()
						execution.renewal.expiresAt = time.Now().Add(-time.Second)
						execution.renewal.mu.Unlock()
					}
				}}
			}
			executor, err := newRuntimeCompleteExecutor(config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, execution)
			if scenario == "renewed" {
				if err != nil || !validRuntimeStageEffect(effect) {
					t.Fatal("valid renewed completion rejected", err)
				}
			} else if !errors.Is(err, errRuntimeStageRetryable) || effect != (runtimeStageEffect{}) {
				t.Fatal("lost completion execution reported success", err)
			}
			wantPut := 0
			if scenario == "renewed" || scenario == "cancel-write" {
				wantPut = 1
			}
			if artifacts.putCalls != wantPut {
				t.Fatal("unexpected completion write boundary", artifacts.putCalls)
			}
		})
	}
}

func completeWorkerFromProjection(t *testing.T, correlationVersion string, options ...preciseExecutorFixtureOptions) (runtimeStageExecution, *runtimeCorrelationArtifactStoreStub) {
	t.Helper()
	fixture := projectionWorkerFromCorrelation(t, correlationVersion, options...)
	projector, err := newRuntimeProjectionExecutor(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := projector.ExecuteAuthorized(context.Background(), fixture.execution)
	if err != nil {
		t.Fatal(err)
	}
	execution := fixture.execution
	execution.lease.Stage, execution.lease.ImplementationVersion = runtimeevent.RuntimeStageComplete, "runtime-complete-v1"
	if correlationVersion == "runtime-correlation-v3" {
		execution.lease.ImplementationVersion = "runtime-complete-v2"
	}
	if correlationVersion == "runtime-correlation-v4" {
		execution.lease.ImplementationVersion = "runtime-complete-v3"
	}
	execution.lease.InputDigest, execution.lease.PredecessorDigest = effect.EffectDigest, &effect.EffectDigest
	execution.lease.InputReference = runtimeTestReceiptReference(execution.lease, fixture.artifacts.output.Reference.String())
	execution.lease.InputVersionID = effect.ResultVersionID
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: execution.lease.InputReference, input: fixture.artifacts.output, outputReference: runtimeTestReceiptReference(execution.lease, mustProductID(t, "pid_00000097-0000-4000-8000-000000000097").String())}
	return execution, artifacts
}

func TestSandboxCompleteWorkerPreservesVersionedReceipts(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
		t.Run(version, func(t *testing.T) {
			execution, artifacts := completeWorkerFromProjection(t, version)
			executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v2"})
			if err != nil {
				t.Fatal("compatible completion worker rejected", err)
			}
			if version == "runtime-correlation-v3" {
				if _, err := executor.Execute(context.Background(), execution.lease); !errors.Is(err, errRuntimeStageMalformed) || artifacts.getCalls != 0 {
					t.Fatal("v2 bypassed authorized execution", err)
				}
			}
			authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{execution.lease}}
			processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageComplete, ImplementationVersion: "runtime-complete-v2", WorkerID: execution.workerID, LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return execution.leaseToken, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); err != nil || len(authority.finishes) != 1 || authority.finishes[0].Outcome != runtimeevent.StageOutcomeSucceeded {
				t.Fatal("completion did not finish", err)
			}
			finish := authority.finishes[0]
			receipt, err := runtimeevent.DecodeStageReceipt(artifacts.put.Body)
			if err != nil || receipt.ImplementationVersion != execution.lease.ImplementationVersion || receipt.InputDigest != execution.lease.InputDigest || !bytes.Equal([]byte(finish.ProjectionReceipt), artifacts.input.Body) {
				t.Fatal("completion lost exact predecessor", err)
			}
			projected, err := runtimeprojection.DecodeReceipt([]byte(finish.ProjectionReceipt))
			if err != nil || len(projected.Items) != 1 || len(receipt.ItemIDs) != 1 || receipt.ItemIDs[0] != projected.Items[0].ID {
				t.Fatal("completion lost risk identity", err)
			}
			if version == "runtime-correlation-v3" {
				if projected.Items[0].SandboxID != "sandbox-a" || projected.Items[0].SandboxSourceSensorID.IsZero() {
					t.Fatal("completion dropped sandbox binding")
				}
			} else {
				oldExecution, oldArtifacts := completeWorkerFromProjection(t, version)
				old, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: oldArtifacts, ImplementationVersion: "runtime-complete-v1"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := old.Execute(context.Background(), oldExecution.lease); err != nil || !bytes.Equal(oldArtifacts.put.Body, artifacts.put.Body) {
					t.Fatal("completion changed historical bytes", err)
				}
			}
		})
	}
}
