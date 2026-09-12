package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"strings"
	"testing"
	"time"
)

type preciseWrongVersionStore struct {
	*runtimeCorrelationArtifactStoreStub
}

func (store preciseWrongVersionStore) Get(ctx context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	artifact, err := store.runtimeCorrelationArtifactStoreStub.Get(ctx, locator)
	if err == nil {
		artifact.VersionID = "other-version"
	}
	return artifact, err
}

func TestPreciseCompleteWorkerRejectsReceiptDriftBeforeWrite(t *testing.T) {
	for _, scenario := range []string{"checksum", "version", "generation", "digest", "legacy predecessor", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			version := "runtime-correlation-v4"
			if scenario == "legacy predecessor" {
				version = "runtime-correlation-v3"
			}
			execution, artifacts := completeWorkerFromProjection(t, version)
			var store artifactstore.ObjectReferencingArtifactStore = artifacts
			execution.lease.ImplementationVersion = "runtime-complete-v3"
			switch scenario {
			case "checksum":
				artifacts.input.SHA256[0] ^= 1
			case "version":
				store = preciseWrongVersionStore{artifacts}
			case "generation":
				execution.lease.Generation++
			case "digest":
				execution.lease.InputDigest[0] ^= 1
				execution.lease.PredecessorDigest = &execution.lease.InputDigest
			case "oversize":
				artifacts.input.Body = bytes.Repeat([]byte(" "), (4<<20)+1)
				artifacts.input.Size = int64(len(artifacts.input.Body))
				artifacts.input.SHA256 = sha256.Sum256(artifacts.input.Body)
			}
			executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: store, ImplementationVersion: "runtime-complete-v3"})
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(context.Background(), execution)
			if err != errRuntimeStageMalformed || effect != (runtimeStageEffect{}) || artifacts.putCalls != 0 {
				t.Fatal("drift wrote completion", err)
			}
		})
	}
}

func TestPreciseCompleteWorkerPassesExactProjectionToFinisher(t *testing.T) {
	execution, artifacts := completeWorkerFromProjection(t, "runtime-correlation-v4")
	body := bytes.Clone(artifacts.input.Body)
	executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v3"})
	if err != nil {
		t.Fatal(err)
	}
	authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{execution.lease}}
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageComplete, ImplementationVersion: "runtime-complete-v3", WorkerID: execution.workerID, LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return execution.leaseToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(authority.finishes) != 1 || authority.finishes[0].Outcome != runtimeevent.StageOutcomeSucceeded || authority.finishes[0].Lease.ImplementationVersion != "runtime-complete-v3" || authority.finishes[0].ProjectionReceipt != string(body) {
		t.Fatal("finisher handoff lost exact receipt")
	}
}

func TestPreciseCompleteWorkerCarriesProjectionAndLargeReceipts(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(map[bool]string{false: "bound", true: "large"}[large], func(t *testing.T) {
			var execution runtimeStageExecution
			var artifacts *runtimeCorrelationArtifactStoreStub
			if large {
				execution, artifacts = completeWorkerFromProjection(t, "runtime-correlation-v4", preciseExecutorFixtureOptions{eventCount: 1000, archiveVersion: strings.Repeat("<", 200)})
			} else {
				execution, artifacts = completeWorkerFromProjection(t, "runtime-correlation-v4")
			}
			original := bytes.Clone(artifacts.input.Body)
			if large && (len(original) <= 1<<20 || len(original) > 4<<20) {
				t.Fatal("fixture does not exercise precise size window", len(original))
			}
			executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v3"})
			if err != nil {
				t.Fatal("V3 completion unavailable", err)
			}
			effect, err := executor.ExecuteAuthorized(context.Background(), execution)
			if err != nil || !validRuntimeStageEffect(effect) || effect.ProjectionReceipt != string(original) {
				t.Fatal("projection handoff lost", err)
			}
			receipt, err := runtimeevent.DecodeStageReceipt(artifacts.put.Body)
			if err != nil || receipt.ImplementationVersion != "runtime-complete-v3" || receipt.EffectDigest != execution.lease.InputDigest {
				t.Fatal("completion receipt lost version or binding", err)
			}
			projected, err := runtimeprojection.DecodePreciseReceipt([]byte(effect.ProjectionReceipt))
			if err != nil || len(receipt.ItemIDs) != len(projected.Items) {
				t.Fatal("projection items lost", err)
			}
			if !large && (projected.Items[0].Confidence.String() != "strong" || projected.Items[0].SandboxSourceSensorID.String() != "pid_00000097-0000-4000-8000-000000000097") {
				t.Fatal("admitted source lost")
			}
		})
	}
}

func TestPreciseCompleteWorkerRejectsInvalidExecution(t *testing.T) {
	for _, scenario := range []string{"worker", "token", "predecessor", "expired", "old worker", "unprivileged"} {
		t.Run(scenario, func(t *testing.T) {
			execution, artifacts := completeWorkerFromProjection(t, "runtime-correlation-v4")
			version := "runtime-complete-v3"
			switch scenario {
			case "worker":
				execution.workerID = ""
			case "token":
				execution.leaseToken = ""
			case "predecessor":
				execution.lease.PredecessorDigest = nil
			case "expired":
				execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			case "old worker":
				version = "runtime-complete-v2"
			}
			executor, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: version})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "unprivileged" {
				_, err = executor.Execute(context.Background(), execution.lease)
			} else {
				_, err = executor.ExecuteAuthorized(context.Background(), execution)
			}
			if err != errRuntimeStageMalformed || artifacts.getCalls != 0 || artifacts.putCalls != 0 {
				t.Fatal("invalid completion performed IO", err)
			}
		})
	}
}

func TestPreciseCompleteWorkerPreservesHistoricalReceipts(t *testing.T) {
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2", "runtime-correlation-v3"} {
		t.Run(version, func(t *testing.T) {
			execution, artifacts := completeWorkerFromProjection(t, version)
			old, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v2"})
			if err != nil {
				t.Fatal(err)
			}
			before, err := old.ExecuteAuthorized(context.Background(), execution)
			if err != nil {
				t.Fatal(err)
			}
			body := bytes.Clone(artifacts.put.Body)
			newer, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v3"})
			if err != nil {
				t.Fatal(err)
			}
			after, err := newer.ExecuteAuthorized(context.Background(), execution)
			if err != nil || after != before || !bytes.Equal(body, artifacts.put.Body) {
				t.Fatal("historical completion changed", err)
			}
		})
	}
}

func TestPreciseCompleteWorkerCancellationAndRenewal(t *testing.T) {
	for _, renewed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-write", true: "renewed"}[renewed], func(t *testing.T) {
			execution, artifacts := completeWorkerFromProjection(t, "runtime-correlation-v4")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := runtimeCompleteExecutorConfig{Receipts: artifacts, ImplementationVersion: "runtime-complete-v3"}
			if renewed {
				execution.renewal = &runtimeStageLeaseRenewal{expiresAt: time.Now().Add(time.Minute)}
				execution.lease.LeaseExpiresAt = time.Now().Add(-time.Second)
			} else {
				config.Receipts = frozenCancelArtifactStore{artifacts, cancel}
			}
			executor, err := newRuntimeCompleteExecutor(config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, execution)
			if renewed {
				if err != nil || !validRuntimeStageEffect(effect) {
					t.Fatal("renewed completion rejected", err)
				}
			} else if err != errRuntimeStageRetryable || effect != (runtimeStageEffect{}) {
				t.Fatal("canceled completion succeeded", err)
			}
		})
	}
}
