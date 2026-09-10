package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestFrozenCorrelationExecutorRequiresCapabilityAndExactReceiptBinding(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	executor, err := newRuntimeCorrelationExecutor(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), fixture.execution.lease); !errors.Is(err, errRuntimeStageMalformed) || fixture.artifacts.getCalls != 0 || fixture.graph.calls != 0 {
		t.Fatal("v2 legacy Execute bypassed execution capability")
	}
	var borrowedReceipt, borrowedArchive []byte
	called := 0
	executor.config.Candidates = runtimeCandidateAuthorityFunc(func(ctx context.Context, lease runtimeevent.StageLease, worker, token string, receipt, archive []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
		called++
		if fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 || lease != fixture.execution.lease || worker != fixture.execution.workerID || token != fixture.execution.leaseToken || !bytes.Equal(receipt, fixture.artifacts.input.Body) || !bytes.Equal(archive, fixture.archive) {
			t.Fatal("effects preceded exact candidate authority")
		}
		borrowedReceipt, borrowedArchive = receipt, archive
		return fixture.snapshot, nil
	})
	effect, err := executor.ExecuteAuthorized(context.Background(), fixture.execution)
	if err != nil || called != 1 || fixture.graph.calls != 1 || fixture.artifacts.putCalls != 1 {
		t.Fatal("authorized v2 execution", err)
	}
	receipt, err := runtimecorrelation.DecodeReceipt(fixture.artifacts.put.Body)
	if err != nil || receipt.ImplementationVersion != "runtime-correlation-v2" || receipt.CandidateSnapshotDigest != fixture.snapshot.Digest() || receipt.EffectDigest != effect.EffectDigest || len(receipt.Results) != 1 || receipt.Results[0].Confidence.String() != "exact" {
		t.Fatal("v2 effect lost frozen receipt binding", err)
	}
	if !bytes.Equal(borrowedReceipt, make([]byte, len(borrowedReceipt))) || !bytes.Equal(borrowedArchive, make([]byte, len(borrowedArchive))) {
		t.Fatal("borrowed evidence buffers weren't cleared")
	}
}

func TestFrozenCorrelationExecutorRejectsMissingOrForeignAuthorityBeforeEffects(t *testing.T) {
	for _, name := range []string{"missing worker", "missing token", "wrong version", "zero snapshot", "wrong index receipt", "canceled after freeze"} {
		t.Run(name, func(t *testing.T) {
			fixture := newFrozenExecutorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			fixture.config.Candidates = runtimeCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
				calls++
				if name == "zero snapshot" {
					return runtimeevent.FrozenCandidateSnapshot{}, nil
				}
				if name == "canceled after freeze" {
					cancel()
				}
				return fixture.snapshot, nil
			})
			switch name {
			case "missing worker":
				fixture.execution.workerID = ""
			case "missing token":
				fixture.execution.leaseToken = ""
			case "wrong version":
				fixture.execution.lease.ImplementationVersion = "runtime-correlation-v3"
			case "wrong index receipt":
				index, err := runtimeevent.DecodeStageReceipt(fixture.artifacts.input.Body)
				if err != nil {
					t.Fatal(err)
				}
				index.ItemIDs = []string{"evt_" + strings.Repeat("c", 64)}
				body, digest, reference, err := runtimeevent.EncodeStageReceipt(index)
				if err != nil {
					t.Fatal(err)
				}
				fixture.artifacts.input.Body, fixture.artifacts.input.Size, fixture.artifacts.input.SHA256 = body, int64(len(body)), digest
				fixture.artifacts.input.Locator.Reference = reference
				fixture.execution.lease.InputReference = runtimeTestReceiptReference(fixture.execution.lease, reference.String())
				fixture.artifacts.inputReference = fixture.execution.lease.InputReference
			}
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			if effect, err := executor.ExecuteAuthorized(ctx, fixture.execution); err == nil || effect != (runtimeStageEffect{}) || fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 {
				t.Fatal("unbound v2 execution produced effects")
			}
			if (name == "missing worker" || name == "missing token" || name == "wrong version") && (calls != 0 || fixture.artifacts.getCalls != 0) {
				t.Fatal("invalid execution reached dependencies")
			}
		})
	}
}

func TestFrozenCorrelationExecutorClassifiesCandidateFailuresWithoutProviderDetails(t *testing.T) {
	for _, scenario := range []struct{ failure, want error }{
		{runtimeevent.ErrCandidateSnapshotDenied, errRuntimeStageDenied},
		{runtimeevent.ErrCandidateSnapshotOverflow, errRuntimeStageMalformed},
		{runtimeevent.ErrProductionPipeline, errRuntimeStageMalformed},
		{runtimeevent.ErrProductionPipelineUnavailable, errRuntimeStageRetryable},
		{errors.New("private-provider-message"), errWorkerExecution},
	} {
		fixture := newFrozenExecutorFixture(t)
		fixture.config.Candidates = runtimeCandidateAuthorityFunc(func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
			return runtimeevent.FrozenCandidateSnapshot{}, scenario.failure
		})
		executor, err := newRuntimeCorrelationExecutor(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		effect, err := executor.ExecuteAuthorized(context.Background(), fixture.execution)
		if !errors.Is(err, scenario.want) || strings.Contains(err.Error(), "private-provider-message") || effect != (runtimeStageEffect{}) || fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 {
			t.Fatal("candidate failure classification", err)
		}
	}
}

func TestFrozenCorrelationExecutorRequiresConfiguredCandidateAuthority(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	fixture.config.Candidates = nil
	if _, err := newRuntimeCorrelationExecutor(fixture.config); err == nil {
		t.Fatal("v2 missing candidate authority accepted")
	}
}

func TestFrozenCorrelationExecutorContinuesAfterConfirmedLeaseRenewal(t *testing.T) {
	for _, failures := range []int{0, 1, 2} {
		t.Run(fmt.Sprint("uncertain-responses-", failures), func(t *testing.T) { proveFrozenExecutionRenewal(t, failures) })
	}
}

func proveFrozenExecutionRenewal(t *testing.T, failures int) {
	t.Helper()
	fixture := newFrozenExecutorFixture(t)
	fixture.execution.lease.LeaseExpiresAt = time.Now().Add(150 * time.Millisecond)
	renewed := make(chan struct{}, 1)
	authority := &renewalCheckingStageAuthority{runtimeStageAuthorityStub: &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{fixture.execution.lease}, heartbeatSeen: renewed}}
	calls := 0
	fixture.config.Candidates = runtimeCandidateAuthorityFunc(func(ctx context.Context, lease runtimeevent.StageLease, worker, token string, receipt, archive []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
		calls++
		if calls > 1 {
			if calls > 2 || !lease.LeaseExpiresAt.After(fixture.execution.lease.LeaseExpiresAt) {
				t.Fatal("replay lacked a confirmed newer lease window")
			}
			if failures > 1 {
				return runtimeevent.FrozenCandidateSnapshot{}, runtimeevent.ErrProductionPipelineUnavailable
			}
			return fixture.snapshot, nil
		}
		select {
		case <-renewed:
		case <-ctx.Done():
			return runtimeevent.FrozenCandidateSnapshot{}, ctx.Err()
		}
		// The declared stage authority renews to now+one minute. Complete this
		// simulated successful SQL response after the original claim deadline.
		timer := time.NewTimer(time.Until(fixture.execution.lease.LeaseExpiresAt.Add(10 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-timer.C:
			if failures > 0 {
				return runtimeevent.FrozenCandidateSnapshot{}, runtimeevent.ErrProductionPipelineUnavailable
			}
			return fixture.snapshot, nil
		case <-ctx.Done():
			return runtimeevent.FrozenCandidateSnapshot{}, ctx.Err()
		}
	})
	executor, err := newRuntimeCorrelationExecutor(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageCorrelate, ImplementationVersion: "runtime-correlation-v2", WorkerID: fixture.execution.workerID, LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return fixture.execution.leaseToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	wantOutcome, wantEffects, wantCalls := runtimeevent.StageOutcomeSucceeded, 1, 1
	if failures > 0 {
		wantCalls = 2
	}
	if failures > 1 {
		wantOutcome, wantEffects = runtimeevent.StageOutcomeRetryable, 0
	}
	if authority.heartbeats == 0 || len(authority.finishes) != 1 || authority.finishes[0].Outcome != wantOutcome || fixture.graph.calls != wantEffects || fixture.artifacts.putCalls != wantEffects || calls != wantCalls {
		t.Fatal("confirmed lease renewal didn't preserve executor progress")
	}
}

type renewalCheckingStageAuthority struct{ *runtimeStageAuthorityStub }

func (authority *renewalCheckingStageAuthority) HeartbeatStage(ctx context.Context, lease runtimeevent.StageLease, worker, token string, seconds int) (time.Time, error) {
	if !lease.LeaseExpiresAt.After(time.Now()) {
		return time.Time{}, runtimeevent.ErrProductionPipeline
	}
	return authority.runtimeStageAuthorityStub.HeartbeatStage(ctx, lease, worker, token, seconds)
}
func (authority *renewalCheckingStageAuthority) FinishStage(ctx context.Context, request runtimeevent.StageFinishRequest) (runtimeevent.StageFinishResult, error) {
	if !request.Lease.LeaseExpiresAt.After(time.Now()) {
		return runtimeevent.StageFinishResult{}, runtimeevent.ErrProductionPipeline
	}
	return authority.runtimeStageAuthorityStub.FinishStage(ctx, request)
}

func TestFrozenCorrelationExecutorReplaysGraphAfterReceiptFailure(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	fixture.artifacts.putErr = artifactstore.ErrPut
	executor, err := newRuntimeCorrelationExecutor(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if effect, err := executor.ExecuteAuthorized(context.Background(), fixture.execution); err == nil || effect != (runtimeStageEffect{}) || fixture.graph.calls != 1 || fixture.graph.mutations != 1 || fixture.artifacts.putCalls != 1 {
		t.Fatal("receipt failure didn't retain an uncertain graph effect")
	}
	firstDigest := fixture.graph.snapshot.InputDigest
	fixture.artifacts.putErr = nil
	effect, err := executor.ExecuteAuthorized(context.Background(), fixture.execution)
	if err != nil || effect.EffectDigest != firstDigest || fixture.graph.calls != 2 || fixture.graph.mutations != 1 || fixture.artifacts.putCalls != 2 {
		t.Fatal("fixed snapshot replay changed graph effects", err)
	}
	receipt, err := runtimecorrelation.DecodeReceipt(fixture.artifacts.put.Body)
	if err != nil || receipt.CandidateSnapshotDigest != fixture.snapshot.Digest() {
		t.Fatal("retry receipt changed frozen provenance", err)
	}
}

func TestFrozenCorrelationExecutorRejectsCancellationAfterEffects(t *testing.T) {
	for _, phase := range []string{"graph", "receipt"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newFrozenExecutorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "graph" {
				fixture.config.Graph = frozenGraphFunc(func(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
					result, err := fixture.graph.ApplySnapshot(ctx, snapshot)
					cancel()
					return result, err
				})
			} else {
				fixture.config.Receipts = frozenCancelArtifactStore{fixture.artifacts, cancel}
			}
			executor, err := newRuntimeCorrelationExecutor(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			effect, err := executor.ExecuteAuthorized(ctx, fixture.execution)
			if !errors.Is(err, errRuntimeStageRetryable) || effect != (runtimeStageEffect{}) || fixture.graph.calls != 1 {
				t.Fatal("canceled effect was reported as completed", err)
			}
			if phase == "graph" && fixture.artifacts.putCalls != 0 {
				t.Fatal("receipt write followed known cancellation")
			}
			if phase == "receipt" && fixture.artifacts.putCalls != 1 {
				t.Fatal("test didn't cross the receipt write boundary")
			}
		})
	}
}

type frozenGraphFunc func(context.Context, graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error)

func (function frozenGraphFunc) ApplySnapshot(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
	return function(ctx, snapshot)
}

type frozenCancelArtifactStore struct {
	*runtimeCorrelationArtifactStoreStub
	cancel context.CancelFunc
}

func (store frozenCancelArtifactStore) Put(ctx context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	result, err := store.runtimeCorrelationArtifactStoreStub.Put(ctx, request)
	store.cancel()
	return result, err
}

type frozenExecutorFixture struct {
	config    runtimeCorrelationExecutorConfig
	execution runtimeStageExecution
	artifacts *runtimeCorrelationArtifactStoreStub
	graph     *runtimeCorrelationGraphStoreStub
	archive   []byte
	snapshot  runtimeevent.FrozenCandidateSnapshot
}

func newFrozenExecutorFixture(t *testing.T) frozenExecutorFixture {
	t.Helper()
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageCorrelate)
	lease.ImplementationVersion = "runtime-correlation-v2"
	body := runtimeOTLPIndexBody()
	archiveDigest, indexDigest := sha256.Sum256(body), sha256.Sum256([]byte("frozen-index-effect"))
	lease.InputDigest, lease.PredecessorDigest = indexDigest, &indexDigest
	indexBody, indexObjectDigest, indexReference, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: lease.Scope, BatchID: lease.BatchID, Generation: lease.Generation, InputReference: "s3://zasp-evidence/runtime/v15/raw.json", InputVersionID: "raw-version", InputDigest: archiveDigest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "raw-version", ArchiveDigest: archiveDigest, EffectDigest: indexDigest})
	if err != nil {
		t.Fatal(err)
	}
	lease.InputReference, lease.InputVersionID = runtimeTestReceiptReference(lease, indexReference.String()), "index-receipt-version"
	artifacts := &runtimeCorrelationArtifactStoreStub{inputReference: lease.InputReference, input: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: lease.Scope, Reference: indexReference, VersionID: lease.InputVersionID}, MediaType: "application/json", Body: indexBody, Size: int64(len(indexBody)), SHA256: indexObjectDigest}, outputReference: runtimeTestReceiptReference(lease, mustProductID(t, "pid_00000092-0000-4000-8000-000000000092").String())}
	graph := &runtimeCorrelationGraphStoreStub{}
	// Declared unpaired semantic snapshot, decoded by the production repository.
	snapshotBody, err := json.Marshal(map[string]any{"schema": "runtime-candidate-snapshot-v1", "organization_id": lease.Scope.OrganizationID().String(), "workspace_id": lease.Scope.WorkspaceID().String(), "environment_id": lease.Scope.EnvironmentID().String(), "batch_id": lease.BatchID.String(), "generation": lease.Generation, "source_sensor_id": "pid_00000095-0000-4000-8000-000000000095", "runtime_sensor_id": nil, "archive_digest": hex.EncodeToString(archiveDigest[:]), "index_receipt_digest": hex.EncodeToString(indexObjectDigest[:]), "window_seconds": 300, "candidates": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest := sha256.Sum256(snapshotBody)
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(snapshotBody), "sha256": hex.EncodeToString(snapshotDigest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(frozenExecutorDatabase{envelope}, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	execution := runtimeStageExecution{lease: lease, workerID: "candidate-worker-01", leaseToken: strings.Repeat("a", 32)}
	snapshot, err := repository.FreezeCandidates(context.Background(), lease, execution.workerID, execution.leaseToken, indexBody, body)
	if err != nil {
		t.Fatal(err)
	}
	return frozenExecutorFixture{config: runtimeCorrelationExecutorConfig{Reader: &runtimeArchivedReaderStub{body: body}, Receipts: artifacts, Graph: graph, ImplementationVersion: "runtime-correlation-v2", Candidates: repository}, execution: execution, artifacts: artifacts, graph: graph, archive: body, snapshot: snapshot}
}

type frozenExecutorDatabase struct{ envelope json.RawMessage }

func (database frozenExecutorDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return bytes.Clone(database.envelope), nil
}

type runtimeCandidateAuthorityFunc func(context.Context, runtimeevent.StageLease, string, string, []byte, []byte) (runtimeevent.FrozenCandidateSnapshot, error)

func (function runtimeCandidateAuthorityFunc) FreezeCandidates(ctx context.Context, lease runtimeevent.StageLease, worker, token string, receipt, archive []byte) (runtimeevent.FrozenCandidateSnapshot, error) {
	return function(ctx, lease, worker, token, receipt, archive)
}
