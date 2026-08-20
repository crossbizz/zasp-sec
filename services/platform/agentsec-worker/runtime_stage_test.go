package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeStageProcessorKeepsLeaseUntilDurableSuccess(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageArchive)
	heartbeatSeen := make(chan struct{}, 1)
	authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{lease}, heartbeatSeen: heartbeatSeen}
	effect := runtimeStageEffect{EffectDigest: sha256.Sum256([]byte("archive-effect")), ResultReference: lease.InputReference, ResultVersionID: lease.InputVersionID, ResultDigest: lease.InputDigest}
	executor := runtimeStageExecutorFunc(func(ctx context.Context, claimed runtimeevent.StageLease) (runtimeStageEffect, error) {
		if claimed != lease {
			t.Fatalf("lease=%#v", claimed)
		}
		select {
		case <-heartbeatSeen:
			return effect, nil
		case <-ctx.Done():
			return runtimeStageEffect{}, ctx.Err()
		}
	})
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageArchive, ImplementationVersion: "runtime-archive-v1", WorkerID: "runtime-archive-01", LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authority.heartbeats != 1 || len(authority.finishes) != 1 {
		t.Fatalf("heartbeats=%d finishes=%#v", authority.heartbeats, authority.finishes)
	}
	finish := authority.finishes[0]
	if finish.Outcome != runtimeevent.StageOutcomeSucceeded || finish.EffectDigest != effect.EffectDigest || finish.ResultReference != effect.ResultReference || finish.ResultVersionID != effect.ResultVersionID || finish.ResultDigest != effect.ResultDigest {
		t.Fatalf("finish=%#v", finish)
	}
}

func TestRuntimeStageProcessorMapsOnlyStableFailureClasses(t *testing.T) {
	for name, test := range map[string]struct {
		err        error
		outcome    runtimeevent.StageOutcome
		errorClass string
		retry      time.Duration
	}{
		"retryable": {err: errRuntimeStageRetryable, outcome: runtimeevent.StageOutcomeRetryable, errorClass: "retryable", retry: 30 * time.Second},
		"denied":    {err: errRuntimeStageDenied, outcome: runtimeevent.StageOutcomeFailed, errorClass: "denied"},
		"malformed": {err: errRuntimeStageMalformed, outcome: runtimeevent.StageOutcomeQuarantined, errorClass: "malformed"},
		"unknown":   {err: errors.New("provider-secret-must-not-escape"), outcome: runtimeevent.StageOutcomeUnknown, errorClass: "outcome_unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			lease := runtimeStageLease(t, runtimeevent.RuntimeStageIndex)
			authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{lease}}
			processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
				return runtimeStageEffect{}, test.err
			}), Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", WorkerID: "runtime-index-01", LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(authority.finishes) != 1 || authority.finishes[0].Outcome != test.outcome || authority.finishes[0].ErrorClass != test.errorClass || authority.finishes[0].RetryAfter != test.retry || authority.finishes[0].ResultReference != "" {
				t.Fatalf("finish=%#v", authority.finishes)
			}
		})
	}
}

func TestRuntimeStageProcessorCancelsOnLeaseLossWithoutFinishing(t *testing.T) {
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageProject)
	authority := &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{lease}, heartbeatErr: errors.New("lease lost")}
	canceled := make(chan struct{})
	executor := runtimeStageExecutorFunc(func(ctx context.Context, _ runtimeevent.StageLease) (runtimeStageEffect, error) {
		<-ctx.Done()
		close(canceled)
		return runtimeStageEffect{}, ctx.Err()
	})
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageProject, ImplementationVersion: "runtime-projection-v1", WorkerID: "runtime-projection-01", LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("RunOnce=%v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("executor was not canceled")
	}
	if len(authority.finishes) != 0 {
		t.Fatalf("finishes=%#v", authority.finishes)
	}
}

type runtimeStageAuthorityStub struct {
	mu            sync.Mutex
	leases        []runtimeevent.StageLease
	heartbeatSeen chan<- struct{}
	heartbeatErr  error
	heartbeats    int
	finishes      []runtimeevent.StageFinishRequest
}

func (*runtimeStageAuthorityStub) Ready(context.Context) error { return nil }
func (authority *runtimeStageAuthorityStub) ClaimStages(context.Context, string, string, int, int) ([]runtimeevent.StageLease, error) {
	return append([]runtimeevent.StageLease(nil), authority.leases...), nil
}
func (authority *runtimeStageAuthorityStub) HeartbeatStage(context.Context, runtimeevent.StageLease, string, string, int) (time.Time, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.heartbeats++
	if authority.heartbeatSeen != nil {
		select {
		case authority.heartbeatSeen <- struct{}{}:
		default:
		}
	}
	if authority.heartbeatErr != nil {
		return time.Time{}, authority.heartbeatErr
	}
	return time.Now().Add(time.Minute), nil
}
func (authority *runtimeStageAuthorityStub) FinishStage(_ context.Context, request runtimeevent.StageFinishRequest) (runtimeevent.StageFinishResult, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.finishes = append(authority.finishes, request)
	return runtimeevent.StageFinishResult{BatchID: request.Lease.BatchID, Generation: request.Lease.Generation, Stage: request.Lease.Stage, State: request.Outcome, Attempt: request.Lease.Attempt, InputDigest: request.Lease.InputDigest, ImplementationVersion: request.Lease.ImplementationVersion, EffectDigest: request.EffectDigest, ResultReference: request.ResultReference, ResultVersionID: request.ResultVersionID, ResultDigest: request.ResultDigest, ErrorClass: request.ErrorClass}, nil
}

type runtimeStageExecutorFunc func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error)

func (function runtimeStageExecutorFunc) Execute(ctx context.Context, lease runtimeevent.StageLease) (runtimeStageEffect, error) {
	return function(ctx, lease)
}

func runtimeStageLease(t *testing.T, stage runtimeevent.RuntimeStage) runtimeevent.StageLease {
	t.Helper()
	versions := map[runtimeevent.RuntimeStage]string{
		runtimeevent.RuntimeStageArchive: "runtime-archive-v1", runtimeevent.RuntimeStageIndex: "runtime-index-v1", runtimeevent.RuntimeStageCorrelate: "runtime-correlation-v1", runtimeevent.RuntimeStageProject: "runtime-projection-v1", runtimeevent.RuntimeStageComplete: "runtime-complete-v1",
	}
	return runtimeevent.StageLease{Scope: workerScope(t), BatchID: workerID(t, "pid_70000002-0000-4000-8000-000000000001"), Generation: 1, Stage: stage, Attempt: 1, ImplementationVersion: versions[stage], InputDigest: sha256.Sum256([]byte("stage-input")), InputReference: "s3://runtime-evidence/runtime/v15/input.json", InputVersionID: "stage-input-version-1", LeaseExpiresAt: time.Now().Add(time.Minute)}
}
