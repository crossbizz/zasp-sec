package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeStageRenewalRejectsSuccessAfterHeartbeatTimeout(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	execution := fixture.execution
	execution.renewal = &runtimeStageLeaseRenewal{expiresAt: execution.lease.LeaseExpiresAt}
	executor, err := newRuntimeCorrelationExecutor(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	authority := &lateRuntimeHeartbeatAuthority{runtimeStageAuthorityStub: &runtimeStageAuthorityStub{}}
	processor := &runtimeStageProcessor{config: runtimeStageProcessorConfig{Authority: authority, Executor: executor, HeartbeatInterval: 10 * time.Millisecond, LeaseSeconds: 5}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go processor.keepStageLease(ctx, cancel, execution, done)
	select {
	case err := <-done:
		if !errors.Is(err, errWorkerExecution) {
			t.Fatal("late heartbeat wasn't rejected", err)
		}
	case <-time.After(200 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("late successful heartbeat kept renewing execution")
	}
	if ctx.Err() == nil || execution.currentLease().LeaseExpiresAt != execution.lease.LeaseExpiresAt {
		t.Fatal("late success published a confirmed expiry")
	}
	if effect, err := executor.ExecuteAuthorized(ctx, execution); err == nil || effect != (runtimeStageEffect{}) || fixture.artifacts.getCalls != 0 || fixture.graph.calls != 0 || fixture.artifacts.putCalls != 0 {
		t.Fatal("rejected renewal authorized further effects")
	}
}

func TestRuntimeStageRenewalDropsSuccessDuringOrderlyShutdown(t *testing.T) {
	fixture := newFrozenExecutorFixture(t)
	execution := fixture.execution
	execution.renewal = &runtimeStageLeaseRenewal{expiresAt: execution.lease.LeaseExpiresAt}
	entered := make(chan struct{})
	authority := &lateRuntimeHeartbeatAuthority{runtimeStageAuthorityStub: &runtimeStageAuthorityStub{}, entered: entered}
	processor := &runtimeStageProcessor{config: runtimeStageProcessorConfig{Authority: authority, HeartbeatInterval: 10 * time.Millisecond, LeaseSeconds: 5}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go processor.keepStageLease(ctx, cancel, execution, done)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("heartbeat didn't enter")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || execution.currentLease().LeaseExpiresAt != execution.lease.LeaseExpiresAt {
			t.Fatal("orderly cancellation renewed or reported lease loss", err)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat didn't shut down")
	}
}

func TestRuntimeStageProcessorRejectsCanceledCallerAfterFinish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease := runtimeStageLease(t, runtimeevent.RuntimeStageArchive)
	authority := &cancelingStageFinishAuthority{runtimeStageAuthorityStub: &runtimeStageAuthorityStub{leases: []runtimeevent.StageLease{lease}}, cancel: cancel}
	executor := runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{EffectDigest: lease.InputDigest, ResultDigest: lease.InputDigest, ResultReference: lease.InputReference, ResultVersionID: lease.InputVersionID}, nil
	})
	processor, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: authority, Executor: executor, Stage: runtimeevent.RuntimeStageArchive, ImplementationVersion: lease.ImplementationVersion, WorkerID: "runtime-archive-01", LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, RetrySeconds: 30, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(ctx); !errors.Is(err, errWorkerExecution) || len(authority.finishes) != 1 {
		t.Fatal("late finish success ignored caller cancellation", err)
	}
}

type cancelingStageFinishAuthority struct {
	*runtimeStageAuthorityStub
	cancel context.CancelFunc
}

func (authority *cancelingStageFinishAuthority) FinishStage(ctx context.Context, request runtimeevent.StageFinishRequest) (runtimeevent.StageFinishResult, error) {
	result, err := authority.runtimeStageAuthorityStub.FinishStage(ctx, request)
	authority.cancel()
	return result, err
}

type lateRuntimeHeartbeatAuthority struct {
	*runtimeStageAuthorityStub
	entered chan struct{}
}

func (authority *lateRuntimeHeartbeatAuthority) HeartbeatStage(ctx context.Context, _ runtimeevent.StageLease, _, _ string, _ int) (time.Time, error) {
	if authority.entered != nil {
		close(authority.entered)
	}
	<-ctx.Done()
	return time.Now().Add(time.Minute), nil
}
