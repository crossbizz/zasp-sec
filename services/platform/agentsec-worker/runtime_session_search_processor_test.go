package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type sessionSearchAuthorityStub struct {
	lease        *runtimeSessionSearchLease
	claimed      bool
	finishes     int
	outcome      string
	ids          []string
	heartbeatErr error
	finishErr    error
	heartbeats   atomic.Int32
}

func (*sessionSearchAuthorityStub) Ready(context.Context) error { return nil }
func (stub *sessionSearchAuthorityStub) Claim(context.Context, string, string, int) (*runtimeSessionSearchLease, error) {
	if stub.claimed {
		return nil, nil
	}
	stub.claimed = true
	return stub.lease, nil
}
func (stub *sessionSearchAuthorityStub) Heartbeat(context.Context, runtimeSessionSearchLease, string, string, int) (time.Time, error) {
	stub.heartbeats.Add(1)
	return time.Now().Add(5 * time.Second), stub.heartbeatErr
}
func (stub *sessionSearchAuthorityStub) Finish(_ context.Context, _ runtimeSessionSearchLease, _, _, outcome string, ids []string, _ int) error {
	stub.finishes++
	stub.outcome = outcome
	stub.ids = slices.Clone(ids)
	return stub.finishErr
}

type sessionSearchExecuteFunc func(context.Context, runtimeSessionSearchLease) ([]string, error)

func (fn sessionSearchExecuteFunc) Execute(ctx context.Context, lease runtimeSessionSearchLease) ([]string, error) {
	return fn(ctx, lease)
}

func searchProcessorConfig(authority runtimeSessionSearchAuthority, executor runtimeSessionSearchWork) runtimeSessionSearchProcessorConfig {
	return runtimeSessionSearchProcessorConfig{Authority: authority, Executor: executor, WorkerID: "search-worker", LeaseSeconds: 5, BatchSize: 2, HeartbeatInterval: 10 * time.Millisecond, RetrySeconds: 5, NewLeaseToken: func() (string, error) { return "search-lease-token-0001", nil }}
}

func TestRuntimeSessionSearchProcessorCheckpointsOnlyExactLiveLease(t *testing.T) {
	for _, fault := range []string{"none", "wrong ids", "execution error", "malformed", "panic", "lost heartbeat", "lost finish"} {
		t.Run(fault, func(t *testing.T) {
			lease, _, _ := sessionSearchWorkerFixture(t)
			authority := &sessionSearchAuthorityStub{lease: &lease}
			if fault == "lost heartbeat" {
				authority.heartbeatErr = errWorkerExecution
			}
			if fault == "lost finish" {
				authority.finishErr = errWorkerExecution
			}
			executor := sessionSearchExecuteFunc(func(ctx context.Context, lease runtimeSessionSearchLease) ([]string, error) {
				switch fault {
				case "wrong ids":
					return []string{"forged"}, nil
				case "execution error":
					return nil, errRuntimeStageRetryable
				case "malformed":
					return nil, errRuntimeStageMalformed
				case "panic":
					panic("provider detail")
				case "lost heartbeat":
					<-ctx.Done()
					return slices.Clone(lease.DocumentIDs), nil
				}
				return slices.Clone(lease.DocumentIDs), nil
			})
			processor, err := newRuntimeSessionSearchProcessor(searchProcessorConfig(authority, executor))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = processor.RunOnce(ctx)
			if fault == "none" {
				if err != nil || authority.finishes != 1 || authority.outcome != "indexed" || authority.heartbeats.Load() < 1 {
					t.Fatalf("successful checkpoint err=%v finish=%d heartbeats=%d", err, authority.finishes, authority.heartbeats.Load())
				}
				return
			}
			if err == nil {
				t.Fatal("failure was reported successful")
			}
			if fault == "lost heartbeat" {
				if authority.finishes != 0 {
					t.Fatal("lease loss allowed checkpoint")
				}
				return
			}
			if authority.finishes != 1 {
				t.Fatalf("failure did not preserve retry/quarantine: %d", authority.finishes)
			}
			want := "retryable"
			if fault == "malformed" {
				want = "quarantined"
			}
			if fault == "lost finish" {
				want = "indexed"
			}
			if authority.outcome != want {
				t.Fatalf("outcome=%s want=%s", authority.outcome, want)
			}
		})
	}
}

func TestRuntimeSessionSearchProcessorCancelsLateSuccessAndDoesNotStarveIndependentWork(t *testing.T) {
	lease, _, _ := sessionSearchWorkerFixture(t)
	authority := &sessionSearchAuthorityStub{lease: &lease}
	ctx, cancel := context.WithCancel(context.Background())
	executor := sessionSearchExecuteFunc(func(context.Context, runtimeSessionSearchLease) ([]string, error) {
		cancel()
		return lease.DocumentIDs, nil
	})
	processor, _ := newRuntimeSessionSearchProcessor(searchProcessorConfig(authority, executor))
	if processor.RunOnce(ctx) == nil || authority.finishes != 0 {
		t.Fatal("late success committed after cancellation")
	}
	var order []string
	combined := runtimeIndexAndSessionProcessor{raw: workerProcessorFunc(func(context.Context) error { order = append(order, "raw"); return errors.New("raw unavailable") }), sessions: workerProcessorFunc(func(context.Context) error { order = append(order, "sessions"); return nil })}
	if combined.RunOnce(context.Background()) == nil || !slices.Equal(order, []string{"raw", "sessions"}) {
		t.Fatalf("independent indexing was starved: %v", order)
	}
}

type workerProcessorFunc func(context.Context) error

func (fn workerProcessorFunc) RunOnce(ctx context.Context) error { return fn(ctx) }

func TestRuntimeSessionSearchProductionCompositionRejectsMissingIndexer(t *testing.T) {
	stage := &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageIndex, Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
		return runtimeStageEffect{}, nil
	}), ready: func(context.Context) error { return nil }, close: func() error { return nil }}
	if _, err := composeRuntimeStageWorkerRuntime(validRuntimeIndexConfig(), readyWorkerDatabase{}, stage); err == nil {
		t.Fatal("production index service started without session indexing")
	}
}

type isolatedSessionReadinessDatabase struct {
	readyWorkerDatabase
	rawClaims, sessionClaims int
	sessionUnavailable       bool
}

func (db *isolatedSessionReadinessDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if strings.Contains(statement, "zasp_runtime_claim_stage") {
		db.rawClaims++
		return json.RawMessage(`[]`), nil
	}
	if strings.Contains(statement, "zasp_runtime_session_search_claim") {
		db.sessionClaims++
		return json.RawMessage(`null`), nil
	}
	if strings.Contains(statement, "zasp_production_runtime_session_search_readiness") && db.sessionUnavailable {
		return json.RawMessage(`false`), nil
	}
	return db.readyWorkerDatabase.QueryJSON(ctx, statement, args...)
}
func TestRuntimeSessionSearchReadinessOutageDoesNotStarveRawIndexing(t *testing.T) {
	for _, fault := range []string{"index", "database"} {
		t.Run(fault, func(t *testing.T) {
			db := &isolatedSessionReadinessDatabase{sessionUnavailable: fault == "database"}
			stage := &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageIndex, Executor: runtimeStageExecutorFunc(func(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error) {
				return runtimeStageEffect{}, nil
			}), Sessions: sessionSearchExecuteFunc(func(context.Context, runtimeSessionSearchLease) ([]string, error) {
				t.Fatal("unready session executor ran")
				return nil, nil
			}), SessionReady: func(context.Context) error {
				if fault == "index" {
					return errRuntimeUnavailable
				}
				return nil
			}, ready: func(context.Context) error { return nil }, close: func() error { return nil }}
			dependencies, err := composeRuntimeStageWorkerRuntime(validRuntimeIndexConfig(), db, stage)
			if err != nil {
				t.Fatal(err)
			}
			if dependencies.Processor.RunOnce(context.Background()) == nil || db.rawClaims != 1 || db.sessionClaims != 0 {
				t.Fatalf("outage starved raw or admitted session work: raw=%d session=%d", db.rawClaims, db.sessionClaims)
			}
			if dependencies.Ready(context.Background()) == nil {
				t.Fatal("degraded search was reported healthy")
			}
		})
	}
}
