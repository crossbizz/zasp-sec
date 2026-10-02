package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

// The processor is real; the authority, queue and runner are controlled at their
// I/O boundaries. These tests do not prove database settlement or external cancel.
func TestRedTeamLinkedProcessorLifecycle(t *testing.T) {
	for _, scenario := range []string{"complete", "unknown", "cancel", "cancel_unknown", "cancel_failure", "cancel_timeout", "cancel_wrong_run", "cancel_wrong_state", "cancel_wrong_error", "cancel_missing_flag", "cancel_expired", "cancel_shutdown", "cancel_no_capability", "cancel_after_renew", "expiry", "blocked_heartbeat", "missing_expiry", "contradictory_heartbeat", "expired_heartbeat", "unbounded_heartbeat", "visibility_failure", "missing_artifact", "finish_failure", "finish_expiry", "renew", "invalid_version", "expired_claim", "reconcile"} {
		t.Run(scenario, func(t *testing.T) {
			scope := fixtureRedTeamScope(t)
			runID := mustProductID(t, "pid_99200001-0000-4000-8000-000000000001")
			definitionID := "pid_99200002-0000-4000-8000-000000000002"
			digest := sha256.Sum256([]byte("linked-processor"))
			initial := time.Now().UTC().Add(250 * time.Millisecond)
			authority := &linkedRuntimeAuthority{claim: apiserver.RedTeamRunClaim{Disposition: "claimed", EvidenceVersion: "red-team-v2", InputDigest: digest, LeaseExpiresAt: initial, Run: apiserver.RedTeamRun{ID: runID.String(), DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1}, Definition: apiserver.RedTeamDefinition{ID: definitionID, Version: 1}}}
			queue := &linkedRuntimeQueue{delivery: jobqueue.Delivery{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "red-team", AuthorityDigest: digest, Payload: redTeamQueuePayload(t, scope, runID.String(), definitionID, 1, digest)}}}
			heartbeatStarted := make(chan struct{}, 1)
			renewed := time.Now().UTC().Add(3 * time.Second)
			if scenario == "expired_heartbeat" {
				renewed = time.Now().Add(-time.Second)
			}
			if scenario == "unbounded_heartbeat" {
				renewed = time.Now().Add(time.Hour)
			}
			queue.failVisibility = scenario == "visibility_failure"
			var cancelParent context.CancelFunc
			authority.linkedCancel = func(ctx context.Context) (apiserver.RedTeamRun, error) {
				if ctx.Err() != nil {
					return apiserver.RedTeamRun{}, ctx.Err()
				}
				deadline, ok := ctx.Deadline()
				bound := initial
				if scenario == "cancel_after_renew" {
					bound = renewed
				}
				if !ok || deadline.After(bound) {
					return apiserver.RedTeamRun{}, errors.New("cancel lacks original lease deadline")
				}
				if scenario == "cancel_failure" {
					return apiserver.RedTeamRun{}, errors.New("commit not acknowledged")
				}
				if scenario == "cancel_timeout" {
					<-ctx.Done()
					return apiserver.RedTeamRun{}, ctx.Err()
				}
				value := apiserver.RedTeamRun{ID: runID.String(), Status: "cancelled", CancelRequested: true, ErrorCode: "cancelled"}
				switch scenario {
				case "cancel_unknown":
					value.Status, value.ErrorCode = "failed", "outcome_unknown"
				case "cancel_wrong_run":
					value.ID = definitionID
				case "cancel_wrong_state":
					value.Status = "leased"
				case "cancel_wrong_error":
					value.ErrorCode = "outcome_unknown"
				case "cancel_missing_flag":
					value.CancelRequested = false
				}
				return value, nil
			}
			authority.finish = func(ctx context.Context) error {
				if scenario == "finish_failure" {
					return errors.New("commit not acknowledged")
				}
				if scenario == "finish_expiry" {
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}
			authority.heartbeat = func(ctx context.Context) (apiserver.RedTeamRunHeartbeat, error) {
				if scenario == "cancel_after_renew" && time.Now().Before(initial) {
					return apiserver.RedTeamRunHeartbeat{Renewed: true, LeaseExpiresAt: &renewed}, nil
				}
				select {
				case heartbeatStarted <- struct{}{}:
				default:
				}
				switch scenario {
				case "cancel", "cancel_unknown", "cancel_failure", "cancel_timeout", "cancel_wrong_run", "cancel_wrong_state", "cancel_wrong_error", "cancel_missing_flag", "cancel_expired", "cancel_shutdown", "cancel_no_capability", "cancel_after_renew":
					return apiserver.RedTeamRunHeartbeat{CancelRequested: true}, nil
				case "blocked_heartbeat":
					<-ctx.Done()
					return apiserver.RedTeamRunHeartbeat{}, ctx.Err()
				case "missing_expiry":
					return apiserver.RedTeamRunHeartbeat{Renewed: true}, nil
				case "contradictory_heartbeat":
					return apiserver.RedTeamRunHeartbeat{Renewed: true, CancelRequested: true, LeaseExpiresAt: &renewed}, nil
				default:
					return apiserver.RedTeamRunHeartbeat{Renewed: true, LeaseExpiresAt: &renewed}, nil
				}
			}
			var runs atomic.Int32
			runner := linkedRuntimeRunner(func(ctx context.Context, request redTeamExecutionRequest) (redTeamExecutionResult, error) {
				runs.Add(1)
				if request.EvidenceVersion != "red-team-v2" {
					return redTeamExecutionResult{}, errors.New("claim evidence version was lost")
				}
				switch scenario {
				case "unknown":
					return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown"}
				case "cancel", "cancel_unknown", "cancel_failure", "cancel_timeout", "cancel_wrong_run", "cancel_wrong_state", "cancel_wrong_error", "cancel_missing_flag", "cancel_expired", "cancel_shutdown", "cancel_no_capability", "cancel_after_renew", "expiry", "blocked_heartbeat", "missing_expiry", "contradictory_heartbeat", "expired_heartbeat", "unbounded_heartbeat", "visibility_failure":
					<-ctx.Done()
					if scenario == "cancel_expired" {
						<-time.After(time.Until(initial.Add(time.Millisecond)))
					}
					if scenario == "cancel_shutdown" {
						cancelParent()
					}
					return redTeamExecutionResult{}, ctx.Err()
				case "missing_artifact":
					return redTeamExecutionResult{Verdict: "pass"}, nil
				case "renew":
					select {
					case <-heartbeatStarted:
					case <-ctx.Done():
						return redTeamExecutionResult{}, ctx.Err()
					}
					timer := time.NewTimer(time.Until(initial.Add(100 * time.Millisecond)))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						return redTeamExecutionResult{}, ctx.Err()
					}
				}
				return redTeamExecutionResult{Verdict: "pass", InputArtifact: &apiserver.RedTeamArtifactReference{Reference: "controlled-input"}}, nil
			})
			interval := 20 * time.Millisecond
			if scenario == "expiry" || scenario == "finish_expiry" {
				interval = time.Second
			}
			if scenario == "invalid_version" {
				authority.claim.EvidenceVersion = "red-team-v3"
			}
			if scenario == "expired_claim" {
				authority.claim.LeaseExpiresAt = time.Now().Add(-time.Second)
			}
			if scenario == "reconcile" {
				authority.claim = apiserver.RedTeamRunClaim{Disposition: "reconcile_required"}
			}
			var selectedAuthority redTeamExecutionAuthority = authority
			if scenario == "cancel_no_capability" {
				selectedAuthority = struct{ redTeamExecutionAuthority }{authority}
			}
			processor, err := newRedTeamProcessor(redTeamProcessorConfig{Authority: selectedAuthority, Queue: queue, Runner: runner, WorkerID: "linked-worker", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: interval, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			cancelParent = cancel
			defer cancel()
			err = processor.RunOnce(ctx)
			if scenario == "complete" || scenario == "renew" {
				if err != nil || authority.finishes.Load() != 1 || queue.acks.Load() != 1 {
					t.Fatalf("completion err=%v finishes=%d acks=%d", err, authority.finishes.Load(), queue.acks.Load())
				}
			} else if scenario == "cancel" || scenario == "cancel_unknown" || scenario == "cancel_after_renew" {
				if err != nil || authority.finishes.Load() != 0 || queue.acks.Load() != 1 {
					t.Fatalf("durable cancellation err=%v finishes=%d acks=%d", err, authority.finishes.Load(), queue.acks.Load())
				}
			} else {
				wantFinish := int32(0)
				if scenario == "finish_failure" || scenario == "finish_expiry" {
					wantFinish = 1
				}
				if authority.finishes.Load() != wantFinish || queue.acks.Load() != 0 {
					t.Fatal("uncertain/stopped work was finalized or acknowledged")
				}
				if scenario != "reconcile" && err == nil {
					t.Fatal("stopped work returned success")
				}
			}
			if authority.retries.Load() != 0 || authority.cancels.Load() != 0 {
				t.Fatal("linked work used legacy retry/cancel")
			}
			wantCancel := int32(0)
			if strings.HasPrefix(scenario, "cancel") && scenario != "cancel_expired" && scenario != "cancel_shutdown" && scenario != "cancel_no_capability" {
				wantCancel = 1
			}
			if authority.linkedCancels.Load() != wantCancel {
				t.Fatalf("linked cancellations=%d want=%d", authority.linkedCancels.Load(), wantCancel)
			}
			if (scenario == "invalid_version" || scenario == "expired_claim" || scenario == "reconcile") && runs.Load() != 0 {
				t.Fatal("invalid/non-claim executed")
			}
			if scenario == "renew" && (queue.visibility.Load() < 1 || queue.visibility.Load() > 2) {
				t.Fatalf("visibility not capped/floored to DB expiry: %d", queue.visibility.Load())
			}
			if scenario == "expiry" || scenario == "blocked_heartbeat" || scenario == "finish_expiry" {
				if ctx.Err() != nil || time.Now().After(initial.Add(500*time.Millisecond)) {
					t.Fatal("runner outlived lease until outer timeout")
				}
			}
		})
	}
}

type linkedRuntimeRunner func(context.Context, redTeamExecutionRequest) (redTeamExecutionResult, error)

func (f linkedRuntimeRunner) Run(c context.Context, r redTeamExecutionRequest) (redTeamExecutionResult, error) {
	return f(c, r)
}

type linkedRuntimeAuthority struct {
	claim                      apiserver.RedTeamRunClaim
	heartbeat                  func(context.Context) (apiserver.RedTeamRunHeartbeat, error)
	finish                     func(context.Context) error
	linkedCancel               func(context.Context) (apiserver.RedTeamRun, error)
	linkedCancels              atomic.Int32
	finishes, retries, cancels atomic.Int32
}

func (*linkedRuntimeAuthority) Ready(context.Context) error { return nil }
func (a *linkedRuntimeAuthority) ClaimRedTeamRun(context.Context, domain.Scope, string, string, string, int) (apiserver.RedTeamRunClaim, error) {
	return a.claim, nil
}
func (a *linkedRuntimeAuthority) HeartbeatRedTeamRun(c context.Context, _ domain.Scope, _, _, _ string, _ int) (apiserver.RedTeamRunHeartbeat, error) {
	return a.heartbeat(c)
}
func (a *linkedRuntimeAuthority) FinishRedTeamRun(ctx context.Context, _ domain.Scope, c apiserver.RedTeamRunCompletion) (apiserver.RedTeamRun, error) {
	a.finishes.Add(1)
	if err := a.finish(ctx); err != nil {
		return apiserver.RedTeamRun{}, err
	}
	return apiserver.RedTeamRun{ID: c.RunID, Status: "complete"}, nil
}
func (a *linkedRuntimeAuthority) RetryRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte, string, time.Time) (apiserver.RedTeamRun, error) {
	a.retries.Add(1)
	return apiserver.RedTeamRun{Status: "retryable"}, nil
}
func (a *linkedRuntimeAuthority) CancelClaimedRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte) (apiserver.RedTeamRun, error) {
	a.cancels.Add(1)
	return apiserver.RedTeamRun{Status: "cancelled"}, nil
}

func (a *linkedRuntimeAuthority) CancelLinkedRedTeamRun(ctx context.Context, scope domain.Scope, run, worker, lease string, digest [sha256.Size]byte) (apiserver.RedTeamRun, error) {
	a.linkedCancels.Add(1)
	if scope.Validate() != nil || run != a.claim.Run.ID || worker != "linked-worker" || lease != strings.Repeat("a", 32) || digest != a.claim.InputDigest {
		return apiserver.RedTeamRun{}, errors.New("cancel authority lost")
	}
	return a.linkedCancel(ctx)
}

type linkedRuntimeQueue struct {
	delivery       jobqueue.Delivery
	acks           atomic.Int32
	visibility     atomic.Int64
	failVisibility bool
}

func (q *linkedRuntimeQueue) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	return []jobqueue.Delivery{q.delivery}, nil
}
func (q *linkedRuntimeQueue) AcknowledgeBatch(context.Context, []jobqueue.Receipt) error {
	q.acks.Add(1)
	return nil
}
func (q *linkedRuntimeQueue) ExtendVisibility(_ context.Context, _ []jobqueue.Receipt, d time.Duration) error {
	q.visibility.Store(int64(d / time.Second))
	if q.failVisibility || d < time.Second || d%time.Second != 0 {
		return errors.New("invalid visibility")
	}
	return nil
}
