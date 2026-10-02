package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// These checks exercise the orchestration used by the database helper without
// starting PostgreSQL. RunOnce is the external-work boundary.
func TestCombinedTemporaryPolicyPolling(t *testing.T) {
	t.Run("empty polls cannot complete", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		var polls atomic.Int32
		err := runCombinedE2ETemporaryPolicyWorkers(ctx, workerProcessorFunc(func(context.Context) error {
			polls.Add(1)
			return nil
		}), workerProcessorFunc(func(context.Context) error { return nil }), time.Millisecond, func() bool { return false })
		if !errors.Is(err, context.DeadlineExceeded) || polls.Load() < 2 {
			t.Fatalf("empty polling returned err=%v polls=%d", err, polls.Load())
		}
	})
	t.Run("failed attempt and empty poll precede actual completion", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var polls atomic.Int32
		var finished atomic.Bool
		var deployed atomic.Bool
		err := runCombinedE2ETemporaryPolicyWorkers(ctx, workerProcessorFunc(func(ctx context.Context) error {
			switch polls.Add(1) {
			case 1:
				return apiserver.ErrRepositoryConflict
			case 2:
				return nil
			}
			if deployed.Load() {
				finished.Store(true)
			}
			return nil
		}), workerProcessorFunc(func(context.Context) error { deployed.Store(true); return nil }), time.Millisecond, finished.Load)
		if err != nil || !finished.Load() || polls.Load() < 3 {
			t.Fatalf("premature completion: err=%v finished=%v polls=%d", err, finished.Load(), polls.Load())
		}
	})
	for _, worker := range []string{"action", "deployment"} {
		t.Run(worker+" errors survive timeout", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			attemptErr := errors.New("persistent " + worker + " failure")
			var attempts atomic.Int32
			failed := workerProcessorFunc(func(context.Context) error { attempts.Add(1); return attemptErr })
			action, deployment := workerProcessor(workerProcessorFunc(func(context.Context) error { return nil })), workerProcessor(failed)
			if worker == "action" {
				action, deployment = deployment, action
			}
			err := runCombinedE2ETemporaryPolicyWorkers(ctx, action, deployment, time.Millisecond, func() bool { return false })
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, attemptErr) || attempts.Load() < 2 || !strings.Contains(err.Error(), worker) {
				t.Fatalf("lost polling diagnosis: err=%v attempts=%d", err, attempts.Load())
			}
		})
	}
	for _, exit := range []string{"cancel", "timeout", "action terminal", "deployment terminal", "complete"} {
		t.Run(exit+" joins both workers", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			actionStarted, deploymentStarted := make(chan struct{}), make(chan struct{})
			actionExited, deploymentExited := make(chan struct{}), make(chan struct{})
			finished := false // Only read/written by the action loop.
			action := workerProcessorFunc(func(ctx context.Context) error {
				close(actionStarted)
				defer close(actionExited)
				<-deploymentStarted
				if exit == "cancel" {
					cancel()
				}
				if exit == "action terminal" {
					return context.Canceled
				}
				if exit == "complete" {
					finished = true
					return nil
				}
				<-ctx.Done()
				return ctx.Err()
			})
			deployment := workerProcessorFunc(func(ctx context.Context) error {
				close(deploymentStarted)
				defer close(deploymentExited)
				<-actionStarted
				if exit == "deployment terminal" {
					return context.Canceled
				}
				<-ctx.Done()
				return ctx.Err()
			})
			err := runCombinedE2ETemporaryPolicyWorkers(ctx, action, deployment, time.Hour, func() bool { return finished })
			if exit == "complete" && err != nil {
				t.Fatalf("completion: %v", err)
			}
			if exit != "complete" && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if strings.Contains(exit, "terminal") && ctx.Err() != nil {
				t.Fatalf("terminal worker error waited for parent timeout: %v", err)
			}
			for name, joined := range map[string]<-chan struct{}{"action": actionExited, "deployment": deploymentExited} {
				select {
				case <-joined:
				default:
					t.Errorf("%s still running after return", name)
				}
			}
		})
	}
}

type combinedFinishAuthority struct {
	apiserver.SecurityAgentActionAuthority
	result apiserver.TemporaryPolicyFinishResult
	err    error
}

// The database seam models one refused store, one empty claim poll, then an
// eligible claim. Natural database lease expiry is covered by the owned proof.
type combinedRecoveringAuthority struct {
	*temporaryPolicyAuthorityFixture
	claim  apiserver.TemporaryPolicyEffectClaim
	polls  int
	stores int
}

func (authority *combinedRecoveringAuthority) ClaimTemporaryPolicyEffects(context.Context, string, string, int, int) ([]apiserver.TemporaryPolicyEffectClaim, error) {
	authority.polls++
	if authority.polls == 2 {
		return nil, nil
	}
	return []apiserver.TemporaryPolicyEffectClaim{authority.claim}, nil
}

func (authority *combinedRecoveringAuthority) StoreTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, lease string, envelope apiserver.TemporaryPolicyTargetEnvelope) error {
	authority.stores++
	if authority.stores == 1 {
		return apiserver.ErrRepositoryConflict
	}
	return authority.temporaryPolicyAuthorityFixture.StoreTemporaryPolicyTarget(ctx, claim, worker, lease, envelope)
}

func (authority *combinedRecoveringAuthority) ReadTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, target apiserver.TemporaryPolicyTarget) (apiserver.TemporaryPolicyTargetEnvelope, error) {
	if authority.stores == 1 {
		return apiserver.TemporaryPolicyTargetEnvelope{}, apiserver.ErrRepositoryNotFound
	}
	return authority.temporaryPolicyAuthorityFixture.ReadTemporaryPolicyTarget(ctx, claim, target)
}

func TestCombinedTemporaryPolicyRealProcessorCompletion(t *testing.T) {
	for _, action := range []string{"create_temporary_policy", "isolate_session"} {
		for _, phase := range []string{"apply", "cleanup"} {
			t.Run(action+"/"+phase, func(t *testing.T) {
				now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
				_, key, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				claim := apiserver.TemporaryPolicyEffectClaim{
					OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
					RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", ActionKey: action, Phase: phase, InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}},
				}
				if action == "isolate_session" {
					claim.SessionID = "pid_78000009-0000-4000-8000-000000000009"
				}
				authority := &combinedRecoveringAuthority{temporaryPolicyAuthorityFixture: &temporaryPolicyAuthorityFixture{}, claim: claim}
				observer := &combinedE2ETemporaryPolicyFinishObserver{SecurityAgentActionAuthority: authority, SecurityAgentConnectorRevocationAuthority: authority, expected: claim}
				processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{
					Authority: observer, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 8, HeartbeatInterval: 10 * time.Millisecond,
					KeyID: "gateway-key-01", PrivateKey: key, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: sequentialActionProductIDs(),
				})
				if err != nil {
					t.Fatal(err)
				}
				defer processor.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				err = runCombinedE2ETemporaryPolicyWorkers(ctx, processor, workerProcessorFunc(func(context.Context) error { return nil }), time.Millisecond, observer.finished.Load)
				if err != nil || !observer.finished.Load() || len(authority.finished) != 1 || len(authority.stored) != 1 || authority.polls < 3 || authority.reconcileCalls < 3 {
					t.Fatalf("err=%v observed=%v finishes=%d stored=%d polls=%d reconciles=%d", err, observer.finished.Load(), len(authority.finished), len(authority.stored), authority.polls, authority.reconcileCalls)
				}
			})
		}
	}
}

func (authority combinedFinishAuthority) FinishTemporaryPolicyEffect(context.Context, apiserver.TemporaryPolicyEffectClaim, string, string, string, string, string) (apiserver.TemporaryPolicyFinishResult, error) {
	return authority.result, authority.err
}

func TestCombinedTemporaryPolicyFinishObservation(t *testing.T) {
	for _, action := range []string{"create_temporary_policy", "isolate_session"} {
		for _, phase := range []string{"apply", "cleanup"} {
			t.Run(action+"/"+phase, func(t *testing.T) {
				claim := apiserver.TemporaryPolicyEffectClaim{OrganizationID: "org", WorkspaceID: "workspace", EnvironmentID: "environment", RunID: "run", StepID: "step", ActionKey: action, Phase: phase}
				state := "cleanup_pending"
				if phase == "cleanup" {
					state = "cleaned"
				}
				result := apiserver.TemporaryPolicyFinishResult{RunID: "run", StepID: "step", Phase: phase, EffectState: state, OutcomeID: "outcome", ResultDigest: "digest"}
				for _, mismatch := range []string{"none", "error", "organization", "workspace", "environment", "run", "action", "phase", "result run", "result step", "result phase", "result state", "result digest", "result outcome"} {
					t.Run(mismatch, func(t *testing.T) {
						gotClaim, gotResult := claim, result
						var finishErr error
						switch mismatch {
						case "error":
							finishErr = apiserver.ErrRepositoryConflict
						case "organization":
							gotClaim.OrganizationID = "foreign"
						case "workspace":
							gotClaim.WorkspaceID = "foreign"
						case "environment":
							gotClaim.EnvironmentID = "foreign"
						case "run":
							gotClaim.RunID = "foreign"
						case "action":
							gotClaim.ActionKey = "foreign"
						case "phase":
							gotClaim.Phase = "foreign"
						case "result run":
							gotResult.RunID = "foreign"
						case "result step":
							gotResult.StepID = "foreign"
						case "result phase":
							gotResult.Phase = "foreign"
						case "result state":
							gotResult.EffectState = "pending"
						case "result digest":
							gotResult.ResultDigest = "foreign"
						case "result outcome":
							gotResult.OutcomeID = ""
						}
						observer := &combinedE2ETemporaryPolicyFinishObserver{SecurityAgentActionAuthority: combinedFinishAuthority{result: gotResult, err: finishErr}, expected: claim}
						_, err := observer.FinishTemporaryPolicyEffect(context.Background(), gotClaim, "worker", "lease", "digest", "audit", "correlation")
						if !errors.Is(err, finishErr) {
							t.Fatalf("finish error changed: %v", err)
						}
						if observer.finished.Load() != (mismatch == "none") {
							t.Fatalf("completion=%v for %s", observer.finished.Load(), mismatch)
						}
					})
				}
			})
		}
	}
}
