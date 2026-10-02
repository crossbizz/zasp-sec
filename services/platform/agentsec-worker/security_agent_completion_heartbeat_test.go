package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type completionHeartbeatAuthority struct {
	*budgetHeartbeatAuthority
	operationErr error
	malformed    bool
}

func (a *completionHeartbeatAuthority) LoadSecurityAgentPlannerContext(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string) (apiserver.SecurityAgentPlannerContext, error) {
	return a.securityAgentWorkerAuthorityStub.LoadSecurityAgentPlannerContext(ctx, claim, worker, lease)
}
func (a *completionHeartbeatAuthority) AcceptSecurityAgentPlannerCandidate(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string, submission apiserver.SecurityAgentPlannerSubmission, approval string, expires time.Time, audit, correlation string) (apiserver.SecurityAgentPrepareResult, error) {
	result, err := a.securityAgentWorkerAuthorityStub.AcceptSecurityAgentPlannerCandidate(ctx, claim, worker, lease, submission, approval, expires, audit, correlation)
	if a.malformed {
		result.RunID = claim.TriggerID
	}
	close(a.contextEntered)
	<-ctx.Done()
	if a.operationErr != nil {
		err = a.operationErr
	}
	return result, err
}
func (a *completionHeartbeatAuthority) ExecuteSecurityAgentRun(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease, audit, correlation string) (apiserver.SecurityAgentExecuteResult, error) {
	result, err := a.securityAgentWorkerAuthorityStub.ExecuteSecurityAgentRun(ctx, claim, worker, lease, audit, correlation)
	if a.malformed {
		result.RunID = claim.TriggerID
	}
	close(a.contextEntered)
	<-ctx.Done()
	if a.operationErr != nil {
		err = a.operationErr
	}
	return result, err
}

func (a *completionHeartbeatAuthority) FailSecurityAgentPlanner(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string, failure apiserver.SecurityAgentPlannerFailure, audit, correlation string) (apiserver.SecurityAgentPlannerFailureResult, error) {
	result, err := a.securityAgentWorkerAuthorityStub.FailSecurityAgentPlanner(ctx, claim, worker, lease, failure, audit, correlation)
	if a.malformed {
		result.RunID = claim.TriggerID
	}
	close(a.contextEntered)
	<-ctx.Done()
	if a.operationErr != nil {
		err = a.operationErr
	}
	return result, err
}

func TestSecurityAgentCommittedCompletionHeartbeatRace(t *testing.T) {
	for _, phase := range []string{"accept", "execute", "fail"} {
		prepared := phase == "execute"
		for _, test := range []struct {
			name                 string
			operation, heartbeat error
			success              bool
		}{
			{"committed lease conflict", nil, apiserver.ErrRepositoryConflict, true},
			{"committed unrelated outage", nil, apiserver.ErrRepositoryUnavailable, false},
			{"unconfirmed lease conflict", apiserver.ErrRepositoryUnavailable, apiserver.ErrRepositoryConflict, false},
			{"operation conflict", apiserver.ErrRepositoryConflict, apiserver.ErrRepositoryConflict, false},
			{"malformed result", nil, apiserver.ErrRepositoryConflict, false},
		} {
			t.Run(phase+"/"+test.name, func(t *testing.T) {
				now := time.Now().UTC()
				base := &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", prepared, now)}}
				a := &completionHeartbeatAuthority{budgetHeartbeatAuthority: &budgetHeartbeatAuthority{securityAgentWorkerAuthorityStub: base, contextEntered: make(chan struct{}), heartbeatErr: test.heartbeat}, operationErr: test.operation}
				a.malformed = test.name == "malformed result"
				planner := successfulSecurityAgentPlanner()
				if phase == "fail" {
					planner.result.Failure = securityAgentPlannerRejected
				}
				generated := 0
				p, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: a, Planner: planner, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) {
					generated++
					return fmt.Sprintf("pid_78000010-0000-4000-8000-%012d", generated), nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				err = p.RunOnce(ctx)
				if ctx.Err() != nil || (err == nil) != test.success {
					t.Fatalf("result=%v context=%v wantSuccess=%v", err, ctx.Err(), test.success)
				}
				wantIDs := 3
				if phase != "accept" {
					wantIDs = 2
				}
				if generated != wantIDs || len(base.prepared)+len(base.executed)+len(base.failedPlanner) != 1 {
					t.Fatalf("duplicate/missing operation ids=%d prepared=%v executed=%v", generated, base.prepared, base.executed)
				}
			})
		}
	}
}
