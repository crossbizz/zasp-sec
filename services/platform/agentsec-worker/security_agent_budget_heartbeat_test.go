package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Coordinate the exact overlap: context handling is active when heartbeat
// fails, and returns its authoritative outcome only after cancellation arrives.
type budgetHeartbeatAuthority struct {
	*securityAgentWorkerAuthorityStub
	contextEntered chan struct{}
	heartbeatErr   error
	contextErr     error
}

type flatBudgetHeartbeatAuthority struct {
	*budgetHeartbeatAuthority
	shape                     string
	acceptCalls, executeCalls int
}

func (a *flatBudgetHeartbeatAuthority) LoadSecurityAgentPlannerContext(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string) (apiserver.SecurityAgentPlannerContext, error) {
	return a.securityAgentWorkerAuthorityStub.LoadSecurityAgentPlannerContext(ctx, claim, worker, lease)
}

func (a *flatBudgetHeartbeatAuthority) result(ctx context.Context, claim apiserver.SecurityAgentRunClaim) (string, int64, string, string, error) {
	close(a.contextEntered)
	<-ctx.Done()
	run, version, state, artifact := claim.RunID, claim.Version+1, "needs_human", ""
	switch a.shape {
	case "foreign run":
		run = claim.TriggerID
	case "wrong version":
		version = claim.Version
	case "heartbeat advanced":
		version++
	case "huge version":
		version = 1000001
	case "artifact":
		artifact = claim.TriggerID
	case "not stopped":
		state = "running"
	case "operation error":
		return run, version, state, artifact, apiserver.ErrRepositoryUnavailable
	}
	return run, version, state, artifact, nil
}

func (a *flatBudgetHeartbeatAuthority) ExecuteSecurityAgentRun(ctx context.Context, claim apiserver.SecurityAgentRunClaim, _, _, _, _ string) (apiserver.SecurityAgentExecuteResult, error) {
	a.executeCalls++
	run, version, state, artifact, err := a.result(ctx, claim)
	result := apiserver.SecurityAgentExecuteResult{RunID: run, Version: version, State: state, StepID: artifact}
	switch a.shape {
	case "effect state":
		result.EffectState = "pending"
	case "outcome ID":
		result.OutcomeID = claim.TriggerID
	case "result digest":
		result.ResultDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	return result, err
}

func (a *flatBudgetHeartbeatAuthority) AcceptSecurityAgentPlannerCandidate(ctx context.Context, claim apiserver.SecurityAgentRunClaim, _, _ string, _ apiserver.SecurityAgentPlannerSubmission, _ string, _ time.Time, _, _ string) (apiserver.SecurityAgentPrepareResult, error) {
	a.acceptCalls++
	run, version, state, artifact, err := a.result(ctx, claim)
	result := apiserver.SecurityAgentPrepareResult{RunID: run, Version: version, State: state, StepID: artifact}
	switch a.shape {
	case "approval ID":
		result.ApprovalID = claim.TriggerID
	case "plan hash":
		result.PlanHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	return result, err
}

func TestSecurityAgentFlatBudgetStopHeartbeatRace(t *testing.T) {
	for _, phase := range []string{"accept", "execute"} {
		shapes := []string{"stopped", "heartbeat advanced", "foreign run", "wrong version", "huge version", "artifact", "not stopped", "operation error"}
		if phase == "accept" {
			shapes = append(shapes, "approval ID", "plan hash")
		} else {
			shapes = append(shapes, "effect state", "outcome ID", "result digest")
		}
		for _, shape := range shapes {
			t.Run(phase+"/"+shape, func(t *testing.T) {
				now := time.Now().UTC()
				base := &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", phase == "execute", now)}}
				authority := &flatBudgetHeartbeatAuthority{budgetHeartbeatAuthority: &budgetHeartbeatAuthority{securityAgentWorkerAuthorityStub: base, contextEntered: make(chan struct{}), heartbeatErr: apiserver.ErrRepositoryConflict}, shape: shape}
				planner := successfulSecurityAgentPlanner()
				generated := 0
				processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: authority, Planner: planner, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) {
					generated++
					return fmt.Sprintf("pid_78000010-0000-4000-8000-%012d", generated), nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err = processor.RunOnce(ctx)
				if ctx.Err() != nil {
					t.Fatal("flat stop coordination timed out")
				}
				if (err == nil) != (shape == "stopped" || shape == "heartbeat advanced") {
					t.Fatalf("outcome=%v shape=%s", err, shape)
				}
				wantPlanner, wantAccept, wantExecute, wantIDs := 1, 1, 0, 3
				if phase == "execute" {
					wantPlanner, wantAccept, wantExecute, wantIDs = 0, 0, 1, 2
				}
				if len(planner.contexts) != wantPlanner || authority.acceptCalls != wantAccept || authority.executeCalls != wantExecute || generated != wantIDs || len(base.failedPlanner) != 0 {
					t.Fatalf("unexpected dispatch: planner=%d accept=%d execute=%d ids=%d", len(planner.contexts), authority.acceptCalls, authority.executeCalls, generated)
				}
			})
		}
	}
}

func (a *budgetHeartbeatAuthority) LoadSecurityAgentPlannerContext(ctx context.Context, _ apiserver.SecurityAgentRunClaim, _, _ string) (apiserver.SecurityAgentPlannerContext, error) {
	close(a.contextEntered)
	<-ctx.Done()
	return apiserver.SecurityAgentPlannerContext{}, a.contextErr
}

func (a *budgetHeartbeatAuthority) HeartbeatSecurityAgentRun(ctx context.Context, _ apiserver.SecurityAgentRunClaim, _, _ string, _ int) error {
	select {
	case <-a.contextEntered:
		return a.heartbeatErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestSecurityAgentBudgetStopHeartbeatRace(t *testing.T) {
	for _, test := range []struct {
		name                 string
		operation, heartbeat error
		wantSuccess          bool
	}{
		{"committed stop and lease conflict", apiserver.ErrSecurityAgentBudgetStopped, apiserver.ErrRepositoryConflict, true},
		{"unverified operation and lease conflict", apiserver.ErrRepositoryUnavailable, apiserver.ErrRepositoryConflict, false},
		{"committed stop and unrelated heartbeat outage", apiserver.ErrSecurityAgentBudgetStopped, apiserver.ErrRepositoryUnavailable, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			authority := &budgetHeartbeatAuthority{securityAgentWorkerAuthorityStub: &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", false, now)}}, contextEntered: make(chan struct{}), heartbeatErr: test.heartbeat, contextErr: test.operation}
			planner := successfulSecurityAgentPlanner()
			processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: authority, Planner: planner, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) { return "", errors.New("stopped operation generated artifact ID") }})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = processor.RunOnce(ctx)
			if ctx.Err() != nil {
				t.Fatal("heartbeat/context coordination did not complete")
			}
			if (err == nil) != test.wantSuccess {
				t.Fatalf("terminal result err=%v wantSuccess=%t", err, test.wantSuccess)
			}
			if len(planner.contexts) != 0 || len(authority.prepared) != 0 || len(authority.executed) != 0 || len(authority.failedPlanner) != 0 {
				t.Fatal("stopped/unverified operation dispatched work")
			}
		})
	}
}
