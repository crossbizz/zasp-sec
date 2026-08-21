package main

import (
	"context"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestSecurityAgentProcessorPlansForApprovalThenExecutesOnlyApprovedWork(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	first := securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", false, now)
	second := securityAgentTestClaim("pid_78000002-0000-4000-8000-000000000002", true, now)
	authority := &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{first, second}}
	ids := []string{
		"pid_78000010-0000-4000-8000-000000000010", "pid_78000011-0000-4000-8000-000000000011", "pid_78000012-0000-4000-8000-000000000012",
		"pid_78000013-0000-4000-8000-000000000013", "pid_78000014-0000-4000-8000-000000000014",
	}
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{
		Authority: authority, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 20 * time.Second,
		Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil },
		NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authority.claimCalls != 1 || len(authority.prepared) != 1 || authority.prepared[0] != first.RunID || len(authority.executed) != 1 || authority.executed[0] != second.RunID {
		t.Fatalf("claims=%d prepared=%v executed=%v", authority.claimCalls, authority.prepared, authority.executed)
	}
	if authority.approvalExpiresAt != now.Add(15*time.Minute) || authority.leaseToken != "lease-token-000000000001" {
		t.Fatalf("approval expires=%s lease=%q", authority.approvalExpiresAt, authority.leaseToken)
	}
}

func TestSecurityAgentProcessorKeepsLeaseThroughVerifiedEffect(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	claim := securityAgentTestClaim("pid_78000002-0000-4000-8000-000000000002", true, now)
	authority := &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{claim}, executeEntered: make(chan struct{}, 1), executeRelease: make(chan struct{}), heartbeatObserved: make(chan struct{}, 1)}
	ids := []string{"pid_78000013-0000-4000-8000-000000000013", "pid_78000014-0000-4000-8000-000000000014"}
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{
		Authority: authority, WorkerID: "security-agent-worker-1", LeaseSeconds: 30, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond,
		Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil },
		NewProductID: func() (string, error) { value := ids[0]; ids = ids[1:]; return value, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- processor.RunOnce(context.Background()) }()
	select {
	case <-authority.executeEntered:
	case <-time.After(time.Second):
		t.Fatal("execute did not start")
	}
	select {
	case <-authority.heartbeatObserved:
	case <-time.After(time.Second):
		t.Fatal("lease was not renewed during execution")
	}
	close(authority.executeRelease)
	if err := <-done; err != nil || authority.heartbeatCalls < 1 {
		t.Fatalf("run error=%v heartbeats=%d", err, authority.heartbeatCalls)
	}
}

func securityAgentTestClaim(runID string, prepared bool, now time.Time) apiserver.SecurityAgentRunClaim {
	return apiserver.SecurityAgentRunClaim{
		OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
		RunID: runID, DefinitionID: "pid_70000004-0000-4000-8000-000000000004", DefinitionVersion: 3, TriggerID: "pid_70000005-0000-4000-8000-000000000005",
		State: "planning", Version: 2, Attempt: 1, LeaseExpiresAt: now.Add(time.Minute), Prepared: prepared,
	}
}

type securityAgentWorkerAuthorityStub struct {
	claims             []apiserver.SecurityAgentRunClaim
	claimCalls         int
	prepared, executed []string
	approvalExpiresAt  time.Time
	leaseToken         string
	executeEntered     chan struct{}
	executeRelease     chan struct{}
	heartbeatObserved  chan struct{}
	heartbeatCalls     int
}

func (*securityAgentWorkerAuthorityStub) Ready(context.Context) error { return nil }

func (authority *securityAgentWorkerAuthorityStub) ClaimSecurityAgentRuns(_ context.Context, _ string, token string, _ int, _ int) ([]apiserver.SecurityAgentRunClaim, error) {
	authority.claimCalls++
	authority.leaseToken = token
	return append([]apiserver.SecurityAgentRunClaim(nil), authority.claims...), nil
}

func (authority *securityAgentWorkerAuthorityStub) HeartbeatSecurityAgentRun(context.Context, apiserver.SecurityAgentRunClaim, string, string, int) error {
	authority.heartbeatCalls++
	if authority.heartbeatObserved != nil {
		select {
		case authority.heartbeatObserved <- struct{}{}:
		default:
		}
	}
	return nil
}

func (authority *securityAgentWorkerAuthorityStub) PrepareSecurityAgentRun(_ context.Context, claim apiserver.SecurityAgentRunClaim, _ string, token, approvalID string, expiresAt time.Time, _, _ string) (apiserver.SecurityAgentPrepareResult, error) {
	authority.prepared = append(authority.prepared, claim.RunID)
	authority.approvalExpiresAt = expiresAt
	authority.leaseToken = token
	return apiserver.SecurityAgentPrepareResult{RunID: claim.RunID, State: "waiting_approval", ApprovalID: approvalID, StepID: "pid_78000020-0000-4000-8000-000000000020", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Version: claim.Version + 1}, nil
}

func (authority *securityAgentWorkerAuthorityStub) ExecuteSecurityAgentRun(_ context.Context, claim apiserver.SecurityAgentRunClaim, _ string, token, _, _ string) (apiserver.SecurityAgentExecuteResult, error) {
	authority.executed = append(authority.executed, claim.RunID)
	authority.leaseToken = token
	if authority.executeEntered != nil {
		authority.executeEntered <- struct{}{}
	}
	if authority.executeRelease != nil {
		<-authority.executeRelease
	}
	return apiserver.SecurityAgentExecuteResult{RunID: claim.RunID, State: "remediated", StepID: "pid_78000020-0000-4000-8000-000000000020", EffectState: "verified", OutcomeID: "pid_78000021-0000-4000-8000-000000000021", ResultDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Version: claim.Version + 1}, nil
}
