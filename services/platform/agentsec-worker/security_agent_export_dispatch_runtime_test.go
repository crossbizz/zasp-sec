package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type exportDispatchAuthority struct {
	*budgetHeartbeatAuthority
	mutate        func(*apiserver.SecurityAgentExecuteResult)
	operationErr  error
	calls         int
	waitHeartbeat bool
}

func (a *exportDispatchAuthority) ExecuteSecurityAgentRun(ctx context.Context, c apiserver.SecurityAgentRunClaim, _, _, _, _ string) (apiserver.SecurityAgentExecuteResult, error) {
	a.calls++
	receipt := &apiserver.SecurityAgentExportDispatchResult{OrganizationID: c.OrganizationID, WorkspaceID: c.WorkspaceID, EnvironmentID: c.EnvironmentID, RunID: c.RunID,
		StepID: "pid_78000020-0000-4000-8000-000000000020", ExportID: "pid_78000021-0000-4000-8000-000000000021", RunVersion: c.Version + 1, State: "pending"}
	result := apiserver.SecurityAgentExecuteResult{RunID: c.RunID, State: "verifying", Version: receipt.RunVersion, StepID: receipt.StepID, ExportDispatch: receipt}
	if a.mutate != nil {
		a.mutate(&result)
	}
	if a.waitHeartbeat {
		close(a.contextEntered)
		<-ctx.Done()
	}
	return result, a.operationErr
}

func TestSecurityAgentExportDispatchProcessor(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		mutate               func(*apiserver.SecurityAgentExecuteResult)
		heartbeat, operation error
		wait, success        bool
	}{
		{name: "pending admission", success: true},
		{name: "replayed admission", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.ExportDispatch.Replayed = true }, success: true},
		{name: "cleared lease heartbeat", heartbeat: apiserver.ErrRepositoryConflict, wait: true, success: true},
		{name: "unrelated heartbeat outage", heartbeat: apiserver.ErrRepositoryUnavailable, wait: true},
		{name: "unconfirmed admission", heartbeat: apiserver.ErrRepositoryConflict, operation: apiserver.ErrRepositoryUnavailable, wait: true},
		{name: "foreign scope", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.ExportDispatch.EnvironmentID = r.ExportDispatch.RunID }},
		{name: "foreign parent", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.ExportDispatch.RunID = r.ExportDispatch.StepID }},
		{name: "foreign step", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.StepID = r.RunID }},
		{name: "stale version", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.Version--; r.ExportDispatch.RunVersion-- }},
		{name: "mismatched version", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.ExportDispatch.RunVersion++ }},
		{name: "bad export", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.ExportDispatch.ExportID = "bad" }},
		{name: "invented availability", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.ExportDispatch.State = "completed" }},
		{name: "invented remediation", mutate: func(r *apiserver.SecurityAgentExecuteResult) {
			r.State = "remediated"
			r.EffectState = "verified"
			r.OutcomeID = r.ExportDispatch.ExportID
			r.ResultDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{name: "budget stop confusion", mutate: func(r *apiserver.SecurityAgentExecuteResult) { r.State = "needs_human"; r.StepID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			claim := securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", true, now)
			base := &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{claim}}
			a := &exportDispatchAuthority{budgetHeartbeatAuthority: &budgetHeartbeatAuthority{securityAgentWorkerAuthorityStub: base, contextEntered: make(chan struct{}), heartbeatErr: tc.heartbeat}, mutate: tc.mutate, operationErr: tc.operation, waitHeartbeat: tc.wait}
			generated := 0
			p, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: a, Planner: successfulSecurityAgentPlanner(), WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) {
				generated++
				return fmt.Sprintf("pid_78000010-0000-4000-8000-%012d", generated), nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = p.RunOnce(ctx)
			if ctx.Err() != nil || (err == nil) != tc.success || a.calls != 1 || generated != 2 {
				t.Fatalf("err=%v context=%v calls=%d ids=%d wantSuccess=%v", err, ctx.Err(), a.calls, generated, tc.success)
			}
		})
	}
}
