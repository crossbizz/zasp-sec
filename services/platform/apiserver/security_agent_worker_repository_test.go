package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestSecurityAgentWorkerRepositoryClaimsPlansHeartbeatsAndExecutesExactTenantWork(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	leaseExpiresAt := now.Add(time.Minute)
	organizationID := "pid_70000001-0000-4000-8000-000000000001"
	workspaceID := "pid_70000002-0000-4000-8000-000000000002"
	environmentID := "pid_70000003-0000-4000-8000-000000000003"
	runID := "pid_78000001-0000-4000-8000-000000000001"
	definitionID := "pid_78000002-0000-4000-8000-000000000002"
	triggerID := "pid_78000003-0000-4000-8000-000000000003"
	approvalID := "pid_78000004-0000-4000-8000-000000000004"
	stepID := "pid_78000005-0000-4000-8000-000000000005"
	auditID := "pid_78000006-0000-4000-8000-000000000006"
	correlationID := "pid_78000007-0000-4000-8000-000000000007"
	outcomeID := "pid_78000008-0000-4000-8000-000000000008"
	claimPayload := `{"items":[{"organization_id":"` + organizationID + `","workspace_id":"` + workspaceID + `","environment_id":"` + environmentID + `","run_id":"` + runID + `","definition_id":"` + definitionID + `","definition_version":3,"trigger_id":"` + triggerID + `","state":"planning","version":2,"attempt":1,"lease_expires_at":"` + leaseExpiresAt.Format(time.RFC3339) + `","prepared":false}]}`
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentWorkerReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentScheduleTriggersSQL: json.RawMessage(`{"created":2}`),
		postgresSecurityAgentClaimRunsSQL:        json.RawMessage(claimPayload),
		postgresSecurityAgentHeartbeatRunSQL:     json.RawMessage(`{"run_id":"` + runID + `","lease_expires_at":"` + leaseExpiresAt.Add(time.Minute).Format(time.RFC3339) + `"}`),
		postgresSecurityAgentPrepareRunSQL:       json.RawMessage(`{"run_id":"` + runID + `","state":"waiting_approval","version":3,"approval_id":"` + approvalID + `","step_id":"` + stepID + `","plan_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		postgresSecurityAgentExecuteRunSQL:       json.RawMessage(`{"run_id":"` + runID + `","state":"remediated","version":3,"step_id":"` + stepID + `","effect_state":"verified","outcome_id":"` + outcomeID + `","result_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`),
	}}
	repository, err := NewSecurityAgentWorkerRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := repository.ScheduleSecurityAgentTriggers(context.Background(), "security-agent-worker-1", 10); err != nil || created != 2 {
		t.Fatalf("scheduled=%d err=%v", created, err)
	}
	claims, err := repository.ClaimSecurityAgentRuns(context.Background(), "security-agent-worker-1", "lease-token-000000000001", 60, 10)
	if err != nil || len(claims) != 1 || claims[0].RunID != runID || claims[0].Prepared {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if err := repository.HeartbeatSecurityAgentRun(context.Background(), claims[0], "security-agent-worker-1", "lease-token-000000000001", 60); err != nil {
		t.Fatal(err)
	}
	expiresAt := now.Add(15 * time.Minute)
	if result, err := repository.PrepareSecurityAgentRun(context.Background(), claims[0], "security-agent-worker-1", "lease-token-000000000001", approvalID, expiresAt, auditID, correlationID); err != nil || result.ApprovalID != approvalID {
		t.Fatalf("prepare=%#v err=%v", result, err)
	}
	claims[0].Prepared = true
	if result, err := repository.ExecuteSecurityAgentRun(context.Background(), claims[0], "security-agent-worker-1", "lease-token-000000000001", auditID, correlationID); err != nil || result.OutcomeID != outcomeID {
		t.Fatalf("execute=%#v err=%v", result, err)
	}
	if len(database.statements) != 6 || database.statements[0] != postgresSecurityAgentWorkerReadySQL || database.statements[1] != postgresSecurityAgentScheduleTriggersSQL || database.statements[2] != postgresSecurityAgentClaimRunsSQL || database.statements[3] != postgresSecurityAgentHeartbeatRunSQL || database.statements[4] != postgresSecurityAgentPrepareRunSQL || database.statements[5] != postgresSecurityAgentExecuteRunSQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}

func TestSecurityAgentWorkerRepositoryAcceptsExactAutonomousPreparationWithoutApproval(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	claim := SecurityAgentRunClaim{
		OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
		RunID: "pid_78000001-0000-4000-8000-000000000001", DefinitionID: "pid_78000002-0000-4000-8000-000000000002", DefinitionVersion: 4, TriggerID: "pid_78000003-0000-4000-8000-000000000003",
		State: "planning", Version: 2, Attempt: 1, LeaseExpiresAt: now.Add(time.Minute), Prepared: false,
	}
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentWorkerReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentPrepareRunSQL:  json.RawMessage(`{"run_id":"` + claim.RunID + `","state":"queued","version":3,"approval_id":null,"step_id":"pid_78000005-0000-4000-8000-000000000005","plan_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
	}}
	repository, err := NewSecurityAgentWorkerRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repository.PrepareSecurityAgentRun(context.Background(), claim, "security-agent-worker-1", "lease-token-000000000001", "pid_78000004-0000-4000-8000-000000000004", now.Add(15*time.Minute), "pid_78000006-0000-4000-8000-000000000006", "pid_78000007-0000-4000-8000-000000000007")
	if err != nil || result.State != "queued" || result.ApprovalID != "" {
		t.Fatalf("autonomous prepare=%#v err=%v", result, err)
	}
}
