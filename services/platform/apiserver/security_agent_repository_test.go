package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentPostgresRepositorySimulatesWithCanonicalPlanAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	correlationID := "pid_78000003-0000-4000-8000-000000000003"
	receiptID := "pid_78000004-0000-4000-8000-000000000004"
	expiresAt := time.Now().UTC().Truncate(time.Second).Add(15 * time.Minute)
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentSimulateSQL:           json.RawMessage(`{"run_id":"` + runID + `","definition_id":"` + definitionID + `","definition_version":2,"plan_hash":"sha256:` + strings.Repeat("a", 64) + `","catalog_version":"security-agent-actions-v1","expires_at":"` + expiresAt.Format(time.RFC3339) + `","matched_evidence_ids":["` + evidenceID + `"],"summary":"Review exposed credential","steps":[{"index":0,"action":"create_temporary_policy","authorization":"approval_required","approval_required":true}],"side_effects":0,"version":1,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	input := SecurityAgentSimulationRequest{DefinitionID: definitionID, IdempotencyKey: "simulate-agent-idem-0001", ExpectedVersion: 2, RunID: runID, Goal: "Review exposed credential", EvidenceIDs: []string{evidenceID}, ExpiresAt: expiresAt, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	result, err := repository.SimulateSecurityAgent(context.Background(), identity, input)
	if err != nil || result.PlanHash != "sha256:"+strings.Repeat("a", 64) || result.SideEffects != 0 || result.Replayed {
		t.Fatalf("simulation=%#v err=%v", result, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID, identity.PrincipalID.String(), input.IdempotencyKey, int64(2), runID, input.Goal, json.RawMessage(`["` + evidenceID + `"]`), expiresAt, auditID, correlationID, receiptID}
	if database.statements[1] != postgresSecurityAgentSimulateSQL || !reflect.DeepEqual(database.arguments[1], want) {
		t.Fatalf("statement=%q args=%#v", database.statements[1], database.arguments[1])
	}
}

type securityAgentRepositoryDatabase struct {
	responses  map[string]json.RawMessage
	statements []string
	arguments  [][]any
}

func TestSecurityAgentPostgresRepositoryPrefersV20ScopedAuthority(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil || repository.schema != SecurityAgentControlsSchemaVersion {
		t.Fatalf("repository=%#v err=%v", repository, err)
	}
	if len(database.statements) != 1 || database.statements[0] != postgresSecurityAgentControlsReadySQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}

func TestSecurityAgentPostgresRepositoryReadsAndMutatesExactTenantControls(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Date(2026, 8, 21, 12, 4, 0, 0, time.UTC)
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	correlationID := "pid_78000003-0000-4000-8000-000000000003"
	receiptID := "pid_78000004-0000-4000-8000-000000000004"
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:       json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentExecutionControlsSQL:   json.RawMessage(`{"global":{"target":"global","action_key":"*","enabled":true,"version":1},"environment":{"target":"environment","action_key":"*","enabled":false,"version":0},"actions":[{"target":"action","action_key":"update_finding_response","enabled":false,"version":0}]}`),
		postgresSecurityAgentSetExecutionControlSQL: json.RawMessage(`{"target":"environment","action_key":"*","enabled":true,"version":1,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	controls, err := repository.GetSecurityAgentExecutionControls(context.Background(), identity)
	if err != nil || !controls.Global.Enabled || controls.Environment.Enabled || len(controls.Actions) != 1 || controls.Actions[0].ActionKey != "update_finding_response" {
		t.Fatalf("controls=%#v err=%v", controls, err)
	}
	input := SecurityAgentExecutionControlMutation{Target: "environment", ActionKey: "*", Enabled: true, IdempotencyKey: "set-agent-control-idem-0001", ExpectedVersion: 0, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	result, err := repository.SetSecurityAgentExecutionControl(context.Background(), identity, input)
	if err != nil || result.Target != "environment" || !result.Enabled || result.Version != 1 || result.Replayed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	wantScope := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}
	wantMutation := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.Target, input.ActionKey, true, int64(0), identity.FreshAuthExpiresAt, auditID, correlationID, receiptID}
	if !reflect.DeepEqual(database.arguments[1], wantScope) || !reflect.DeepEqual(database.arguments[2], wantMutation) {
		t.Fatalf("arguments=%#v", database.arguments)
	}
	input.Target = "global"
	if _, err := repository.SetSecurityAgentExecutionControl(context.Background(), identity, input); !errors.Is(err, ErrRepositoryOperation) || len(database.statements) != 3 {
		t.Fatalf("global mutation err=%v statements=%#v", err, database.statements)
	}
}

func TestSecurityAgentPostgresRepositoryReadsExactActivationState(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:        json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL:   json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:       json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentDefinitionActivationSQL: json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","definition_id":"` + definitionID + `","activation":"validated","version":2,"definition_version":1,"body":{"id":"` + definitionID + `","name":"Review exposed credential","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + identity.Scope.EnvironmentID().String() + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["update_finding_response"],"verification_kind":"finding_state","definition_version":1,"enabled":false},"updated_at":"2026-08-21T12:00:00Z"}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repository.GetSecurityAgentActivation(context.Background(), identity, definitionID)
	if err != nil || result.ID != definitionID || result.Activation != "validated" || result.Enabled || result.Version != 2 {
		t.Fatalf("activation=%#v err=%v", result, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID}
	if database.statements[1] != postgresSecurityAgentDefinitionActivationSQL || !reflect.DeepEqual(database.arguments[1], want) {
		t.Fatalf("statement=%q args=%#v", database.statements[1], database.arguments[1])
	}
}

func TestSecurityAgentPostgresRepositoryActivatesWithExactScopeAndReceiptAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Date(2026, 8, 21, 12, 4, 0, 0, time.UTC)
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	correlationID := "pid_78000003-0000-4000-8000-000000000003"
	receiptID := "pid_78000004-0000-4000-8000-000000000004"
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActivateSQL:           json.RawMessage(`{"id":"` + definitionID + `","activation":"validated","enabled":false,"version":2,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	input := SecurityAgentActivation{DefinitionID: definitionID, IdempotencyKey: "activate-agent-idem-0001", ExpectedVersion: 1, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	result, err := repository.ActivateSecurityAgent(context.Background(), identity, input)
	if err != nil || result.Version != 2 || result.Replayed {
		t.Fatalf("activation=%#v err=%v", result, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID, identity.PrincipalID.String(), input.IdempotencyKey, int64(1), "validated", identity.FreshAuthExpiresAt, auditID, correlationID, receiptID}
	if database.statements[1] != postgresSecurityAgentActivateSQL || !reflect.DeepEqual(database.arguments[1], want) {
		t.Fatalf("statement=%q args=%#v", database.statements[1], database.arguments[1])
	}
}

func TestSecurityAgentPostgresRepositoryRunsAndApprovesWithExactScopedAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Date(2026, 8, 21, 12, 4, 0, 0, time.UTC)
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	approvalID := "pid_78000007-0000-4000-8000-000000000007"
	stepID := "pid_78000008-0000-4000-8000-000000000008"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	correlationID := "pid_78000003-0000-4000-8000-000000000003"
	receiptID := "pid_78000004-0000-4000-8000-000000000004"
	freshAuthAt := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	expiresAt := freshAuthAt.Add(15 * time.Minute)
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentRunSQL:                json.RawMessage(`{"id":"` + runID + `","agent_id":"` + definitionID + `","state":"queued","evidence_ids":["` + evidenceID + `"],"definition_version":3,"version":1,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
		postgresSecurityAgentDecideApprovalSQL:     json.RawMessage(`{"id":"` + approvalID + `","run_id":"` + runID + `","step_id":"` + stepID + `","state":"approved","expires_at":"` + expiresAt.Format(time.RFC3339) + `","version":2,"expected_effect":"Move finding to under review","reversible":true,"ttl_seconds":0,"evidence_summary":["` + evidenceID + `"],"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	runInput := SecurityAgentRunRequest{DefinitionID: definitionID, IdempotencyKey: "run-security-agent-0001", ExpectedVersion: 3, RunID: runID, TriggerKind: "finding", TriggerID: evidenceID, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	if result, err := repository.RunSecurityAgent(context.Background(), identity, runInput); err != nil || result.ID != runID || result.State != "queued" {
		t.Fatalf("run=%#v err=%v", result, err)
	}
	decisionInput := SecurityAgentApprovalDecisionRequest{ApprovalID: approvalID, IdempotencyKey: "approve-security-agent-0001", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: freshAuthAt, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	if result, err := repository.DecideSecurityAgentApproval(context.Background(), identity, decisionInput); err != nil || result.ID != approvalID || result.State != "approved" {
		t.Fatalf("approval=%#v err=%v", result, err)
	}
	wantRun := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID, identity.PrincipalID.String(), runInput.IdempotencyKey, int64(3), runID, "finding", evidenceID, auditID, correlationID, receiptID}
	wantDecision := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), approvalID, identity.PrincipalID.String(), decisionInput.IdempotencyKey, int64(1), "approved", freshAuthAt, auditID, correlationID, receiptID}
	if database.statements[1] != postgresSecurityAgentRunSQL || !reflect.DeepEqual(database.arguments[1], wantRun) || database.statements[2] != postgresSecurityAgentDecideApprovalSQL || !reflect.DeepEqual(database.arguments[2], wantDecision) {
		t.Fatalf("statements=%#v args=%#v", database.statements, database.arguments)
	}
}

func TestSecurityAgentPostgresRepositoryReadsExactScopedRunsAndApprovals(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	approvalID := "pid_78000007-0000-4000-8000-000000000007"
	stepID := "pid_78000008-0000-4000-8000-000000000008"
	createdAt := time.Date(2026, 8, 21, 11, 59, 0, 123000, time.UTC)
	expiresAt := time.Date(2026, 8, 21, 12, 15, 0, 0, time.UTC)
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentRunPageSQL:            json.RawMessage(`{"items":[{"id":"` + runID + `","agent_id":"` + definitionID + `","state":"waiting_approval","evidence_ids":["` + evidenceID + `"],"definition_version":3,"version":4}],"next_created_at":"` + createdAt.Format("2006-01-02T15:04:05.000000Z") + `","next_id":"` + runID + `"}`),
		postgresSecurityAgentRunDetailSQL:          json.RawMessage(`{"run":{"id":"` + runID + `","agent_id":"` + definitionID + `","state":"waiting_approval","evidence_ids":["` + evidenceID + `"],"definition_version":3,"version":4},"evidence_ids":["` + evidenceID + `"],"plan":{"plan_hash":"sha256:` + strings.Repeat("a", 64) + `","catalog_version":"security-agent-actions-v1","expires_at":"` + expiresAt.Format(time.RFC3339) + `","steps":[{"id":"` + stepID + `","index":0,"action":"update_finding_response","authorization":"approval_required","state":"waiting_approval","version":1}]},"authorization":"approval_required","approvals":[{"id":"` + approvalID + `","run_id":"` + runID + `","step_id":"` + stepID + `","state":"pending","expires_at":"` + expiresAt.Format(time.RFC3339) + `","version":1,"expected_effect":"Move finding to under review","reversible":true,"ttl_seconds":0,"evidence_summary":["` + evidenceID + `"]}],"execution":[{"step_id":"` + stepID + `","action":"update_finding_response","state":"waiting_approval","version":1}],"verification":"not_started"}`),
		postgresSecurityAgentApprovalPageSQL:       json.RawMessage(`{"items":[{"id":"` + approvalID + `","run_id":"` + runID + `","step_id":"` + stepID + `","state":"pending","expires_at":"` + expiresAt.Format(time.RFC3339) + `","version":1,"expected_effect":"Move finding to under review","reversible":true,"ttl_seconds":0,"evidence_summary":["` + evidenceID + `"]}],"next_created_at":null,"next_id":null}`),
		postgresSecurityAgentApprovalDetailSQL:     json.RawMessage(`{"id":"` + approvalID + `","run_id":"` + runID + `","step_id":"` + stepID + `","state":"pending","expires_at":"` + expiresAt.Format(time.RFC3339) + `","version":1,"expected_effect":"Move finding to under review","reversible":true,"ttl_seconds":0,"evidence_summary":["` + evidenceID + `"]}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	runPage, err := repository.ListSecurityAgentRuns(context.Background(), identity, SecurityAgentRunPageRequest{DefinitionID: definitionID, State: "waiting_approval", BeforeCreatedAt: createdAt.Add(time.Minute), BeforeID: "pid_78000009-0000-4000-8000-000000000009", Limit: 25})
	if err != nil || len(runPage.Items) != 1 || runPage.Items[0].ID != runID || runPage.NextCreatedAt == nil || !runPage.NextCreatedAt.Equal(createdAt) || runPage.NextID != runID {
		t.Fatalf("run page=%#v err=%v", runPage, err)
	}
	detail, err := repository.GetSecurityAgentRun(context.Background(), identity, runID)
	if err != nil || detail.Run.ID != runID || detail.Plan == nil || len(detail.Plan.Steps) != 1 || detail.Authorization != "approval_required" || detail.Verification != "not_started" {
		t.Fatalf("run detail=%#v err=%v", detail, err)
	}
	approvalPage, err := repository.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{State: "pending", RunID: runID, Limit: 25})
	if err != nil || len(approvalPage.Items) != 1 || approvalPage.Items[0].ID != approvalID || approvalPage.NextCreatedAt != nil || approvalPage.NextID != "" {
		t.Fatalf("approval page=%#v err=%v", approvalPage, err)
	}
	approval, err := repository.GetSecurityAgentApproval(context.Background(), identity, approvalID)
	if err != nil || approval.ID != approvalID || approval.ExpectedEffect != "Move finding to under review" || !approval.Reversible {
		t.Fatalf("approval=%#v err=%v", approval, err)
	}
	wantRunPage := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID, "waiting_approval", createdAt.Add(time.Minute), "pid_78000009-0000-4000-8000-000000000009", 25}
	wantApprovalPage := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), "pending", runID, nil, "", 25}
	if !reflect.DeepEqual(database.arguments[1], wantRunPage) || !reflect.DeepEqual(database.arguments[2], []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID}) || !reflect.DeepEqual(database.arguments[3], wantApprovalPage) || !reflect.DeepEqual(database.arguments[4], []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), approvalID}) {
		t.Fatalf("arguments=%#v", database.arguments)
	}
}

func TestSecurityAgentPostgresRepositoryPreservesEmptyRunAndApprovalCollections(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentRunPageSQL:            json.RawMessage(`{"items":[],"next_created_at":null,"next_id":null}`),
		postgresSecurityAgentApprovalPageSQL:       json.RawMessage(`{"items":[],"next_created_at":null,"next_id":null}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := repository.ListSecurityAgentRuns(context.Background(), identity, SecurityAgentRunPageRequest{Limit: 100})
	if err != nil || runs.Items == nil || len(runs.Items) != 0 {
		t.Fatalf("runs=%#v err=%v", runs, err)
	}
	approvals, err := repository.ListSecurityAgentApprovals(context.Background(), identity, SecurityAgentApprovalPageRequest{Limit: 100})
	if err != nil || approvals.Items == nil || len(approvals.Items) != 0 {
		t.Fatalf("approvals=%#v err=%v", approvals, err)
	}
}

func TestSecurityAgentPostgresRepositoryCancelsWithoutExposingMutationAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	correlationID := "pid_78000003-0000-4000-8000-000000000003"
	receiptID := "pid_78000004-0000-4000-8000-000000000004"
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentControlsReadySQL:      json.RawMessage(`{"release":true,"principal":true}`),
		postgresIdentityAdminSecurityAgentReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentAuthorityReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentCancelRunSQL:          json.RawMessage(`{"id":"` + runID + `","agent_id":"` + definitionID + `","state":"cancelled","evidence_ids":["` + evidenceID + `"],"definition_version":3,"version":5,"audit_id":"` + auditID + `","correlation_id":"` + correlationID + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	input := SecurityAgentCancelRequest{RunID: runID, IdempotencyKey: "cancel-agent-run-0001", ExpectedVersion: 4, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}
	result, err := repository.CancelSecurityAgentRun(context.Background(), identity, input)
	if err != nil || result.ID != runID || result.State != "cancelled" || result.Version != 5 || result.Replayed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID, identity.PrincipalID.String(), input.IdempotencyKey, int64(4), auditID, correlationID, receiptID}
	if database.statements[1] != postgresSecurityAgentCancelRunSQL || !reflect.DeepEqual(database.arguments[1], want) {
		t.Fatalf("statement=%q args=%#v", database.statements[1], database.arguments[1])
	}
}

func (*securityAgentRepositoryDatabase) SchemaVersion(context.Context) (string, error) {
	return "", errors.New("security agent authority must not read schema metadata")
}
func (database *securityAgentRepositoryDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	database.statements = append(database.statements, statement)
	database.arguments = append(database.arguments, append([]any(nil), arguments...))
	value, ok := database.responses[statement]
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	return append(json.RawMessage(nil), value...), nil
}
func (*securityAgentRepositoryDatabase) Exec(context.Context, string, ...any) error { return nil }

func TestSecurityAgentPostgresRepositoryUsesOnlyV18ScopedAuthority(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentAuthorityReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentDefinitionPageSQL: json.RawMessage(`{"items":[{"id":"pid_78000001-0000-4000-8000-000000000001","enabled":false}],"next_id":null}`),
	}}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	page, err := repository.ListWorkflowPage(context.Background(), scope, "security_agent", "", 10)
	if err != nil || len(page.Items) != 1 || page.NextID != "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if len(database.statements) != 4 || database.statements[0] != postgresSecurityAgentControlsReadySQL || database.statements[1] != postgresIdentityAdminSecurityAgentReadySQL || database.statements[2] != postgresSecurityAgentAuthorityReadySQL || database.statements[3] != postgresSecurityAgentDefinitionPageSQL {
		t.Fatalf("statements=%#v", database.statements)
	}
	if _, err := repository.ListWorkflowPage(context.Background(), scope, "policy", "", 10); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("foreign kind error=%v", err)
	}
}

func TestSecurityAgentPostgresRepositoryRejectsUnreadyOrMalformedAuthority(t *testing.T) {
	for _, payload := range []string{`{"release":false,"principal":true}`, `{"release":true,"principal":false}`, `{"release":true,"principal":true,"extra":true}`, `null`} {
		database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentAuthorityReadySQL: json.RawMessage(payload)}}
		if _, err := NewSecurityAgentPostgresRepository(database); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("payload=%s error=%v", payload, err)
		}
	}
}
