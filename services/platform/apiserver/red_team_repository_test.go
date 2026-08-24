package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestRedTeamRepositoryCreatesAndRunsTenantScopedDefinition(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	definitionID := "pid_79000001-0000-4000-8000-000000000001"
	targetID := "pid_79000002-0000-4000-8000-000000000002"
	runID := "pid_79000003-0000-4000-8000-000000000003"
	auditID := "pid_79000006-0000-4000-8000-000000000006"
	receiptID := "pid_79000007-0000-4000-8000-000000000007"
	createdAt := time.Now().UTC().Truncate(time.Second)
	definitionCorrelation := "pid_79000004-0000-4000-8000-000000000004"
	runCorrelation := "pid_79000005-0000-4000-8000-000000000005"
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresRedTeamCreateDefinitionSQL: json.RawMessage(`{"body":{"id":"` + definitionID + `","version":1,"name":"Gateway safety","target_id":"` + targetID + `","target_kind":"mcp_server","categories":["prompt_injection","tool_abuse"],"safety":{"environment":"staging","credential_class":"read_only","expected_side_effects":["audit event"]},"enabled":true,"created_at":"` + createdAt.Format(time.RFC3339) + `","updated_at":"` + createdAt.Format(time.RFC3339) + `"},"audit_id":"` + auditID + `","correlation_id":"` + definitionCorrelation + `","receipt_id":"` + receiptID + `","replayed":false}`),
		postgresRedTeamRunTestSQL:          json.RawMessage(`{"body":{"id":"` + runID + `","version":1,"definition_id":"` + definitionID + `","definition_version":1,"status":"queued","attempt":0,"cancel_requested":false,"queued_at":"` + createdAt.Format(time.RFC3339) + `"},"audit_id":"` + auditID + `","correlation_id":"` + runCorrelation + `","receipt_id":"` + receiptID + `","replayed":false}`),
	}}
	repository := &PostgresRepository{database: database, schema: RedTeamExecutionSchemaVersion}
	definitionInput := RedTeamDefinitionMutation{ID: definitionID, IdempotencyKey: "red-team-create-0001", Name: "Gateway safety", TargetID: targetID, TargetKind: "mcp_server", Categories: []string{"prompt_injection", "tool_abuse"}, Safety: RedTeamSafety{Environment: "staging", CredentialClass: "read_only", ExpectedSideEffects: []string{"audit event"}}, CorrelationID: definitionCorrelation}
	definition, err := repository.CreateRedTeamDefinition(context.Background(), identity, definitionInput)
	if err != nil || definition.Body.ID != definitionID || definition.Body.Version != 1 || definition.AuditID != auditID || definition.ReceiptID != receiptID {
		t.Fatalf("definition=%#v err=%v", definition, err)
	}
	runInput := RedTeamRunRequest{DefinitionID: definitionID, DefinitionVersion: 1, RunID: runID, IdempotencyKey: "red-team-run-000001", CorrelationID: runCorrelation}
	run, err := repository.RunRedTeamTest(context.Background(), identity, runInput)
	if err != nil || run.Body.ID != runID || run.Body.Status != "queued" || run.Body.Version != 1 {
		t.Fatalf("run=%#v err=%v", run, err)
	}
	if len(database.statements) != 2 || database.statements[0] != postgresRedTeamCreateDefinitionSQL || database.statements[1] != postgresRedTeamRunTestSQL {
		t.Fatalf("statements=%#v", database.statements)
	}
	wantCreate := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), definitionInput.IdempotencyKey, definitionID, definitionInput.Name, targetID, definitionInput.TargetKind, json.RawMessage(`["prompt_injection","tool_abuse"]`), json.RawMessage(`{"credential_class":"read_only","environment":"staging","expected_side_effects":["audit event"]}`), definitionInput.CorrelationID}
	if !reflect.DeepEqual(database.arguments[0], wantCreate) {
		t.Fatalf("create args=%#v", database.arguments[0])
	}
}

func TestRedTeamRepositoryRejectsUnsafeOrCrossSchemaRequestsWithoutIO(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{}}
	for _, repository := range []*PostgresRepository{{database: database, schema: SecurityAgentSessionIsolationSchemaVersion}, {database: database, schema: RedTeamExecutionSchemaVersion}} {
		input := RedTeamDefinitionMutation{ID: "pid_79000001-0000-4000-8000-000000000001", IdempotencyKey: "red-team-create-0001", Name: "Unsafe", TargetID: "pid_79000002-0000-4000-8000-000000000002", TargetKind: "mcp_server", Categories: []string{"custom_prompt"}, Safety: RedTeamSafety{Environment: "production", CredentialClass: "production_write", ExpectedSideEffects: []string{"shell"}}, CorrelationID: "pid_79000004-0000-4000-8000-000000000004"}
		if _, err := repository.CreateRedTeamDefinition(context.Background(), identity, input); err == nil {
			t.Fatalf("unsafe request accepted by schema %q", repository.schema)
		}
	}
	if len(database.statements) != 0 {
		t.Fatalf("unexpected IO %#v", database.statements)
	}
}

func TestRedTeamRepositoryAcceptsOnlyCanonicalRunStatesAndLaterSuccessfulAttempt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	runID := "pid_79000011-0000-4000-8000-000000000011"
	definitionID := "pid_79000012-0000-4000-8000-000000000012"
	queuedAt := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Minute)
	startedAt := queuedAt.Add(time.Minute)
	completedAt := startedAt.Add(time.Minute)
	reference := "s3://zasp-red-team-evidence/organizations/pid_79000001-0000-4000-8000-000000000001/workspaces/pid_79000002-0000-4000-8000-000000000002/environments/pid_79000003-0000-4000-8000-000000000003/artifacts/" + runID
	complete := RedTeamRun{
		ID: runID, Version: 7, DefinitionID: definitionID, DefinitionVersion: 2,
		Status: "complete", Attempt: 3, QueuedAt: queuedAt, StartedAt: &startedAt,
		CompletedAt: &completedAt, Verdict: "pass", EvidenceReference: reference,
	}
	detail := RedTeamRunDetail{RedTeamRun: complete, Attempts: []RedTeamAttempt{{
		Attempt: 3, Verdict: "pass", Objective: "Reject prompt injection",
		Behavior: "The target preserved its system boundary.", Evidence: []string{"bounded refusal"},
		EvidenceReference: reference, CompletedAt: completedAt,
	}}}
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresRedTeamGetRunSQL: mustRedTeamJSON(t, detail)}}
	repository := &PostgresRepository{database: database, schema: RedTeamExecutionSchemaVersion}
	if result, err := repository.GetRedTeamRun(context.Background(), identity, runID); err != nil || result.Attempt != 3 || len(result.Attempts) != 1 || result.Attempts[0].Attempt != 3 {
		t.Fatalf("later attempt detail=%#v err=%v", result, err)
	}

	validQueued := RedTeamRun{ID: runID, Version: 1, DefinitionID: definitionID, DefinitionVersion: 1, Status: "queued", QueuedAt: queuedAt}
	validLeased := RedTeamRun{ID: runID, Version: 2, DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1, QueuedAt: queuedAt, StartedAt: &startedAt}
	validRetryable := RedTeamRun{ID: runID, Version: 3, DefinitionID: definitionID, DefinitionVersion: 1, Status: "retryable", Attempt: 1, QueuedAt: queuedAt, StartedAt: &startedAt, ErrorCode: "retryable"}
	validFailed := RedTeamRun{ID: runID, Version: 6, DefinitionID: definitionID, DefinitionVersion: 1, Status: "failed", Attempt: 5, QueuedAt: queuedAt, StartedAt: &startedAt, CompletedAt: &completedAt, ErrorCode: "exhausted"}
	validCancelled := RedTeamRun{ID: runID, Version: 2, DefinitionID: definitionID, DefinitionVersion: 1, Status: "cancelled", CancelRequested: true, QueuedAt: queuedAt, CompletedAt: &completedAt, ErrorCode: "cancelled"}
	for name, value := range map[string]RedTeamRun{"queued": validQueued, "leased": validLeased, "retryable": validRetryable, "complete": complete, "failed": validFailed, "cancelled": validCancelled} {
		if !validRedTeamRun(value) {
			t.Fatalf("valid %s state rejected: %#v", name, value)
		}
	}
	for name, value := range map[string]RedTeamRun{
		"queued attempt":       withRedTeamRunAttempt(validQueued, 1),
		"leased without start": withRedTeamRunStart(validLeased, nil),
		"retry without error":  withRedTeamRunError(validRetryable, ""),
		"complete cancelled":   withRedTeamRunCancel(complete, true),
		"failed too early":     withRedTeamRunAttempt(validFailed, 4),
		"cancel flag missing":  withRedTeamRunCancel(validCancelled, false),
	} {
		if validRedTeamRun(value) {
			t.Fatalf("hostile %s state accepted: %#v", name, value)
		}
	}
}

func withRedTeamRunAttempt(value RedTeamRun, attempt int) RedTeamRun {
	value.Attempt = attempt
	return value
}
func withRedTeamRunStart(value RedTeamRun, started *time.Time) RedTeamRun {
	value.StartedAt = started
	return value
}
func withRedTeamRunError(value RedTeamRun, code string) RedTeamRun {
	value.ErrorCode = code
	return value
}
func withRedTeamRunCancel(value RedTeamRun, requested bool) RedTeamRun {
	value.CancelRequested = requested
	return value
}
