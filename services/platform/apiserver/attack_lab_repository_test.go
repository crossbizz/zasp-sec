package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestAttackLabRepositoryCreatesOnlyTenantScopedDerivedRun(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	runID := "pid_79100001-0000-4000-8000-000000000001"
	sourceRunID := "pid_79100002-0000-4000-8000-000000000002"
	definitionID := "pid_79100003-0000-4000-8000-000000000003"
	targetID := "pid_79100004-0000-4000-8000-000000000004"
	correlationID := "pid_79100005-0000-4000-8000-000000000005"
	queuedAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	result := AttackLabMutationResult{Body: AttackLabRun{ID: runID, Version: 1, SourceRunID: sourceRunID, DefinitionID: definitionID, DefinitionVersion: 2, TargetID: targetID, TargetKind: "agent_endpoint", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "queued", CleanupState: "pending", Limits: AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: queuedAt}, AuditID: "pid_79100006-0000-4000-8000-000000000006", CorrelationID: correlationID, ReceiptID: "pid_79100007-0000-4000-8000-000000000007"}
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresAttackLabCreateSQL: mustRedTeamJSON(t, result)}}
	repository := &PostgresRepository{database: database, schema: AttackLabExecutionSchemaVersion}
	input := AttackLabCreateRequest{RunID: runID, SourceRunID: sourceRunID, Approved: true, IdempotencyKey: "attack-lab-create-0001", CorrelationID: correlationID}
	created, err := repository.CreateAttackLabRun(context.Background(), identity, input)
	if err != nil || !reflect.DeepEqual(created.Body, result.Body) {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, runID, sourceRunID, correlationID}
	if len(database.statements) != 1 || database.statements[0] != postgresAttackLabCreateSQL || !reflect.DeepEqual(database.arguments[0], want) {
		t.Fatalf("statements=%#v args=%#v", database.statements, database.arguments)
	}
}

func TestAttackLabRepositoryRejectsHostileStateTuplesAndClientAuthority(t *testing.T) {
	queuedAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	startedAt := queuedAt.Add(time.Minute)
	completedAt := startedAt.Add(time.Minute)
	base := AttackLabRun{ID: "pid_79200001-0000-4000-8000-000000000001", Version: 1, SourceRunID: "pid_79200002-0000-4000-8000-000000000002", DefinitionID: "pid_79200003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_79200004-0000-4000-8000-000000000004", TargetKind: "mcp_server", Environment: "staging", CredentialClass: "read_only", Destination: "canary.attack-lab.internal", Status: "queued", CleanupState: "pending", Limits: AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: queuedAt}
	if !validAttackLabRun(base) {
		t.Fatal("valid queued state rejected")
	}
	complete := base
	complete.Version, complete.Status, complete.Attempt, complete.StartedAt, complete.CompletedAt, complete.Verdict, complete.CleanupState, complete.EvidenceReference = 4, "complete", 1, &startedAt, &completedAt, "verified", "complete", "s3://attack-lab-evidence/object"
	if !validAttackLabRun(complete) {
		t.Fatal("valid complete state rejected")
	}
	for name, mutate := range map[string]func(*AttackLabRun){
		"production":            func(value *AttackLabRun) { value.Environment = "production" },
		"write credential":      func(value *AttackLabRun) { value.CredentialClass = "production_write" },
		"arbitrary destination": func(value *AttackLabRun) { value.Destination = "https://evil.example/path" },
		"larger limits":         func(value *AttackLabRun) { value.Limits.Memory = "8Gi" },
		"queued evidence":       func(value *AttackLabRun) { value.EvidenceReference = "s3://unexpected" },
	} {
		value := base
		mutate(&value)
		if validAttackLabRun(value) {
			t.Fatalf("hostile %s accepted: %#v", name, value)
		}
	}
	identity := fixtureRequestIdentity(t)
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{}}
	repository := &PostgresRepository{database: database, schema: AttackLabExecutionSchemaVersion}
	if _, err := repository.CreateAttackLabRun(context.Background(), identity, AttackLabCreateRequest{RunID: base.ID, SourceRunID: base.SourceRunID, Approved: false, IdempotencyKey: "attack-lab-create-0001", CorrelationID: "pid_79200005-0000-4000-8000-000000000005"}); err == nil || len(database.statements) != 0 {
		t.Fatalf("unapproved run reached provider err=%v statements=%#v", err, database.statements)
	}
}

func TestAttackLabRepositoryAcceptsActiveCancellationAndRequiresCompleteEvidence(t *testing.T) {
	queuedAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	startedAt := queuedAt.Add(time.Minute)
	active := AttackLabRun{
		ID:                "pid_79300001-0000-4000-8000-000000000001",
		Version:           2,
		SourceRunID:       "pid_79300002-0000-4000-8000-000000000002",
		DefinitionID:      "pid_79300003-0000-4000-8000-000000000003",
		DefinitionVersion: 1,
		TargetID:          "pid_79300004-0000-4000-8000-000000000004",
		TargetKind:        "coding_agent",
		Environment:       "test",
		CredentialClass:   "test_write",
		Destination:       "canary.attack-lab.internal",
		Status:            "running",
		Attempt:           1,
		CancelRequested:   true,
		CleanupState:      "pending",
		Limits:            AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300},
		QueuedAt:          queuedAt,
		StartedAt:         &startedAt,
	}
	if !validAttackLabRun(active) {
		t.Fatal("active cancellation state rejected")
	}

	attempt := AttackLabAttempt{
		Attempt:           1,
		Verdict:           "verified",
		CriterionObserved: true,
		CanaryTouched:     true,
		CleanupCompleted:  true,
		Evidence:          []string{"semantic:criterion", "gateway:decision", "egress:allowlist", "kubernetes:job", "cloud:task"},
		EvidenceReference: "s3://attack-lab-evidence/organizations/evidence.json",
		CompletedAt:       startedAt.Add(time.Minute),
	}
	if !validAttackLabAttempt(attempt) {
		t.Fatal("complete ordered evidence rejected")
	}
	attempt.Evidence = attempt.Evidence[:4]
	if validAttackLabAttempt(attempt) {
		t.Fatal("incomplete evidence accepted")
	}
}
