package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
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
	input := AttackLabCreateRequest{RunID: runID, SourceRunID: sourceRunID, DecisionDigest: strings.Repeat("a", 64), Approved: true, IdempotencyKey: "attack-lab-create-0001", CorrelationID: correlationID}
	created, err := repository.CreateAttackLabRun(context.Background(), identity, input)
	if err != nil || !reflect.DeepEqual(created.Body, result.Body) {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, runID, sourceRunID, bytes.Repeat([]byte{0xaa}, sha256.Size), correlationID}
	if len(database.statements) != 1 || database.statements[0] != postgresAttackLabCreateSQL || !reflect.DeepEqual(database.arguments[0], want) {
		t.Fatalf("statements=%#v args=%#v", database.statements, database.arguments)
	}
}

func TestAttackLabRepositoryReadsStrictTenantScopedPreflight(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	sourceRunID := "pid_79110001-0000-4000-8000-000000000001"
	value := AttackLabPreflight{SourceRunID: sourceRunID, DefinitionID: "pid_79110002-0000-4000-8000-000000000002", DefinitionVersion: 2, TargetID: "pid_79110003-0000-4000-8000-000000000003", TargetKind: "agent_endpoint", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", AllowedDestinations: []string{"adapter.customer.example"}, SuccessCriterion: "Reject direct prompt injection", ExpectedSideEffects: []string{"bounded evaluation"}, DecisionDigest: strings.Repeat("a", 64), DecisionExpiresAt: time.Date(2026, 8, 28, 12, 5, 0, 0, time.UTC), Limits: AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}}
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresAttackLabPreflightSQL: mustRedTeamJSON(t, value)}}
	repository := &PostgresRepository{database: database, schema: AttackLabExecutionSchemaVersion}
	got, err := repository.PreflightAttackLabRun(context.Background(), identity, sourceRunID)
	if err != nil || !reflect.DeepEqual(got, value) {
		t.Fatalf("preflight=%#v err=%v", got, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), sourceRunID}
	if len(database.statements) != 1 || database.statements[0] != postgresAttackLabPreflightSQL || !reflect.DeepEqual(database.arguments[0], want) {
		t.Fatalf("statements=%#v args=%#v", database.statements, database.arguments)
	}
	for name, mutate := range map[string]func(*AttackLabPreflight){
		"destination drift": func(item *AttackLabPreflight) { item.AllowedDestinations = []string{"foreign.example"} },
		"production":        func(item *AttackLabPreflight) { item.Environment = "production" },
		"limits":            func(item *AttackLabPreflight) { item.Limits.Memory = "8Gi" },
		"decision digest":   func(item *AttackLabPreflight) { item.DecisionDigest = strings.Repeat("A", 64) },
		"decision expiry": func(item *AttackLabPreflight) {
			item.DecisionExpiresAt = item.DecisionExpiresAt.In(time.FixedZone("hostile", 3600))
		},
	} {
		hostile := value
		mutate(&hostile)
		database.responses[postgresAttackLabPreflightSQL] = mustRedTeamJSON(t, hostile)
		if got, err := repository.PreflightAttackLabRun(context.Background(), identity, sourceRunID); err == nil || !reflect.DeepEqual(got, AttackLabPreflight{}) {
			t.Fatalf("%s accepted got=%#v err=%v", name, got, err)
		}
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
	complete.EvidenceVersionID, complete.EvidenceChecksum, complete.EvidenceSizeBytes = "version-attack-lab-1", strings.Repeat("c", 64), 512
	complete.AttemptStartedAt = &startedAt
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
	if _, err := repository.CreateAttackLabRun(context.Background(), identity, AttackLabCreateRequest{RunID: base.ID, SourceRunID: base.SourceRunID, DecisionDigest: strings.Repeat("a", 64), Approved: false, IdempotencyKey: "attack-lab-create-0001", CorrelationID: "pid_79200005-0000-4000-8000-000000000005"}); err == nil || len(database.statements) != 0 {
		t.Fatalf("unapproved run reached provider err=%v statements=%#v", err, database.statements)
	}
	if _, err := repository.CreateAttackLabRun(context.Background(), identity, AttackLabCreateRequest{RunID: base.ID, SourceRunID: base.SourceRunID, DecisionDigest: strings.Repeat("A", 64), Approved: true, IdempotencyKey: "attack-lab-create-0002", CorrelationID: "pid_79200005-0000-4000-8000-000000000005"}); err == nil || len(database.statements) != 0 {
		t.Fatalf("malformed decision digest reached provider err=%v statements=%#v", err, database.statements)
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
		AttemptStartedAt:  &startedAt,
	}
	if !validAttackLabRun(active) {
		t.Fatal("active cancellation state rejected")
	}

	attempt := AttackLabAttempt{
		Attempt:           1,
		EvidenceState:     "complete",
		Verdict:           "verified",
		CriterionObserved: true,
		CanaryTouched:     true,
		CleanupCompleted:  true,
		Evidence:          []string{"semantic:criterion", "gateway:decision", "egress:allowlist", "kubernetes:job", "cloud:task"},
		EvidenceReference: "s3://attack-lab-evidence/organizations/evidence.json",
		EvidenceVersionID: "version-attack-lab-1",
		EvidenceChecksum:  strings.Repeat("c", 64),
		EvidenceSizeBytes: 512,
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

func TestAttackLabRepositoryReadsCancelledRunWithExactFinalCleanupAttempt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	queuedAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	startedAt, completedAt := queuedAt.Add(time.Minute), queuedAt.Add(2*time.Minute)
	runID := "pid_79400001-0000-4000-8000-000000000001"
	run := AttackLabRun{ID: runID, Version: 4, SourceRunID: "pid_79400002-0000-4000-8000-000000000002", DefinitionID: "pid_79400003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_79400004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "cancelled", Attempt: 1, CancelRequested: true, CleanupState: "complete", Limits: AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: queuedAt, StartedAt: &startedAt, AttemptStartedAt: &startedAt, CompletedAt: &completedAt, ErrorCode: "cancelled"}
	attempt := AttackLabAttempt{Attempt: 1, EvidenceState: "unavailable", CleanupCompleted: true, ErrorCode: "cancelled", Evidence: []string{}, CompletedAt: completedAt}
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresAttackLabGetRunSQL: mustRedTeamJSON(t, AttackLabRunDetail{AttackLabRun: run, Attempts: []AttackLabAttempt{attempt}})}}
	repository := &PostgresRepository{database: database, schema: AttackLabExecutionSchemaVersion}
	detail, err := repository.GetAttackLabRun(context.Background(), identity, runID)
	if err != nil || len(detail.Attempts) != 1 || detail.Attempts[0].ErrorCode != "cancelled" {
		t.Fatalf("detail=%#v err=%v", detail, err)
	}
	database.responses[postgresAttackLabGetRunSQL] = mustRedTeamJSON(t, AttackLabRunDetail{AttackLabRun: run, Attempts: []AttackLabAttempt{}})
	if _, err := repository.GetAttackLabRun(context.Background(), identity, runID); err == nil {
		t.Fatal("post-sandbox cancellation without its durable cleanup attempt was accepted")
	}
}
