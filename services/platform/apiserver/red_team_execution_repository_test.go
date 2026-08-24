package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRedTeamExecutionRepositoryBindsOutboxAndRunLeases(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	runID := "pid_99000001-0000-4000-8000-000000000001"
	definitionID := "pid_99000002-0000-4000-8000-000000000002"
	outboxID := "pid_99000003-0000-4000-8000-000000000003"
	worker := "red-team-worker-01"
	token := strings.Repeat("a", 32)
	inputDigest := sha256.Sum256([]byte("red-team-input"))
	payload := json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","run_id":"` + runID + `","definition_id":"` + definitionID + `","definition_version":1,"input_digest":"` + strings.Repeat("b", 64) + `"}`)
	payloadDigest := sha256.Sum256(payload)
	now := time.Now().UTC()
	run := RedTeamRun{ID: runID, Version: 2, DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1, QueuedAt: now, StartedAt: &now}
	definition := RedTeamDefinition{ID: definitionID, Version: 1, Name: "Bounded prompt injection", TargetID: "pid_99000004-0000-4000-8000-000000000004", TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, Safety: RedTeamSafety{Environment: "test", CredentialClass: "read_only", ExpectedSideEffects: []string{"read-only evaluation"}}, Enabled: true, CreatedAt: now, UpdatedAt: now}
	claimRun := mustRedTeamJSON(t, map[string]any{"disposition": "claimed", "run": run, "definition": definition, "input_digest": hex.EncodeToString(inputDigest[:]), "lease_expires_at": now.Add(60 * time.Second)})
	claimedOutbox := mustRedTeamJSON(t, []map[string]any{{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "outbox_id": outboxID, "topic": RedTeamOutboxTopic, "payload": string(payload), "payload_digest": hex.EncodeToString(payloadDigest[:]), "attempt": 1, "lease_expires_at": now.Add(60 * time.Second)}})
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresRedTeamExecutionReadinessSQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`),
		postgresRedTeamClaimOutboxSQL: claimedOutbox, postgresRedTeamHeartbeatOutboxSQL: json.RawMessage(`true`), postgresRedTeamAckOutboxSQL: json.RawMessage(`true`), postgresRedTeamRetryOutboxSQL: json.RawMessage(`true`),
		postgresRedTeamClaimRunSQL: claimRun, postgresRedTeamHeartbeatRunSQL: json.RawMessage(`{"renewed":true,"cancel_requested":false}`),
		postgresRedTeamFinishRunSQL: mustRedTeamJSON(t, completeRedTeamRun(run, now)), postgresRedTeamRetryRunSQL: mustRedTeamJSON(t, retryableRedTeamRun(run)), postgresRedTeamCancelClaimedRunSQL: mustRedTeamJSON(t, cancelledRedTeamRun(run, now)),
	}}

	outbox, err := NewRedTeamExecutionRepository(database, RedTeamExecutionAuthorityOutbox)
	if err != nil {
		t.Fatal(err)
	}
	events, err := outbox.ClaimRedTeamOutbox(context.Background(), worker, token, 60, 10)
	if err != nil || len(events) != 1 || events[0].ID != outboxID || !bytes.Equal(events[0].Payload, payload) || !bytes.Equal(events[0].PayloadDigest, payloadDigest[:]) {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	if renewed, err := outbox.HeartbeatRedTeamOutbox(context.Background(), identity.Scope, outboxID, worker, token, 60); err != nil || !renewed {
		t.Fatalf("heartbeat renewed=%v err=%v", renewed, err)
	}
	if err := outbox.AcknowledgeRedTeamOutbox(context.Background(), identity.Scope, outboxID, worker, token, "sha256:"+strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if err := outbox.RetryRedTeamOutbox(context.Background(), identity.Scope, outboxID, worker, token, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}

	runner, err := NewRedTeamExecutionRepository(database, RedTeamExecutionAuthorityWorker)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runner.ClaimRedTeamRun(context.Background(), identity.Scope, runID, worker, token, 60)
	if err != nil || claim.Disposition != "claimed" || claim.Run.ID != runID || claim.Definition.ID != definitionID || claim.InputDigest != inputDigest {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	heartbeat, err := runner.HeartbeatRedTeamRun(context.Background(), identity.Scope, runID, worker, token, 60)
	if err != nil || !heartbeat.Renewed || heartbeat.CancelRequested {
		t.Fatalf("heartbeat=%#v err=%v", heartbeat, err)
	}
	evidenceKey := "organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/artifacts/" + runID
	completion := RedTeamRunCompletion{RunID: runID, Worker: worker, LeaseToken: token, InputDigest: inputDigest, Verdict: "pass", Objective: "Reject prompt injection", Behavior: "The target refused the unsafe instruction.", Evidence: []string{"target returned a bounded refusal"}, EvidenceReference: "s3://zasp-evidence/" + evidenceKey, EvidenceKey: evidenceKey, EvidenceVersionID: "version-1", EvidenceChecksum: bytes.Repeat([]byte{0xee}, 32), EvidenceSizeBytes: 128}
	if _, err := runner.FinishRedTeamRun(context.Background(), identity.Scope, completion); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.RetryRedTeamRun(context.Background(), identity.Scope, runID, worker, token, inputDigest, "retryable", now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.CancelClaimedRedTeamRun(context.Background(), identity.Scope, runID, worker, token, inputDigest); err != nil {
		t.Fatal(err)
	}
	if calls := database.callsFor(postgresRedTeamClaimRunSQL); len(calls) != 1 || !reflect.DeepEqual(calls[0], []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID, worker, token, 60}) {
		t.Fatalf("claim calls=%#v", calls)
	}
}

func TestRedTeamExecutionRepositoryRejectsWrongAuthorityAndHostileOutput(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresRedTeamExecutionReadinessSQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`), postgresRedTeamClaimOutboxSQL: json.RawMessage(`[{"secret":"must-not-leak"}]`)}}
	if repository, err := NewRedTeamExecutionRepository(nil, RedTeamExecutionAuthorityWorker); repository != nil || !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("nil repository=%v err=%v", repository, err)
	}
	worker, err := NewRedTeamExecutionRepository(database, RedTeamExecutionAuthorityWorker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.ClaimRedTeamOutbox(context.Background(), "red-team-worker-01", strings.Repeat("a", 32), 60, 10); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("wrong authority error=%v", err)
	}
	outbox, err := NewRedTeamExecutionRepository(database, RedTeamExecutionAuthorityOutbox)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.ClaimRedTeamOutbox(context.Background(), "red-team-outbox-01", strings.Repeat("a", 32), 60, 10); !errors.Is(err, ErrRepositoryUnavailable) || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("hostile output error=%v", err)
	}
}

func completeRedTeamRun(run RedTeamRun, completedAt time.Time) RedTeamRun {
	run.Version, run.Status, run.Verdict, run.CompletedAt = 3, "complete", "pass", &completedAt
	return run
}

func retryableRedTeamRun(run RedTeamRun) RedTeamRun {
	run.Version, run.Status, run.ErrorCode = 3, "retryable", "retryable"
	return run
}

func cancelledRedTeamRun(run RedTeamRun, completedAt time.Time) RedTeamRun {
	run.Version, run.Status, run.ErrorCode, run.CancelRequested, run.CompletedAt = 3, "cancelled", "cancelled", true, &completedAt
	return run
}

func mustRedTeamJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
