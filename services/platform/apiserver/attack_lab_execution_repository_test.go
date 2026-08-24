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

func TestAttackLabExecutionRepositoryBindsOutboxControllerAndProxyAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Now().UTC()
	runID := "pid_7b000001-0000-4000-8000-000000000001"
	sourceRunID := "pid_7b000002-0000-4000-8000-000000000002"
	definitionID := "pid_7b000003-0000-4000-8000-000000000003"
	targetID := "pid_7b000004-0000-4000-8000-000000000004"
	outboxID := "pid_7b000005-0000-4000-8000-000000000005"
	worker := "attack-lab-controller-01"
	token := strings.Repeat("a", 32)
	inputDigest := sha256.Sum256([]byte("attack-lab-input"))
	payload := json.RawMessage(`{"organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","run_id":"` + runID + `","source_run_id":"` + sourceRunID + `","definition_id":"` + definitionID + `","definition_version":2,"target_id":"` + targetID + `","target_kind":"agent_endpoint","input_digest":"` + hex.EncodeToString(inputDigest[:]) + `"}`)
	payloadDigest := sha256.Sum256(payload)
	baseRun := AttackLabRun{ID: runID, Version: 2, SourceRunID: sourceRunID, DefinitionID: definitionID, DefinitionVersion: 2, TargetID: targetID, TargetKind: "agent_endpoint", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now, StartedAt: &now}
	preflight := AttackLabPreflightSnapshot{Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", AllowedDestinations: []string{"adapter.customer.example"}, SuccessCriterion: "Reject direct prompt injection", ExpectedSideEffects: []string{"audit event"}}
	claimRun := mustRedTeamJSON(t, map[string]any{"disposition": "claimed", "run": baseRun, "preflight": preflight, "input_digest": hex.EncodeToString(inputDigest[:]), "lease_expires_at": now.Add(60 * time.Second)})
	claimedOutbox := mustRedTeamJSON(t, map[string]any{"items": []map[string]any{{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "outbox_id": outboxID, "topic": AttackLabOutboxTopic, "payload": string(payload), "payload_digest": hex.EncodeToString(payloadDigest[:]), "attempt": 1, "lease_expires_at": now.Add(60 * time.Second)}}})
	sandboxReference := "k8s://attack-lab/jobs/zasp-attack-lab-7b000001@123e4567-e89b-12d3-a456-426614174000"
	running := baseRun
	running.Version, running.Status = 3, "running"
	retryable := baseRun
	retryable.Version, retryable.Status, retryable.ErrorCode = 3, "retryable", "retryable"
	cleanup := running
	cleanup.Version, cleanup.Status, cleanup.CleanupState = 4, "cleanup", "in_progress"
	evidenceKey := "organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/attack-lab/" + runID + "/attempts/1/evidence.json"
	evidenceReference := "s3://zasp-attack-lab-evidence/" + evidenceKey
	complete := cleanup
	complete.Version, complete.Status, complete.CleanupState, complete.Verdict, complete.EvidenceReference, complete.CompletedAt = 5, "complete", "complete", "verified", evidenceReference, &now
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresAttackLabExecutionReadinessSQL: json.RawMessage(`true`), postgresAttackLabPrincipalReadySQL: json.RawMessage(`true`),
		postgresAttackLabClaimOutboxSQL: claimedOutbox, postgresAttackLabHeartbeatOutboxSQL: mustRedTeamJSON(t, map[string]any{"topic": AttackLabOutboxTopic, "lease_expires_at": now.Add(60 * time.Second), "remaining_count": 1}),
		postgresAttackLabAckOutboxSQL:   mustRedTeamJSON(t, map[string]any{"outbox_id": outboxID, "state": "published", "provider_ack": "sha256:" + strings.Repeat("b", 64), "published_at": now, "remaining_count": 0, "replayed": false}),
		postgresAttackLabRetryOutboxSQL: mustRedTeamJSON(t, map[string]any{"outbox_id": outboxID, "state": "pending", "available_at": now.Add(30 * time.Second), "error_code": "queue_publish_unknown", "remaining_count": 0, "replayed": false}),
		postgresAttackLabClaimRunSQL:    claimRun, postgresAttackLabHeartbeatRunSQL: mustRedTeamJSON(t, map[string]any{"renewed": true, "cancel_requested": false, "lease_expires_at": now.Add(60 * time.Second)}), postgresAttackLabRetryRunSQL: mustRedTeamJSON(t, mergeAttackLabRun(retryable, nil)),
		postgresAttackLabMarkRunningSQL: mustRedTeamJSON(t, mergeAttackLabRun(running, map[string]any{"replayed": false})), postgresAttackLabBeginCleanupSQL: mustRedTeamJSON(t, mergeAttackLabRun(cleanup, map[string]any{"replayed": false})), postgresAttackLabFinishCleanupSQL: mustRedTeamJSON(t, mergeAttackLabRun(complete, map[string]any{"replayed": false})),
		postgresAttackLabResolveEgressSQL: mustRedTeamJSON(t, map[string]any{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "run_id": runID, "destination": "adapter.customer.example", "methods": []string{"POST"}, "expires_at": now.Add(60 * time.Second)}),
	}}

	outbox, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityOutbox)
	if err != nil {
		t.Fatal(err)
	}
	events, err := outbox.ClaimAttackLabOutbox(context.Background(), worker, token, 60, 10)
	if err != nil || len(events) != 1 || events[0].ID != outboxID || !bytes.Equal(events[0].Payload, payload) || !bytes.Equal(events[0].PayloadDigest, payloadDigest[:]) {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	if transition, err := outbox.HeartbeatAttackLabOutbox(context.Background(), worker, token, 60, 1); err != nil || transition.RemainingCount != 1 {
		t.Fatalf("heartbeat=%#v err=%v", transition, err)
	}
	if transition, err := outbox.AcknowledgeAttackLabOutbox(context.Background(), identity.Scope, outboxID, worker, token, "sha256:"+strings.Repeat("b", 64)); err != nil || transition.State != "published" || transition.Replayed {
		t.Fatalf("ack=%#v err=%v", transition, err)
	}
	if transition, err := outbox.RetryAttackLabOutbox(context.Background(), identity.Scope, outboxID, worker, token, 30, "queue_publish_unknown"); err != nil || transition.State != "pending" || transition.Replayed {
		t.Fatalf("retry=%#v err=%v", transition, err)
	}

	controller, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityController)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := controller.ClaimAttackLabRun(context.Background(), identity.Scope, runID, worker, token, 60)
	if err != nil || claim.Disposition != "claimed" || claim.Run.ID != runID || claim.Preflight.SuccessCriterion != preflight.SuccessCriterion || claim.InputDigest != inputDigest {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	if heartbeat, err := controller.HeartbeatAttackLabRun(context.Background(), identity.Scope, runID, worker, token, 60); err != nil || !heartbeat.Renewed || heartbeat.CancelRequested {
		t.Fatalf("heartbeat=%#v err=%v", heartbeat, err)
	}
	if result, err := controller.RetryAttackLabRun(context.Background(), identity.Scope, runID, worker, token, inputDigest, "retryable", now.Add(30*time.Second)); err != nil || result.Run.Status != "retryable" {
		t.Fatalf("retry run=%#v err=%v", result, err)
	}
	if result, err := controller.MarkAttackLabRunning(context.Background(), identity.Scope, AttackLabRunningInput{RunID: runID, Controller: worker, LeaseToken: token, InputDigest: inputDigest, SandboxReference: sandboxReference}); err != nil || result.Run.Status != "running" || result.Replayed {
		t.Fatalf("running=%#v err=%v", result, err)
	}
	database.responses[postgresAttackLabClaimRunSQL] = mustRedTeamJSON(t, map[string]any{"disposition": "running", "run": running, "sandbox_reference": sandboxReference, "input_digest": hex.EncodeToString(inputDigest[:]), "lease_expires_at": now.Add(60 * time.Second)})
	resumed, err := controller.ClaimAttackLabRun(context.Background(), identity.Scope, runID, worker, token, 60)
	if err != nil || resumed.Disposition != "running" || resumed.Run.Status != "running" || resumed.SandboxReference != sandboxReference || resumed.InputDigest != inputDigest {
		t.Fatalf("running resume=%#v err=%v", resumed, err)
	}
	cleanupInput := AttackLabCleanupInput{RunID: runID, Controller: worker, LeaseToken: token, InputDigest: inputDigest, Attempt: 1, SandboxReference: sandboxReference, Verdict: "verified", CriterionObserved: true, CanaryTouched: true, Evidence: []string{"semantic:criterion observed", "gateway:allowed", "egress:adapter.customer.example", "kubernetes:job complete", "cloud:canary touched"}, EvidenceReference: evidenceReference, EvidenceKey: evidenceKey, EvidenceVersionID: "version-1", EvidenceChecksum: bytes.Repeat([]byte{0xcc}, sha256.Size), EvidenceSizeBytes: 512}
	if result, err := controller.BeginAttackLabCleanup(context.Background(), identity.Scope, cleanupInput); err != nil || result.Run.Status != "cleanup" || result.Replayed {
		t.Fatalf("begin cleanup=%#v err=%v", result, err)
	}
	if result, err := controller.FinishAttackLabCleanup(context.Background(), identity.Scope, runID, worker, token, inputDigest); err != nil || result.Run.Status != "complete" || result.Replayed {
		t.Fatalf("finish cleanup=%#v err=%v", result, err)
	}

	proxy, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityProxy)
	if err != nil {
		t.Fatal(err)
	}
	if authority, err := proxy.ResolveAttackLabEgress(context.Background(), identity.Scope, runID, "adapter.customer.example"); err != nil || authority.RunID != runID || !reflect.DeepEqual(authority.Methods, []string{"POST"}) {
		t.Fatalf("egress=%#v err=%v", authority, err)
	}
	wantClaim := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID, worker, token, 60}
	if calls := database.callsFor(postgresAttackLabClaimRunSQL); len(calls) != 2 || !reflect.DeepEqual(calls[0], wantClaim) || !reflect.DeepEqual(calls[1], wantClaim) {
		t.Fatalf("claim calls=%#v", calls)
	}
}

func TestAttackLabExecutionRepositoryRejectsIncompleteEvidenceBeforeDatabaseIO(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresAttackLabExecutionReadinessSQL: json.RawMessage(`true`), postgresAttackLabPrincipalReadySQL: json.RawMessage(`true`)}}
	repository, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityController)
	if err != nil {
		t.Fatal(err)
	}
	runID := "pid_7c000001-0000-4000-8000-000000000001"
	key := "organizations/" + identity.Scope.OrganizationID().String() + "/workspaces/" + identity.Scope.WorkspaceID().String() + "/environments/" + identity.Scope.EnvironmentID().String() + "/attack-lab/" + runID + "/attempts/1/evidence.json"
	input := AttackLabCleanupInput{RunID: runID, Controller: "attack-lab-controller-01", LeaseToken: strings.Repeat("a", 32), InputDigest: sha256.Sum256([]byte("attack-lab-input")), Attempt: 1, SandboxReference: "k8s://attack-lab/jobs/zasp-attack-lab-7c000001@123e4567-e89b-12d3-a456-426614174000", Verdict: "verified", CriterionObserved: true, CanaryTouched: true, Evidence: []string{"semantic:criterion observed", "gateway:allowed", "egress:adapter.customer.example", "kubernetes:job complete"}, EvidenceReference: "s3://zasp-attack-lab-evidence/" + key, EvidenceKey: key, EvidenceVersionID: "version-1", EvidenceChecksum: bytes.Repeat([]byte{0xcc}, sha256.Size), EvidenceSizeBytes: 512}
	if _, err := repository.BeginAttackLabCleanup(context.Background(), identity.Scope, input); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("incomplete evidence error=%v", err)
	}
	if calls := database.callsFor(postgresAttackLabBeginCleanupSQL); len(calls) != 0 {
		t.Fatalf("incomplete evidence reached database: %#v", calls)
	}
}

func mergeAttackLabRun(run AttackLabRun, extra map[string]any) map[string]any {
	payload, _ := json.Marshal(run)
	result := map[string]any{}
	_ = json.Unmarshal(payload, &result)
	for key, value := range extra {
		result[key] = value
	}
	return result
}
