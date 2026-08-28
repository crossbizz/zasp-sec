package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
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
	evidenceKey := mustAttackLabExecutionEvidenceKey(t, identity.Scope, runID, 1)
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
		postgresAttackLabResolveEgressSQL: mustRedTeamJSON(t, map[string]any{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "run_id": runID, "destination": "adapter.customer.example", "credential_reference": "ref:red-team/target-0001", "methods": []string{"POST"}, "expires_at": now.Add(60 * time.Second)}),
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
	if authority, err := proxy.ResolveAttackLabEgress(context.Background(), identity.Scope, runID, "adapter.customer.example"); err != nil || authority.RunID != runID || authority.CredentialReference != "ref:red-team/target-0001" || !reflect.DeepEqual(authority.Methods, []string{"POST"}) {
		t.Fatalf("egress=%#v err=%v", authority, err)
	}
	wantClaim := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID, worker, token, 60}
	if calls := database.callsFor(postgresAttackLabClaimRunSQL); len(calls) != 2 || !reflect.DeepEqual(calls[0], wantClaim) || !reflect.DeepEqual(calls[1], wantClaim) {
		t.Fatalf("claim calls=%#v", calls)
	}
}

func TestAttackLabExecutionRepositoryUsesExactV27RecoveryReadiness(t *testing.T) {
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresProductionRecoveryReadinessSQL: json.RawMessage(`true`),
		postgresAttackLabPrincipalReadySQL:     json.RawMessage(`true`),
	}}
	if _, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityController); err != nil {
		t.Fatal(err)
	}
	if calls := database.callsFor(postgresProductionRecoveryReadinessSQL); len(calls) != 1 {
		t.Fatalf("v27 readiness calls=%#v", calls)
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
	key := mustAttackLabExecutionEvidenceKey(t, identity.Scope, runID, 1)
	input := AttackLabCleanupInput{RunID: runID, Controller: "attack-lab-controller-01", LeaseToken: strings.Repeat("a", 32), InputDigest: sha256.Sum256([]byte("attack-lab-input")), Attempt: 1, SandboxReference: "k8s://attack-lab/jobs/zasp-attack-lab-7c000001@123e4567-e89b-12d3-a456-426614174000", Verdict: "verified", CriterionObserved: true, CanaryTouched: true, Evidence: []string{"semantic:criterion observed", "gateway:allowed", "egress:adapter.customer.example", "kubernetes:job complete"}, EvidenceReference: "s3://zasp-attack-lab-evidence/" + key, EvidenceKey: key, EvidenceVersionID: "version-1", EvidenceChecksum: bytes.Repeat([]byte{0xcc}, sha256.Size), EvidenceSizeBytes: 512}
	if _, err := repository.BeginAttackLabCleanup(context.Background(), identity.Scope, input); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("incomplete evidence error=%v", err)
	}
	if calls := database.callsFor(postgresAttackLabBeginCleanupSQL); len(calls) != 0 {
		t.Fatalf("incomplete evidence reached database: %#v", calls)
	}
	input.Evidence = append(input.Evidence, "cloud:canary touched")
	input.EvidenceReference = "s3://zasp-attack-lab-evidence/foreign-prefix/" + key
	if _, err := repository.BeginAttackLabCleanup(context.Background(), identity.Scope, input); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("prefixed evidence object path error=%v", err)
	}
	if calls := database.callsFor(postgresAttackLabBeginCleanupSQL); len(calls) != 0 {
		t.Fatalf("prefixed evidence object path reached database: %#v", calls)
	}
}

func TestAttackLabExecutionRepositoryRejectsMissingOrMalformedProxyCredentialAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Now().UTC()
	runID := "pid_7c000031-0000-4000-8000-000000000031"
	for name, reference := range map[string]any{
		"missing": nil,
		"foreign": "ref:github/installation/123456",
		"inline":  "plaintext-secret",
	} {
		t.Run(name, func(t *testing.T) {
			value := map[string]any{"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "run_id": runID, "destination": "adapter.customer.example", "methods": []string{"POST"}, "expires_at": now.Add(time.Minute)}
			if reference != nil {
				value["credential_reference"] = reference
			}
			database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresAttackLabExecutionReadinessSQL: json.RawMessage(`true`), postgresAttackLabPrincipalReadySQL: json.RawMessage(`true`), postgresAttackLabResolveEgressSQL: mustRedTeamJSON(t, value)}}
			repository, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityProxy)
			if err != nil {
				t.Fatal(err)
			}
			if authority, err := repository.ResolveAttackLabEgress(context.Background(), identity.Scope, runID, "adapter.customer.example"); !errors.Is(err, ErrRepositoryUnavailable) || !reflect.DeepEqual(authority, AttackLabEgressAuthority{}) {
				t.Fatalf("authority=%#v err=%v", authority, err)
			}
		})
	}
}

func TestAttackLabExecutionRepositoryAllowsUnavailableAndCancelledEvidenceCleanup(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	now := time.Now().UTC()
	runID := "pid_7c100001-0000-4000-8000-000000000001"
	digest := sha256.Sum256([]byte("attack-lab-cleanup-authority"))
	run := AttackLabRun{ID: runID, Version: 4, SourceRunID: "pid_7c100002-0000-4000-8000-000000000002", DefinitionID: "pid_7c100003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7c100004-0000-4000-8000-000000000004", TargetKind: "agent_endpoint", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "cleanup", Attempt: 1, CleanupState: "in_progress", Limits: AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now, StartedAt: &now}
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresAttackLabExecutionReadinessSQL: json.RawMessage(`true`), postgresAttackLabPrincipalReadySQL: json.RawMessage(`true`), postgresAttackLabBeginCleanupSQL: mustRedTeamJSON(t, mergeAttackLabRun(run, map[string]any{"replayed": false}))}}
	repository, err := NewAttackLabExecutionRepository(database, AttackLabExecutionAuthorityController)
	if err != nil {
		t.Fatal(err)
	}
	base := AttackLabCleanupInput{RunID: runID, Controller: "attack-lab-controller-01", LeaseToken: strings.Repeat("a", 32), InputDigest: digest, Attempt: 1, SandboxReference: "k8s://attack-lab/jobs/zasp-attack-lab-7c100001@123e4567-e89b-12d3-a456-426614174000", Verdict: "inconclusive", ErrorCode: "outcome_unknown"}
	if result, err := repository.BeginAttackLabCleanup(context.Background(), identity.Scope, base); err != nil || result.Run.Status != "cleanup" {
		t.Fatalf("unavailable result=%#v err=%v", result, err)
	}
	key := mustAttackLabExecutionEvidenceKey(t, identity.Scope, runID, 1)
	cancelled := base
	cancelled.ErrorCode = "cancelled"
	cancelled.Evidence = []string{"semantic:cancelled before verdict", "gateway:cancelled", "egress:no undeclared egress", "kubernetes:cleanup requested", "cloud:no verified canary touch"}
	cancelled.EvidenceReference, cancelled.EvidenceKey, cancelled.EvidenceVersionID = "s3://zasp-attack-lab-evidence/"+key, key, "version-cancelled-1"
	cancelled.EvidenceChecksum, cancelled.EvidenceSizeBytes = bytes.Repeat([]byte{0xcd}, sha256.Size), 512
	if result, err := repository.BeginAttackLabCleanup(context.Background(), identity.Scope, cancelled); err != nil || result.Run.Status != "cleanup" {
		t.Fatalf("cancelled result=%#v err=%v", result, err)
	}
	if calls := database.callsFor(postgresAttackLabBeginCleanupSQL); len(calls) != 2 {
		t.Fatalf("cleanup calls=%#v", calls)
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

func mustAttackLabExecutionEvidenceKey(t *testing.T, scope domain.Scope, runID string, attempt int) string {
	t.Helper()
	evidenceID, err := CanonicalDiscoveryID(scope, "attack_lab_evidence", runID+"\x1f"+strconv.Itoa(attempt))
	if err != nil {
		t.Fatal(err)
	}
	return "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + evidenceID
}
