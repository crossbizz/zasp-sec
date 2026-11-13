package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentActionRepositoryUsesExactV27RecoveryReadiness(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentActionReadyV27SQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActionClaimV24SQL: json.RawMessage(`{"items":[]}`),
	}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := repository.ClaimTemporaryPolicyEffects(context.Background(), "security-agent-action-1", "lease-token-000000000001", 60, 10); err != nil || len(claims) != 0 {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if len(database.statements) != 3 || database.statements[0] != currentSecurityAgentActionReadySQL || database.statements[1] != postgresSecurityAgentActionReadyV27SQL || database.statements[2] != postgresSecurityAgentActionClaimV24SQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}

func TestSecurityAgentActionRepositoryClaimsHeartbeatsStoresReadsAndFinishesExactTenantTargets(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	organizationID := "pid_70000001-0000-4000-8000-000000000001"
	workspaceID := "pid_70000002-0000-4000-8000-000000000002"
	environmentID := "pid_70000003-0000-4000-8000-000000000003"
	runID := "pid_78000001-0000-4000-8000-000000000001"
	stepID := "pid_78000002-0000-4000-8000-000000000002"
	deviceID := "pid_78000003-0000-4000-8000-000000000003"
	credentialID := "pid_78000004-0000-4000-8000-000000000004"
	auditID := "pid_78000005-0000-4000-8000-000000000005"
	correlationID := "pid_78000006-0000-4000-8000-000000000006"
	payloadDigest := strings.Repeat("a", 64)
	envelopeDigest := strings.Repeat("b", 64)
	resultDigest := strings.Repeat("c", 64)
	policies := json.RawMessage(`[{"id":"temporary-containment-http","event":"http_request","condition":{"field":"http.method","operator":"present","value":""},"action":"block"}]`)
	claimPayload := `{"items":[{"organization_id":"` + organizationID + `","workspace_id":"` + workspaceID + `","environment_id":"` + environmentID + `","run_id":"` + runID + `","step_id":"` + stepID + `","phase":"apply","input_digest":"sha256:` + payloadDigest + `","ttl_seconds":600,"lease_expires_at":"` + now.Add(time.Minute).Format(time.RFC3339) + `","targets":[{"device_id":"` + deviceID + `","credential_id":"` + credentialID + `","sequence":2,"policy_version":2}]}]}`
	readPayload := `{"device_id":"` + deviceID + `","credential_id":"` + credentialID + `","phase":"apply","state":"stored","sequence":2,"policy_version":2,"key_id":"gateway-key-01","issued_at":"` + now.Format(time.RFC3339) + `","expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339) + `","failure_mode":"closed","payload_digest":"sha256:` + payloadDigest + `","policies":` + string(policies) + `,"signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `","envelope_digest":"sha256:` + envelopeDigest + `"}`
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentActionReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActionClaimSQL:     json.RawMessage(claimPayload),
		postgresSecurityAgentActionHeartbeatSQL: json.RawMessage(`{"lease_expires_at":"` + now.Add(2*time.Minute).Format(time.RFC3339) + `"}`),
		postgresSecurityAgentActionStoreSQL:     json.RawMessage(`{"device_id":"` + deviceID + `","phase":"apply","sequence":2,"policy_version":2,"envelope_digest":"sha256:` + envelopeDigest + `"}`),
		postgresSecurityAgentActionReadSQL:      json.RawMessage(readPayload),
		postgresSecurityAgentActionFinishSQL:    json.RawMessage(`{"run_id":"` + runID + `","step_id":"` + stepID + `","phase":"apply","effect_state":"cleanup_pending","outcome_id":"pid_78000007-0000-4000-8000-000000000007","result_digest":"sha256:` + resultDigest + `"}`),
	}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := repository.ClaimTemporaryPolicyEffects(context.Background(), "security-agent-action-1", "lease-token-000000000001", 60, 10)
	if err != nil || len(claims) != 1 || len(claims[0].Targets) != 1 || claims[0].EnvironmentID != environmentID {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	claim := claims[0]
	if err := repository.HeartbeatTemporaryPolicyEffect(context.Background(), claim, "security-agent-action-1", "lease-token-000000000001", 60); err != nil {
		t.Fatal(err)
	}
	envelope := TemporaryPolicyTargetEnvelope{Target: claim.Targets[0], Phase: "apply", KeyID: "gateway-key-01", IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), FailureMode: "closed", PayloadDigest: "sha256:" + payloadDigest, Policies: policies, Signature: make([]byte, 64), EnvelopeDigest: "sha256:" + envelopeDigest}
	if err := repository.StoreTemporaryPolicyTarget(context.Background(), claim, "security-agent-action-1", "lease-token-000000000001", envelope); err != nil {
		t.Fatal(err)
	}
	readback, err := repository.ReadTemporaryPolicyTarget(context.Background(), claim, claim.Targets[0])
	if err != nil || readback.EnvelopeDigest != envelope.EnvelopeDigest || readback.Target != envelope.Target {
		t.Fatalf("readback=%#v err=%v", readback, err)
	}
	result, err := repository.FinishTemporaryPolicyEffect(context.Background(), claim, "security-agent-action-1", "lease-token-000000000001", "sha256:"+resultDigest, auditID, correlationID)
	if err != nil || result.EffectState != "cleanup_pending" || result.RunID != runID {
		t.Fatalf("finish=%#v err=%v", result, err)
	}
}

func TestSecurityAgentActionRepositoryClaimsExactV24SessionIsolation(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	organizationID := "pid_70000001-0000-4000-8000-000000000001"
	workspaceID := "pid_70000002-0000-4000-8000-000000000002"
	environmentID := "pid_70000003-0000-4000-8000-000000000003"
	runID := "pid_78000001-0000-4000-8000-000000000001"
	stepID := "pid_78000002-0000-4000-8000-000000000002"
	sessionID := "pid_78000003-0000-4000-8000-000000000003"
	deviceID := "pid_78000004-0000-4000-8000-000000000004"
	credentialID := "pid_78000005-0000-4000-8000-000000000005"
	claimPayload := `{"items":[{"organization_id":"` + organizationID + `","workspace_id":"` + workspaceID + `","environment_id":"` + environmentID + `","run_id":"` + runID + `","step_id":"` + stepID + `","action_key":"isolate_session","session_id":"` + sessionID + `","phase":"apply","input_digest":"sha256:` + strings.Repeat("a", 64) + `","ttl_seconds":600,"lease_expires_at":"` + now.Add(time.Minute).Format(time.RFC3339) + `","targets":[{"device_id":"` + deviceID + `","credential_id":"` + credentialID + `","sequence":2,"policy_version":2}]}]}`
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentActionReadyV24SQL: json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActionClaimV24SQL: json.RawMessage(claimPayload),
	}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := repository.ClaimTemporaryPolicyEffects(context.Background(), "security-agent-action-1", "lease-token-000000000001", 60, 10)
	if err != nil || len(claims) != 1 || claims[0].ActionKey != "isolate_session" || claims[0].SessionID != sessionID || claims[0].Targets[0].DeviceID != deviceID {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if len(database.statements) != 4 || database.statements[0] != currentSecurityAgentActionReadySQL || database.statements[1] != postgresSecurityAgentActionReadyV27SQL || database.statements[2] != postgresSecurityAgentActionReadyV24SQL || database.statements[3] != postgresSecurityAgentActionClaimV24SQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}

func TestSecurityAgentActionRepositoryRejectsCrossTenantAndDriftedEnvelopeBeforeDatabase(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentActionReadySQL: json.RawMessage(`{"release":true,"principal":true}`)}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	claim := TemporaryPolicyEffectClaim{OrganizationID: "foreign", Phase: "apply"}
	if err := repository.StoreTemporaryPolicyTarget(context.Background(), claim, "security-agent-action-1", "lease-token-000000000001", TemporaryPolicyTargetEnvelope{}); err != ErrRepositoryOperation {
		t.Fatalf("store err=%v", err)
	}
	if len(database.statements) != 5 || database.statements[0] != currentSecurityAgentActionReadySQL || database.statements[1] != postgresSecurityAgentActionReadyV27SQL || database.statements[2] != postgresSecurityAgentActionReadyV24SQL || database.statements[3] != postgresSecurityAgentActionReadyV23SQL || database.statements[4] != postgresSecurityAgentActionReadySQL {
		t.Fatalf("unexpected database statements=%#v", database.statements)
	}
}

func TestTemporaryPolicyEffectClaimRequiresDatabaseTargetOrder(t *testing.T) {
	claim := TemporaryPolicyEffectClaim{
		OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
		RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:" + strings.Repeat("a", 64), TTLSeconds: 600, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
		Targets: []TemporaryPolicyTarget{
			{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000005-0000-4000-8000-000000000005", Sequence: 1, PolicyVersion: 1},
			{DeviceID: "pid_78000004-0000-4000-8000-000000000004", CredentialID: "pid_78000006-0000-4000-8000-000000000006", Sequence: 1, PolicyVersion: 1},
		},
	}
	if !validTemporaryPolicyEffectClaim(claim) {
		t.Fatal("rejected canonical database target order")
	}
	claim.Targets[0], claim.Targets[1] = claim.Targets[1], claim.Targets[0]
	if validTemporaryPolicyEffectClaim(claim) {
		t.Fatal("accepted target order that cannot match the database result digest")
	}
}

func TestSecurityAgentActionRepositoryReconcilesConnectorRevocationsOnlyOnV23(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentActionReadyV23SQL:  json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActionReconcileSQL: json.RawMessage(`{"reconciled":2}`),
	}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled, err := repository.ReconcileConnectorRevocations(context.Background(), "security-agent-action-1", 10); err != nil || reconciled != 2 {
		t.Fatalf("reconciled=%d err=%v", reconciled, err)
	}
	if len(database.statements) != 5 || database.statements[0] != currentSecurityAgentActionReadySQL || database.statements[1] != postgresSecurityAgentActionReadyV27SQL || database.statements[2] != postgresSecurityAgentActionReadyV24SQL || database.statements[3] != postgresSecurityAgentActionReadyV23SQL || database.statements[4] != postgresSecurityAgentActionReconcileSQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}

func TestSecurityAgentActionRepositoryTreatsConnectorReconciliationAsUnavailableNoopOnV22(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		postgresSecurityAgentActionReadySQL: json.RawMessage(`{"release":true,"principal":true}`),
	}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled, err := repository.ReconcileConnectorRevocations(context.Background(), "security-agent-action-1", 10); err != nil || reconciled != 0 {
		t.Fatalf("reconciled=%d err=%v", reconciled, err)
	}
	if len(database.statements) != 5 || database.statements[0] != currentSecurityAgentActionReadySQL || database.statements[1] != postgresSecurityAgentActionReadyV27SQL || database.statements[2] != postgresSecurityAgentActionReadyV24SQL || database.statements[3] != postgresSecurityAgentActionReadyV23SQL || database.statements[4] != postgresSecurityAgentActionReadySQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}

// On the current catalog the action worker asks the current readiness
// question first and, when it answers, no historical release probe at all.
// That question includes the catalog integrity check, so the per-release
// budget pin is not asked either. A refusal falls back to the historical
// questions, which keep their own pins.
func TestSecurityAgentActionRepositoryPrefersCurrentCatalogReadiness(t *testing.T) {
	database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{
		currentSecurityAgentActionReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresSecurityAgentActionClaimV24SQL: json.RawMessage(`{"items":[]}`),
	}}
	repository, err := NewSecurityAgentActionRepository(database)
	if err != nil || !repository.current || !repository.sessionIsolation || repository.reconcileSQL != postgresSecurityAgentActionReconcileSQL {
		t.Fatalf("repository=%#v err=%v", repository, err)
	}
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ClaimTemporaryPolicyEffects(context.Background(), "security-agent-action-1", "lease-token-000000000001", 60, 10); err != nil {
		t.Fatal(err)
	}
	for _, statement := range database.statements {
		if statement != currentSecurityAgentActionReadySQL && statement != postgresSecurityAgentActionClaimV24SQL {
			t.Fatalf("historical statement used on the current catalog: %s", statement)
		}
	}
	if len(database.arguments) == 0 || len(database.arguments[0]) != 2 || database.arguments[0][0] != migrations.ProductionRecovery().Checksum() || database.arguments[0][1] != migrations.ProductionRecoverySemanticFingerprint() {
		t.Fatalf("readiness pins=%v", database.arguments)
	}
	for name, answer := range map[string]string{"release": `{"release":false,"principal":true}`, "principal": `{"release":true,"principal":false}`, "shape": `{"release":true}`} {
		refused := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{currentSecurityAgentActionReadySQL: json.RawMessage(answer)}}
		if repository, err := NewSecurityAgentActionRepository(refused); err == nil {
			t.Fatalf("%s refusal accepted: %#v", name, repository)
		}
		if len(refused.statements) != 5 || refused.statements[1] != postgresSecurityAgentActionReadyV27SQL {
			t.Fatalf("%s refusal did not fall back to the historical questions: %v", name, refused.statements)
		}
	}
}
