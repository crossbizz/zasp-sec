package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
	if len(database.statements) != 2 || database.statements[0] != postgresSecurityAgentActionReadyV23SQL || database.statements[1] != postgresSecurityAgentActionReadySQL {
		t.Fatalf("unexpected database statements=%#v", database.statements)
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
	if len(database.statements) != 2 || database.statements[0] != postgresSecurityAgentActionReadyV23SQL || database.statements[1] != postgresSecurityAgentActionReconcileSQL {
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
	if len(database.statements) != 2 || database.statements[0] != postgresSecurityAgentActionReadyV23SQL || database.statements[1] != postgresSecurityAgentActionReadySQL {
		t.Fatalf("statements=%#v", database.statements)
	}
}
