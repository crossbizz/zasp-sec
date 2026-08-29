package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestPolicyDeploymentRepositoryDecodesExactClaimAndFencesReceipt(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	claimPayload := json.RawMessage(`{"items":[{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","device_id":"pid_70000004-0000-4000-8000-000000000004","credential_id":"pid_70000005-0000-4000-8000-000000000005","desired_generation":4,"sequence":7,"policy_version":7,"input_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lease_expires_at":"2026-08-28T12:01:00Z","persistent_policies":[{"id":"policy-runtime","name":"Runtime","scope":"environment","trigger":"runtime","conditions":[{"field":"resource","operator":"equals","value":"repository"}],"action":"block","rollout":"enforced","failure_mode":"closed"}],"temporary_policies":[],"temporary_expires_at":null}]}`)
	database := &discoveryCallDatabase{responses: map[string]json.RawMessage{
		postgresPolicyDeploymentReadySQL:     json.RawMessage(`{"release":true,"principal":true}`),
		postgresPolicyDeploymentClaimSQL:     claimPayload,
		postgresPolicyDeploymentHeartbeatSQL: json.RawMessage(`{"lease_expires_at":"2026-08-28T12:01:30Z"}`),
		postgresPolicyDeploymentStoreSQL:     nil,
		postgresPolicyDeploymentReadSQL:      policyDeploymentEnvelopeFixture(t, now),
		postgresPolicyDeploymentFinishSQL:    nil,
	}}
	repository, err := NewPolicyDeploymentRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := repository.ClaimPolicyDeployments(context.Background(), "policy-deployment-01", "lease-token-000000000001", 60, 8)
	if err != nil || len(claims) != 1 || claims[0].DesiredGeneration != 4 || claims[0].Sequence != 7 || len(claims[0].PersistentPolicies) != 1 || claims[0].LeaseExpiresAt != now.Add(time.Minute) {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	claim := claims[0]
	if err := repository.HeartbeatPolicyDeployment(context.Background(), claim, "policy-deployment-01", "lease-token-000000000001", 60); err != nil {
		t.Fatal(err)
	}
	envelope := mustPolicyDeploymentEnvelopeFixture(t, now)
	envelopeRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelopeHash := sha256.Sum256(envelopeRaw)
	wantDigest := "sha256:" + hex.EncodeToString(envelopeHash[:])
	database.responses[postgresPolicyDeploymentStoreSQL] = json.RawMessage(`{"envelope_digest":"` + wantDigest + `"}`)
	database.responses[postgresPolicyDeploymentFinishSQL] = json.RawMessage(`{"desired_generation":4,"applied_generation":4,"state":"scheduled","envelope_digest":"` + wantDigest + `"}`)
	digest, err := repository.StorePolicyDeployment(context.Background(), claim, "policy-deployment-01", "lease-token-000000000001", envelope)
	if err != nil || digest != wantDigest {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	readback, err := repository.ReadPolicyDeployment(context.Background(), claim)
	if err != nil || !reflect.DeepEqual(readback, envelope) {
		t.Fatalf("readback=%+v err=%v", readback, err)
	}
	if err := repository.FinishPolicyDeployment(context.Background(), claim, "policy-deployment-01", "lease-token-000000000001", digest); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyDeploymentRepositoryRejectsForeignAndMalformedClaims(t *testing.T) {
	valid := `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","device_id":"pid_70000004-0000-4000-8000-000000000004","credential_id":"pid_70000005-0000-4000-8000-000000000005","desired_generation":4,"sequence":7,"policy_version":7,"input_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","lease_expires_at":"2026-08-28T12:01:00Z","persistent_policies":[],"temporary_policies":[],"temporary_expires_at":null`
	for name, payload := range map[string]string{
		"unknown field":  `{"items":[` + valid + `,"secret":"leak"}]}`,
		"sequence drift": `{"items":[` + valid + `,"policy_version":8}]}`,
		"non utc":        `{"items":[` + valid + `,"lease_expires_at":"2026-08-28T05:01:00-07:00"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			database := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresPolicyDeploymentReadySQL: json.RawMessage(`{"release":true,"principal":true}`), postgresPolicyDeploymentClaimSQL: json.RawMessage(payload)}}
			repository, err := NewPolicyDeploymentRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repository.ClaimPolicyDeployments(context.Background(), "policy-deployment-01", "lease-token-000000000001", 60, 8); err == nil {
				t.Fatal("malformed claim accepted")
			}
		})
	}
}

func mustPolicyDeploymentEnvelopeFixture(t *testing.T, now time.Time) policy.GatewayPolicyEnvelope {
	t.Helper()
	var value policy.GatewayPolicyEnvelope
	if err := json.Unmarshal(policyDeploymentEnvelopeFixture(t, now), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func policyDeploymentEnvelopeFixture(t *testing.T, now time.Time) json.RawMessage {
	t.Helper()
	value := map[string]any{
		"contract_version": 1, "key_id": "gateway-key-01", "algorithm": "Ed25519", "audience": "runtime-gateway-policy",
		"organization_id": "pid_70000001-0000-4000-8000-000000000001", "workspace_id": "pid_70000002-0000-4000-8000-000000000002", "environment_id": "pid_70000003-0000-4000-8000-000000000003", "device_id": "pid_70000004-0000-4000-8000-000000000004",
		"sequence": 7, "policy_version": 7, "issued_at": now, "expires_at": now.Add(24 * time.Hour), "failure_mode": "closed",
		"payload_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policies": []any{}, "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
