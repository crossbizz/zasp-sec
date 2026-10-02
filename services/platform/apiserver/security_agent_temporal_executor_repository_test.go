package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestTemporalExecutorSourceSignatureBoundary(t *testing.T) {
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	const r = "pid_78000001-0000-4000-8000-000000000001"
	const s = "pid_2e9322f4-505e-4d5b-8057-a15ead7db914"
	claim := map[string]any{"targets": []any{map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": float64(1), "policy_version": float64(1)}}, "ttl_seconds": float64(600)}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	for _, mode := range []string{"exact", "signature", "key", "digest", "scope", "lease", "generation", "wrong_receipt", "cleanup_exact", "cleanup_signature", "cleanup_key", "cleanup_digest", "cleanup_renew_exact", "cleanup_renew_signature", "cleanup_renew_key", "cleanup_renew_digest", "cleanup_renew_scope", "cleanup_renew_source_digest", "cleanup_renew_wrong_receipt"} {
		t.Run(mode, func(t *testing.T) {
			cleanup := strings.HasPrefix(mode, "cleanup_")
			mode = strings.TrimPrefix(mode, "cleanup_")
			renew := strings.HasPrefix(mode, "renew_")
			mode = strings.TrimPrefix(mode, "renew_")
			source := orderedApplicationStoreRequest(t, o, w, e, r, s, claim, key)["envelope"].(map[string]any)
			if cleanup {
				now := time.Now().UTC().Truncate(time.Second)
				v := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: orderedApplicationDevice, CredentialID: orderedApplicationDevice, Sequence: 1, PolicyVersion: 1}, "ordered-key-01", key, now, now.Add(5*time.Minute), []policy.CompiledPolicy{})
				source = map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": 1, "policy_version": 1, "key_id": v.KeyID, "issued_at": v.IssuedAt, "expires_at": v.ExpiresAt, "failure_mode": v.FailureMode, "payload_digest": v.PayloadDigest, "policies": v.Policies, "signature": base64.StdEncoding.EncodeToString(v.Signature), "envelope_digest": v.EnvelopeDigest}
			}
			q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "generation": 1, "operation": "source", "payload": source}
			if renew {
				q["operation"] = "renew"
				q["payload"] = map[string]any{"source_digest": "sha256:" + strings.Repeat("a", 64), "envelope": source}
			}
			response := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "generation": 1, "effect_key": "47bc1250488627baef2b38585c418150d1ed425ee21a47c3b688847fa68dfd3f", "ttl_seconds": 600, "targets": []any{map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": 1, "policy_version": 1, "state": "stored", "desired_generation": 2, "envelope_digest": source["envelope_digest"]}}}
			if cleanup {
				response["ttl_seconds"] = 300
			}
			switch mode {
			case "source_digest":
				q["payload"].(map[string]any)["source_digest"] = "not-a-digest"
			case "signature":
				source["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "key":
				source["key_id"] = "unknown-key-01"
			case "digest":
				source["envelope_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			case "scope":
				source["device_id"] = r
			case "lease":
				q["lease_token"] = "invented-lease"
			case "generation":
				q["generation"] = 2
			case "wrong_receipt":
				response["effect_key"] = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			raw, _ := json.Marshal(q)
			output, _ := json.Marshal(response)
			query := `SELECT zasp_temporal68.application($1::jsonb)`
			if cleanup {
				query = `SELECT zasp_temporal68.cleanup($1::jsonb)`
			}
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{query: output}}
			executor, ok := any(&securityAgentMultistepAdmissionRepository{database: db}).(interface {
				TemporalApplication(context.Context, json.RawMessage, policy.GatewayPolicyKeys) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("lease-free signing repository missing")
			}
			invoke := executor.TemporalApplication
			if cleanup {
				invoke = (&securityAgentMultistepAdmissionRepository{database: db}).TemporalCleanupSource
			}
			_, err := invoke(context.Background(), raw, keys)
			if mode == "exact" {
				if err != nil || len(db.statements) != 1 {
					t.Fatal("verified source refused", err)
				}
			} else if err == nil || mode != "wrong_receipt" && len(db.statements) != 0 {
				t.Fatal("unverified source or receipt accepted", mode, err, len(db.statements))
			}
		})
	}
}

func TestTemporalDeliveryWireNullability(t *testing.T) {
	const wire = `{"organization_id":"o","workspace_id":"w","environment_id":"e","run_id":"r","step_id":"s","generation":1,"effect_key":"k","phase":"apply","device_id":"d","credential_id":"c","source_sequence":1,"source_digest":"h","desired_generation":1,"sequence":1,"composition":{},"state":"prepared","envelope":null,"envelope_digest":null,"read_at":null,"acknowledged_at":null}`
	if !temporalDeliveryResponseObject(json.RawMessage(wire)) {
		t.Fatal("not-yet-created evidence rejected")
	}
	for _, field := range []string{"organization_id", "run_id", "effect_key", "source_digest", "composition"} {
		t.Run(field, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal([]byte(wire), &value); err != nil {
				t.Fatal(err)
			}
			value[field] = nil
			raw, _ := json.Marshal(value)
			if temporalDeliveryResponseObject(raw) {
				t.Fatal("null authority accepted", field)
			}
		})
	}
	for _, bad := range []string{strings.Replace(wire, `"state":"prepared"`, `"state":"stored","state":"prepared"`, 1), strings.Replace(wire, `"state":"prepared"`, `"unknown":0,"state":"prepared"`, 1), wire + `{}`} {
		if temporalDeliveryResponseObject(json.RawMessage(bad)) {
			t.Fatal("ambiguous receipt accepted")
		}
	}
}

func TestTemporalExecutorDeliverySignatureBoundary(t *testing.T) {
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	const r = "pid_78000001-0000-4000-8000-000000000001"
	const s = "pid_2e9322f4-505e-4d5b-8057-a15ead7db914"
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	source := orderedApplicationStoreRequest(t, o, w, e, r, s, map[string]any{"targets": []any{map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": float64(1), "policy_version": float64(1)}}, "ttl_seconds": float64(600)}, key)["envelope"].(map[string]any)
	now := time.Now().UTC().Truncate(time.Second)
	policyJSON, _ := json.Marshal(source["policies"])
	var compiled []policy.CompiledPolicy
	if err := json.Unmarshal(policyJSON, &compiled); err != nil {
		t.Fatal(err)
	}
	signed, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: 1, PolicyVersion: 1, Now: now, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), FailureMode: "closed", Policies: compiled}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"exact", "signature", "digest", "wrong_scope", "no_key", "lease"} {
		t.Run(mode, func(t *testing.T) {
			envelope := signed
			activeKeys := keys
			digest := orderedEnvelopeDigest(envelope)
			switch mode {
			case "signature":
				envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			case "digest":
				digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			case "wrong_scope":
				envelope.WorkspaceID = o
			case "no_key":
				activeKeys = policy.GatewayPolicyKeys{}
			}
			q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "generation": 1, "operation": "store", "payload": map[string]any{"device_id": orderedApplicationDevice, "phase": "apply", "envelope": envelope, "digest": digest}}
			if mode == "lease" {
				q["lease_token"] = "not-authority"
			}
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_temporal68.delivery($1::jsonb)`: json.RawMessage(`{}`)}}
			repo, ok := any(&securityAgentMultistepAdmissionRepository{database: db}).(interface {
				TemporalDelivery(context.Context, json.RawMessage, policy.GatewayPolicyKeys) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("lease-free delivery verifier missing")
			}
			raw, _ := json.Marshal(q)
			_, err := repo.TemporalDelivery(context.Background(), raw, activeKeys)
			if err == nil {
				t.Fatal("empty delivery receipt accepted")
			}
			if mode == "exact" && len(db.statements) != 1 || mode != "exact" && len(db.statements) != 0 {
				t.Fatal("signature boundary IO", mode, len(db.statements), err)
			}
		})
	}
}
