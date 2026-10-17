package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These are untrusted native-response fixtures. The test proves decoding and
// reservation boundaries only; it does not authenticate SQL receipts or HMACs.
func TestConnectorMaintenanceRecoveryDecodeBoundaries(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	digest := strings.Repeat("a", 64)
	lease := ConnectorEffectLease{
		OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(),
		ID: "pid_70000003-0000-4000-8000-000000000003", IntegrationID: "pid_70000001-0000-4000-8000-000000000001",
		OAuthAttemptID: "pid_70000002-0000-4000-8000-000000000002", PrincipalID: identity.PrincipalID.String(), RequestedScopes: []string{"read:org"},
		Provider: "github", Operation: "pkce_cleanup", IdempotencyKey: "pkce-cleanup:pid_70000003-0000-4000-8000-000000000003", RequestDigest: digest,
		ConnectionReference: "ref:oauth/pkce/70000012-0000-4000-8000-000000000012", Attempt: 1,
		LeaseOwner: "connector-worker-a", LeaseToken: strings.Repeat("b", 64), LeaseExpiresAt: time.Now().UTC().Add(45 * time.Second).Truncate(time.Microsecond),
	}
	marshal := func(value any) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	fixture := func(attempt int) (map[string]any, map[string]any, map[string]any) {
		current := lease
		current.Attempt = attempt
		var item map[string]any
		if err := json.Unmarshal(marshal(current), &item); err != nil {
			t.Fatal(err)
		}
		item["intent_digest"] = digest
		reference := map[string]any{"organization_id": current.OrganizationID, "workspace_id": current.WorkspaceID, "environment_id": current.EnvironmentID, "effect_id": current.ID, "integration_id": current.IntegrationID, "lease_owner": current.LeaseOwner, "lease_token": current.LeaseToken, "intent_digest": digest}
		body := map[string]any{"purpose": "connector-captured", "key_version": digest, "reference": reference, "attempt": attempt, "kind": "pkce_recovery", "forward_digest": digest, "lease_expires_at": current.LeaseExpiresAt, "session_user": "captured-session-user", "origin_digest": digest}
		envelope := map[string]any{"version": digest, "mac": strings.Repeat("c", 64)}
		return item, body, envelope
	}
	encode := func(item, body, envelope map[string]any) json.RawMessage {
		envelope["body"] = base64.StdEncoding.EncodeToString(marshal(body))
		item["captured_proof"] = envelope
		return marshal(map[string]any{"items": []any{item}})
	}
	for _, attempt := range []int{1, 99} {
		t.Run("accept_exact_recovery_attempt_"+strconv.Itoa(attempt), func(t *testing.T) {
			item, body, envelope := fixture(attempt)
			raw := encode(item, body, envelope)
			leases, pending, err := decodeNativeConnectorClaims(raw, lease.LeaseOwner, 60, 1, true)
			if err != nil || len(leases) != 1 || len(pending) != 1 {
				t.Fatalf("exact recovery response rejected: %v", err)
			}
			state := pending[nativeConnectorKey(leases[0])]
			if state == nil || !state.recovery || state.lease.Attempt != attempt || state.reference.IntentDigest != digest || string(state.captured) != string(marshal(envelope)) {
				t.Fatal("recovery reservation lost its exact lease, intent or captured proof")
			}
		})
	}
	type mutation struct {
		name  string
		apply func(map[string]any, map[string]any, map[string]any)
	}
	cases := []mutation{
		{"provider_receipt", func(_, b, _ map[string]any) { b["kind"] = "provider" }},
		{"forward_operation", func(i, _, _ map[string]any) { i["operation"] = "revoke" }},
		{"zero_attempt", func(i, b, _ map[string]any) { i["attempt"] = 0; b["attempt"] = 0 }},
		{"final_attempt", func(i, b, _ map[string]any) { i["attempt"] = 100; b["attempt"] = 100 }},
		{"wrong_owner", func(i, _, _ map[string]any) { i["lease_owner"] = "another-worker" }},
		{"expired_lease", func(i, _, _ map[string]any) { i["lease_expires_at"] = time.Now().Add(-time.Minute) }},
		{"unbounded_lease", func(i, _, _ map[string]any) { i["lease_expires_at"] = time.Now().Add(time.Hour) }},
		{"different_proof_expiry", func(_, b, _ map[string]any) { b["lease_expires_at"] = lease.LeaseExpiresAt.Add(time.Microsecond) }},
		{"different_proof_attempt", func(_, b, _ map[string]any) { b["attempt"] = 2 }},
		{"different_purpose", func(_, b, _ map[string]any) { b["purpose"] = "connector-forward" }},
		{"different_key_version", func(_, b, _ map[string]any) { b["key_version"] = strings.Repeat("d", 64) }},
		{"extra_item_field", func(i, _, _ map[string]any) { i["grant_new_authority"] = true }},
		{"extra_body_field", func(_, b, _ map[string]any) { b["grant_new_authority"] = true }},
		{"extra_envelope_field", func(_, _, e map[string]any) { e["grant_new_authority"] = true }},
		{"malformed_intent", func(i, _, _ map[string]any) { i["intent_digest"] = "not-a-digest" }},
		{"uppercase_intent", func(i, _, _ map[string]any) { i["intent_digest"] = strings.ToUpper(digest) }},
		{"missing_mac", func(_, _, e map[string]any) { delete(e, "mac") }},
		{"malformed_mac", func(_, _, e map[string]any) { e["mac"] = "wrong" }},
		{"malformed_key_version", func(_, _, e map[string]any) { e["version"] = "wrong" }},
		{"malformed_forward_lineage", func(_, b, _ map[string]any) { b["forward_digest"] = "wrong" }},
		{"malformed_origin_lineage", func(_, b, _ map[string]any) { b["origin_digest"] = "wrong" }},
		{"missing_session", func(_, b, _ map[string]any) { delete(b, "session_user") }},
		{"oversized_session", func(_, b, _ map[string]any) { b["session_user"] = strings.Repeat("s", 64) }},
		{"oversized_proof", func(_, b, _ map[string]any) { b["session_user"] = strings.Repeat("s", 65537) }},
	}
	for _, field := range []string{"organization_id", "workspace_id", "environment_id", "effect_id", "integration_id", "lease_owner", "lease_token", "intent_digest"} {
		field := field
		cases = append(cases, mutation{"different_reference_" + field, func(_, b, _ map[string]any) { b["reference"].(map[string]any)[field] = "different" }})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item, body, envelope := fixture(1)
			tc.apply(item, body, envelope)
			if leases, pending, err := decodeNativeConnectorClaims(encode(item, body, envelope), lease.LeaseOwner, 60, 1, true); err == nil || leases != nil || pending != nil {
				t.Fatal("malformed recovery response entered reservations")
			}
		})
	}
	t.Run("reject_malformed_or_duplicate_pages", func(t *testing.T) {
		item, body, envelope := fixture(1)
		valid := encode(item, body, envelope)
		for _, raw := range []json.RawMessage{
			marshal(map[string]any{"items": []any{item, item}}),
			marshal(map[string]any{"items": []any{item}, "unexpected": true}),
			marshal(map[string]any{"items": nil}),
			json.RawMessage(`{"items":[`),
		} {
			if _, _, err := decodeNativeConnectorClaims(raw, lease.LeaseOwner, 60, 2, true); err == nil {
				t.Fatal("invalid page accepted")
			}
		}
		if _, _, err := decodeNativeConnectorClaims(valid, lease.LeaseOwner, 60, 0, true); err == nil {
			t.Fatal("page limit ignored")
		}
		item["captured_proof"] = map[string]any{"body": "%%%", "version": digest, "mac": digest}
		if _, _, err := decodeNativeConnectorClaims(marshal(map[string]any{"items": []any{item}}), lease.LeaseOwner, 60, 1, true); err == nil {
			t.Fatal("invalid proof encoding accepted")
		}
	})
	t.Run("forward_response_cannot_import_captured_authority", func(t *testing.T) {
		item, body, envelope := fixture(1)
		raw := encode(item, body, envelope)
		if _, _, err := decodeNativeConnectorClaims(raw, lease.LeaseOwner, 60, 1, false); err == nil {
			t.Fatal("forward response imported captured authority")
		}
		delete(item, "captured_proof")
		item["attempt"] = 0
		leases, pending, err := decodeNativeConnectorClaims(marshal(map[string]any{"items": []any{item}}), lease.LeaseOwner, 60, 1, false)
		if err != nil || len(leases) != 1 || len(pending) != 1 {
			t.Fatalf("ordinary reserved forward response rejected: %v", err)
		}
		state := pending[nativeConnectorKey(leases[0])]
		if state == nil || state.recovery || len(state.captured) != 0 {
			t.Fatal("ordinary reservation acquired recovery authority")
		}
	})
}
