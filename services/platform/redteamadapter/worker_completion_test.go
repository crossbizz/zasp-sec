package redteamadapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkerHeldCompletionExactReceipt(t *testing.T) {
	r := journalRequestFixture(t)
	r.LeaseToken = ""
	// Independently computed SHA256 of the retained v1 effect identity tuple.
	r.EffectKey = "5f54181176138a00efc787d94a0b807f276eb07c0000d3c40bd9d20a61219ef0"
	protected := false
	o := InvocationObservation{HTTPStatus: 200, ResponseDigest: strings.Repeat("c", 64), Protected: &protected, CredentialVersionDigest: strings.Repeat("d", 64)}
	base := map[string]any{"organization_id": testOrganizationID, "workspace_id": testWorkspaceID, "environment_id": testEnvironmentID, "parent_run_id": "pid_7d000006-0000-4000-8000-000000000006", "test_run_id": testRunID, "step_id": "pid_7d000007-0000-4000-8000-000000000007", "effect_key": r.EffectKey, "category": "prompt_injection", "attempt": 1, "state": "completed", "request_digest": r.RequestDigest, "response_digest": o.ResponseDigest, "http_status": 200, "protected": false, "credential_version_digest": o.CredentialVersionDigest, "completed_at": "2026-09-25T12:00:00.123456Z"}
	raw, _ := json.Marshal(base)
	if err := validateWorkerCompletion(raw, r, o); err != nil {
		t.Fatal("exact held observation receipt refused", err)
	}
	for name, value := range map[string]any{"organization_id": testTargetID, "workspace_id": testTargetID, "environment_id": testTargetID, "parent_run_id": testTargetID, "test_run_id": testTargetID, "step_id": testTargetID, "effect_key": strings.Repeat("a", 64), "category": "data_exfiltration", "attempt": 2, "state": "started", "request_digest": strings.Repeat("e", 64), "response_digest": strings.Repeat("e", 64), "http_status": 201, "protected": true, "credential_version_digest": strings.Repeat("e", 64), "completed_at": "2026-09-25T12:00:00.123456-07:00"} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			_ = json.Unmarshal(raw, &fields)
			fields[name] = value
			bad, _ := json.Marshal(fields)
			if validateWorkerCompletion(bad, r, o) == nil {
				t.Fatal("mismatched completion accepted")
			}
		})
	}
	for name := range base {
		t.Run("missing-or-null-"+name, func(t *testing.T) {
			var fields map[string]any
			_ = json.Unmarshal(raw, &fields)
			delete(fields, name)
			bad, _ := json.Marshal(fields)
			if validateWorkerCompletion(bad, r, o) == nil {
				t.Fatal("missing receipt field accepted")
			}
			fields[name] = nil
			bad, _ = json.Marshal(fields)
			if validateWorkerCompletion(bad, r, o) == nil {
				t.Fatal("null receipt field accepted")
			}
		})
	}
	for _, bad := range []string{"null", string(raw) + "{}", strings.Replace(string(raw), `"attempt":1`, `"attempt":1,"attempt":1`, 1), strings.Replace(string(raw), `"attempt":1`, `"Attempt":1`, 1), strings.Replace(string(raw), `"attempt":1`, `"attempt":1,"target_binding":{}`, 1), strings.Repeat(" ", 8193) + string(raw)} {
		if validateWorkerCompletion([]byte(bad), r, o) == nil {
			t.Fatal("malformed completion accepted")
		}
	}
}
