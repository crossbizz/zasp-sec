package redteamadapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkerCompletedReceiptClosedDecode(t *testing.T) {
	q := CompletedReceiptRequest{OrganizationID: testOrganizationID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID, ParentRunID: "pid_7d000006-0000-4000-8000-000000000006", TestRunID: testRunID, StepID: "pid_7d000007-0000-4000-8000-000000000007", EffectKey: "5f54181176138a00efc787d94a0b807f276eb07c0000d3c40bd9d20a61219ef0", Generation: 1, Category: "prompt_injection", InputDigest: strings.Repeat("a", 64), RequestDigest: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(q)
	if got, err := decodeCompletedRequest(raw); err != nil || got != q {
		t.Fatal("exact captured request")
	}
	protected := false
	r := CompletedReceipt{CompletedReceiptRequest: q, Attempt: 1, State: "completed", ResponseDigest: strings.Repeat("c", 64), HTTPStatus: 200, Protected: &protected, CredentialVersionDigest: strings.Repeat("d", 64), CompletedAt: "2026-09-25T12:00:00.123456Z", CapturedResolutionDigest: strings.Repeat("e", 64)}
	receipt, _ := json.Marshal(r)
	if got, err := decodeCompletedReceipt(receipt, q); err != nil || got.Protected == nil || *got.Protected {
		t.Fatal("completed unsafe observation must remain false")
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		fields string
		decode func([]byte) error
	}{{"request", raw, completedRequestFields, func(b []byte) error { _, e := decodeCompletedRequest(b); return e }}, {"receipt", receipt, completedReceiptFields, func(b []byte) error { _, e := decodeCompletedReceipt(b, q); return e }}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range strings.Fields(tc.fields) {
				for _, mode := range []string{"missing", "null", "wrong-type"} {
					var m map[string]any
					_ = json.Unmarshal(tc.raw, &m)
					switch mode {
					case "missing":
						delete(m, field)
					case "null":
						m[field] = nil
					default:
						m[field] = []string{"invalid"}
					}
					bad, _ := json.Marshal(m)
					if tc.decode(bad) == nil {
						t.Fatalf("accepted %s %s", field, mode)
					}
				}
			}
			for _, bad := range []string{"null", string(tc.raw) + "{}", strings.Replace(string(tc.raw), `"generation":1`, `"generation":1,"generation":1`, 1), strings.Replace(string(tc.raw), `"generation":1`, `"generation":1,"target_binding":{}`, 1), strings.Repeat(" ", 8193) + string(tc.raw)} {
				if tc.decode([]byte(bad)) == nil {
					t.Fatal("accepted malformed object")
				}
			}
		})
	}
	for key, value := range map[string]any{"parent_run_id": testTargetID, "step_id": testTargetID, "input_digest": strings.Repeat("f", 64), "generation": 2, "state": "started", "attempt": 2, "http_status": 503, "credential_version_digest": strings.Repeat("0", 64), "completed_at": "2026-09-25T12:00:00.123456-07:00", "captured_resolution_digest": "bad"} {
		var m map[string]any
		_ = json.Unmarshal(receipt, &m)
		m[key] = value
		bad, _ := json.Marshal(m)
		if _, err := decodeCompletedReceipt(bad, q); err == nil {
			t.Fatalf("accepted changed %s", key)
		}
	}
}
