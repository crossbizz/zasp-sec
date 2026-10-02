package apiserver

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Rejecting a valid exact Attack Lab action or accepting an ambiguous reference
// breaks the public definition boundary before SQL ever sees the request.
func TestSecurityAgentAttackLabReferenceContract(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	const id = "pid_8a000001-0000-4000-8000-000000000001"
	const ref = `"existing_test":{"definition_id":"pid_8a000002-0000-4000-8000-000000000002","definition_version":1}`
	for _, tc := range []struct {
		name, action, verification, reference string
		valid                                 bool
	}{
		{"attack_lab", `["start_attack_lab"]`, "attack_lab_run", ref, true},
		{"run_test", `["run_test"]`, "test_run", ref, true},
		{"rerun_test", `["rerun_test"]`, "test_run", ref, true},
		{"wrong_verification", `["start_attack_lab"]`, "test_run", ref, false},
		{"mixed", `["run_test","start_attack_lab"]`, "attack_lab_run", ref, false},
		{"missing_reference", `["start_attack_lab"]`, "attack_lab_run", `"existing_test":null`, false},
		{"duplicate", `["start_attack_lab"]`, "attack_lab_run", strings.Replace(ref, `"definition_version":1`, `"definition_version":2,"definition_version":1`, 1), false},
		{"alias", `["start_attack_lab"]`, "attack_lab_run", strings.Replace(ref, `"definition_version":1`, `"Definition_Version":1`, 1), false},
		{"source_override", `["start_attack_lab"]`, "attack_lab_run", strings.Replace(ref, `"definition_version":1`, `"definition_version":1,"source_run_id":"pid_8a000003-0000-4000-8000-000000000003"`, 1), false},
		{"url_override", `["start_attack_lab"]`, "attack_lab_run", strings.Replace(ref, `"definition_version":1`, `"definition_version":1,"url":"https://untrusted.invalid"`, 1), false},
		{"prompt_override", `["start_attack_lab"]`, "attack_lab_run", strings.Replace(ref, `"definition_version":1`, `"definition_version":1,"prompt":"caller instructions"`, 1), false},
		{"target_override", `["start_attack_lab"]`, "attack_lab_run", strings.Replace(ref, `"definition_version":1`, `"definition_version":1,"target_class":"test"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"name":"Exact Attack Lab draft","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + identity.Scope.EnvironmentID().String() + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":` + tc.action + `,"verification_kind":"` + tc.verification + `","definition_version":1,"enabled":false,` + tc.reference + `}`
			got, _, err := securityAgentBody(httptest.NewRequest("POST", "/", strings.NewReader(body)), identity.Scope, id, true, false, false, true, true)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v body=%s error=%v", tc.valid, got, err)
			}
			if tc.name == "attack_lab" {
				for _, capability := range [][]bool{nil, {false}, {true, true}} {
					if _, _, err := securityAgentBody(httptest.NewRequest("POST", "/", strings.NewReader(body)), identity.Scope, id, true, false, false, true, capability...); err == nil {
						t.Fatalf("ambiguous/unavailable Attack Lab capability accepted: %v", capability)
					}
				}
			}
		})
	}
}
