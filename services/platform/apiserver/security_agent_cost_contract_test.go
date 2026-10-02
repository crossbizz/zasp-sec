package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Losing this field silently would leave the durable run without cost authority.
func TestSecurityAgentBodyPreservesExplicitCostAllowance(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	const id = "pid_90000001-0000-4000-8000-000000000001"
	for _, create := range []bool{true, false} {
		for _, tc := range []struct {
			name, cost string
			valid      bool
		}{
			{"legacy_draft", "", true},
			{"minimum", "1", true},
			{"maximum", "1000000000000", true},
			{"zero", "0", false},
			{"negative", "-1", false},
			{"above_maximum", "1000000000001", false},
			{"overflow", "9223372036854775808", false},
			{"fraction", "0.5", false},
			{"string", `"100"`, false},
			{"null", "null", false},
			{"boolean", "true", false},
			{"object", "{}", false},
			{"array", "[]", false},
			{"exponent", "1e2", false},
		} {
			mode := "create/"
			if !create {
				mode = "update/"
			}
			t.Run(mode+tc.name, func(t *testing.T) {
				body := `{"name":"Bounded response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + identity.Scope.EnvironmentID().String() + `"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["update_finding_response"],"verification_kind":"finding_state","definition_version":1,"enabled":false`
				if !create {
					body += `,"id":"` + id + `"`
				}
				if tc.cost != "" {
					body += `,"max_ai_cost_nano_credits":` + tc.cost
				}
				request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body+"}"))
				result, resultID, err := securityAgentBody(request, identity.Scope, id, create, false, false, false)
				if !tc.valid {
					if err == nil {
						t.Fatalf("invalid cost accepted: %s", result)
					}
					return
				}
				if err != nil || resultID != id {
					t.Fatalf("id=%q err=%v", resultID, err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(result, &fields); err != nil {
					t.Fatal(err)
				}
				if got := string(fields["max_ai_cost_nano_credits"]); got != tc.cost {
					t.Fatalf("cost persisted=%q want=%q", got, tc.cost)
				}
			})
		}
	}
}
