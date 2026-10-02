package apiserver

import (
	"context"
	"encoding/json"
	"testing"
)

func TestP7HomeHealthWireAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, statuses            string
		proof, environment, valid bool
	}{
		{"restricted", `"healthy":null,"attention_required":null`, true, false, true},
		{"full healthy", `"healthy":true,"attention_required":false`, true, true, true},
		{"full attention", `"healthy":false,"attention_required":true`, true, true, true},
		{"fabricated healthy", `"healthy":true,"attention_required":false`, true, false, false},
		{"fabricated degraded", `"healthy":false,"attention_required":true`, true, false, false},
		{"null without proof", `"healthy":null,"attention_required":null`, false, false, false},
		{"null with environment proof", `"healthy":null,"attention_required":null`, true, true, false},
		{"mixed", `"healthy":null,"attention_required":true`, true, false, false},
		{"missing", `"healthy":true`, true, true, false},
		{"equal", `"healthy":false,"attention_required":false`, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := json.RawMessage(`{"agent_count":1,"high_risk_paths":0,"verified_changes":0,"blocked_changes":0,"pending_approvals":0,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0,` + tc.statuses + `}`)
			ctx := context.Background()
			if tc.proof {
				ctx = context.WithValue(ctx, requestAuthorizationContextKey{}, RequestAuthorization{OperationID: "getHomeSummary", EnvironmentView: tc.environment})
			}
			statement := authorizationReadStatement(ctx, postgresInventoryHomeSummarySQL, `SELECT zasp_authorization80.home_summary($1,$2,$3)`)
			repository := &PostgresInventoryRepository{database: &inventoryJSONDatabase{responses: map[string]json.RawMessage{statement: payload}}}
			summary, err := repository.GetHomeSummary(ctx, inventoryScope(t))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid {
				body, err := json.Marshal(summary)
				var wire map[string]json.RawMessage
				if err != nil || json.Unmarshal(body, &wire) != nil {
					t.Fatal("invalid home wire")
				}
				var input map[string]json.RawMessage
				_ = json.Unmarshal(payload, &input)
				if string(wire["healthy"]) != string(input["healthy"]) || string(wire["attention_required"]) != string(input["attention_required"]) {
					t.Fatalf("status changed: %s", body)
				}
			}
		})
	}
}
