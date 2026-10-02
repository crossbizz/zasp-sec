package gatewaycontrol

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
	"time"
)

func TestEvaluationRiskContract(t *testing.T) {
	base := DecisionEvent{CredentialID: fixtureID(1), DeviceID: fixtureID(2), EventID: fixtureID(3), NextFloor: 1, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", PolicyIDs: []string{"policy-a", "policy-b"}, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "requested", "session_id": fixtureID(5)}, OccurredAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	for _, tc := range []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{"known", func(map[string]any) {}, true},
		{"unknown", func(v map[string]any) { delete(v, "risk") }, true},
		{"bad risk", func(v map[string]any) { v["risk"] = "severe" }, false},
		{"empty risk", func(v map[string]any) { v["risk"] = "" }, false},
		{"null risk", func(v map[string]any) { v["risk"] = nil }, false},
		{"wrong version", func(v map[string]any) { v["version"] = 2 }, false},
		{"extra field", func(v map[string]any) { v["outcome"] = "block" }, false},
		{"case alias", func(v map[string]any) { v["Action"] = v["action"]; delete(v, "action") }, false},
		{"foreign contributor", func(v map[string]any) { v["contributing_policy_ids"] = []string{"policy-c"} }, false},
		{"unsorted contributors", func(v map[string]any) { v["contributing_policy_ids"] = []string{"policy-b", "policy-a"} }, false},
		{"unattributed risk", func(v map[string]any) { v["contributing_policy_ids"] = []string{} }, false},
		{"wrong session", func(v map[string]any) { v["session_id"] = fixtureID(6) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evaluation := map[string]any{"version": 1, "action": "tool_execute", "agent_id": fixtureID(4), "session_id": fixtureID(5), "contributing_policy_ids": []string{"policy-b"}, "risk": "high"}
			tc.edit(evaluation)
			raw, _ := json.Marshal(base)
			var object map[string]any
			json.Unmarshal(raw, &object)
			object["evaluation"] = evaluation
			raw, _ = json.Marshal(object)
			var got DecisionEvent
			err := strictJSON(raw, &got)
			valid := err == nil && validDecisionEvent(got)
			if valid != tc.valid {
				t.Fatalf("valid=%v want=%v err=%v", valid, tc.valid, err)
			}
			if valid {
				encoded, _ := json.Marshal(got)
				var preserved map[string]any
				json.Unmarshal(encoded, &preserved)
				if preserved["evaluation"] == nil {
					t.Fatal("evaluation dropped")
				}
			}
		})
	}
}

func TestEvaluationRiskRecordNoDowngrade(t *testing.T) {
	event := DecisionEvent{CredentialID: fixtureID(1), DeviceID: fixtureID(2), EventID: fixtureID(3), NextFloor: 1, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", PolicyIDs: []string{"policy-a"}, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "requested", "session_id": fixtureID(5)}, OccurredAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), Evaluation: &EvaluationEvidence{Version: 1, Action: "tool_execute", AgentID: fixtureID(4), SessionID: fixtureID(5), ContributingPolicyIDs: []string{"policy-a"}, Risk: "high"}}
	receipt := json.RawMessage(`{"event_id":"` + event.EventID + `","device_id":"` + event.DeviceID + `","sequence":1,"recorded_at":"2026-08-20T12:00:00Z","replayed":false}`)
	t.Run("annotated statement retains evaluation", func(t *testing.T) {
		db := &postgresDatabaseStub{responses: []any{receipt}}
		repo, _ := NewPostgresRepository(db, time.Second)
		if err := repo.Record(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		if len(db.calls) != 1 || !strings.Contains(db.calls[0].statement, "zasp_temporal77.record_gateway_event") || len(db.calls[0].arguments) != 12 {
			t.Fatalf("annotated record used legacy boundary: %#v", db.calls)
		}
		want, _ := json.Marshal(event.Evaluation)
		if string(db.calls[0].arguments[11].(json.RawMessage)) != string(want) {
			t.Fatal("evaluation omitted")
		}
	})
	t.Run("missing77 cannot fall back", func(t *testing.T) {
		db := &postgresDatabaseStub{responses: []any{&pgconn.PgError{Code: "42883"}, receipt}}
		repo, _ := NewPostgresRepository(db, time.Second)
		if repo.Record(context.Background(), event) == nil || len(db.calls) != 1 {
			t.Fatalf("annotated record downgraded: calls=%d", len(db.calls))
		}
	})
}
