package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"testing"
)

func TestOrderedLifecycleClosedRequests(t *testing.T) {
	start := workerPlanningStartFixture()
	for _, kind := range []string{"inspect", "stop", "message"} {
		t.Run(kind, func(t *testing.T) {
			fields := temporalStartFields(start)
			statement := "SELECT zasp_temporal69." + kind + "($1::jsonb)"
			if kind == "stop" {
				fields["reason"] = "workflow_cancelled"
			}
			if kind == "message" {
				delete(fields, "definition_version")
				delete(fields, "input_digest")
				fields["event_id"] = "pid_99200006-0000-4000-8000-000000000006"
				fields["decision_id"] = "pid_99200007-0000-4000-8000-000000000007"
				fields["kind"] = "cancel"
				statement = "SELECT zasp_temporal69.inspect_message($1::jsonb)"
			}
			raw, _ := json.Marshal(fields)
			op, err := orderedLifecycleOperation(statement, raw, start.Ref)
			if err != nil || string(op) != "ordered69."+kind {
				t.Fatal("missing fixed lifecycle route", op, err)
			}
			for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id"} {
				bad := map[string]any{}
				for k, v := range fields {
					bad[k] = v
				}
				bad[field] = "pid_99999999-0000-4000-8000-000000000001"
				changed, _ := json.Marshal(bad)
				if _, err := orderedLifecycleOperation(statement, changed, start.Ref); err == nil {
					t.Fatal("foreign lifecycle scope", field)
				}
			}
			if _, err := orderedLifecycleOperation("SELECT arbitrary($1::jsonb)", raw, start.Ref); err == nil {
				t.Fatal("arbitrary entry accepted")
			}
			if _, err := orderedLifecycleOperation(statement, append([]byte(`{"run_id":"duplicate",`), raw[1:]...), start.Ref); err == nil {
				t.Fatal("duplicate identity accepted")
			}
			mutations := map[string]any{"definition_version": 0, "input_digest": "not-a-digest"}
			if kind == "stop" {
				mutations["reason"] = "arbitrary"
			}
			if kind == "message" {
				mutations = map[string]any{"event_id": "uncommitted", "decision_id": nil, "kind": "start"}
			}
			for field, value := range mutations {
				bad := map[string]any{}
				for k, v := range fields {
					bad[k] = v
				}
				bad[field] = value
				changed, _ := json.Marshal(bad)
				if _, err := orderedLifecycleOperation(statement, changed, start.Ref); err == nil {
					t.Fatal("invalid native identity accepted", field)
				}
			}
			fields["provider_body"] = "forbidden"
			bad, _ := json.Marshal(fields)
			if _, err := orderedLifecycleOperation(statement, bad, start.Ref); err == nil {
				t.Fatal("extended payload accepted")
			}
		})
	}
}

// The actual outbox/engine adapter must not reach the old unfenced message
// database when a named worker profile is configured, even on denial.
func TestOrderedLifecycleNotifyDoesNotUseRawDatabase(t *testing.T) {
	calls := 0
	db := singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{}`), nil
	})
	product := &temporalSecurityAgentProduct{executor: db, workerForward: &authorization.WorkerExecutor{}, workerCompensation: &authorization.WorkerExecutor{}}
	engine := retainedTemporalEngine{product: product}
	start := workerPlanningStartFixture()
	err := engine.Notify(context.Background(), orchestration.Message{Ref: start.Ref, EventID: "pid_99200006-0000-4000-8000-000000000006", DecisionID: "pid_99200007-0000-4000-8000-000000000007", Kind: "cancel"})
	if err == nil || calls != 0 {
		t.Fatal("named lifecycle fell back to raw database", calls, err)
	}
	if _, err := product.inspect(context.Background(), start, db); err == nil || calls != 0 {
		t.Fatal("named inspection raw fallback", calls, err)
	}
	stop := temporalStartFields(start)
	stop["reason"] = "workflow_failed"
	if _, err := product.lifecycleQuery(context.Background(), db, `SELECT zasp_temporal69.stop($1::jsonb)`, start.Ref, stop); err == nil || calls != 0 {
		t.Fatal("named stop raw fallback", calls, err)
	}
}
