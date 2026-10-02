package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestOrderedLifecycleRetirementBindingCompatibility(t *testing.T) {
	start := workerPlanningStartFixture()
	for _, route := range []struct{ name, statement string }{
		{"inspect", "SELECT zasp_temporal69.inspect($1::jsonb)"},
		{"message", "SELECT zasp_temporal69.inspect_message($1::jsonb)"},
		{"stop", "SELECT zasp_temporal69.stop($1::jsonb)"},
	} {
		fields := temporalStartFields(start)
		if route.name == "stop" {
			fields["reason"] = "workflow_failed"
		}
		if route.name == "message" {
			delete(fields, "definition_version")
			delete(fields, "input_digest")
			fields["event_id"] = "pid_99200006-0000-4000-8000-000000000006"
			fields["decision_id"] = "pid_99200007-0000-4000-8000-000000000007"
			fields["kind"] = "cancel"
		}
		expected, _ := json.Marshal(fields)
		t.Run(route.name, func(t *testing.T) {
			for _, fail := range []bool{false, true} {
				calls := 0
				sentinel := errors.New("retained database refusal")
				want := json.RawMessage(`{"retained":true}`)
				type key struct{}
				ctx := context.WithValue(context.Background(), key{}, "preserved")
				db := singleDeliveryDatabaseFunc(func(got context.Context, sql string, args ...any) (json.RawMessage, error) {
					calls++
					deadline, bounded := got.Deadline()
					if got.Value(key{}) != "preserved" || got.Err() != nil || !bounded || time.Until(deadline) > 10*time.Second || sql != route.statement || len(args) != 1 {
						t.Fatal("retained call context/route changed")
					}
					raw, ok := args[0].(json.RawMessage)
					if !ok || !bytes.Equal(raw, expected) {
						t.Fatal("retained request changed")
					}
					if fail {
						return nil, sentinel
					}
					return want, nil
				})
				product := &temporalSecurityAgentProduct{}
				got, err := product.lifecycleQuery(ctx, db, route.statement, start.Ref, fields)
				if calls != 1 || fail && (!errors.Is(err, sentinel) || len(got) != 0) || !fail && (err != nil || !bytes.Equal(got, want)) {
					t.Fatal("both-nil retained route/result/error changed", calls, err)
				}
			}
			for _, partial := range []*temporalSecurityAgentProduct{
				{workerForward: &authorization.WorkerExecutor{}},
				{workerCompensation: &authorization.WorkerExecutor{}},
			} {
				calls := 0
				db := singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
					calls++
					return json.RawMessage(`{}`), nil
				})
				got, err := partial.lifecycleQuery(context.Background(), db, route.statement, start.Ref, fields)
				if err == nil || len(got) != 0 || calls != 0 {
					t.Fatal("partial named binding used raw fallback", calls, err)
				}
			}
		})
	}
}
