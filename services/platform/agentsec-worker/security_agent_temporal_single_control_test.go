package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"testing"
)

func TestSingleTestControlDurablyCancelsOnlyExistingWorkflow(t *testing.T) {
	for _, mode := range []string{"cancel", "approval", "terminal", "rpc_failure", "commit_failure"} {
		t.Run(mode, func(t *testing.T) {
			q := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}, DefinitionVersion: 3, InputDigest: strings.Repeat("a", 64)}
			const id = "pid_99200005-0000-4000-8000-000000000005"
			kind := "cancel"
			if mode == "approval" {
				kind = "approval"
			}
			steps := []string{}
			recovered := false
			db := singleDeliveryDatabaseFunc(func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == `SELECT zasp_temporal74.pending_controls()` {
					steps = append(steps, "pending")
					return json.Marshal([]any{map[string]any{"start": q, "control_id": id, "kind": kind, "terminal": mode == "terminal"}})
				}
				if sql != `SELECT zasp_temporal74.accept_control($1::jsonb)` || len(args) != 1 {
					t.Fatal(sql)
				}
				steps = append(steps, "accept")
				expected := temporalStartFields(q)
				expected["control_id"] = id
				raw, _ := json.Marshal(args[0])
				want, _ := json.Marshal(expected)
				if !jsonEqualWorker(raw, want) {
					t.Fatal("control identity changed")
				}
				if mode == "commit_failure" && !recovered {
					return nil, errors.New("commit lost")
				}
				workflowID, _ := orchestration.SingleTestWorkflowID(q.Ref)
				return json.Marshal(map[string]any{"control_id": id, "workflow_id": workflowID, "accepted_at": "2026-09-23T10:00:00Z"})
			})
			p := &temporalSecurityAgentProduct{executor: db}
			factory, ok := any(p).(interface {
				singleTestControlRelay(func(context.Context, string, orchestration.StartRequest) error) workerProcessor
			})
			if !ok {
				t.Fatal("specialized durable cancellation relay missing")
			}
			relay := factory.singleTestControlRelay(func(ctx context.Context, actualKind string, actual orchestration.StartRequest) error {
				if actual != q || actualKind != kind {
					t.Fatal("different workflow")
				}
				steps = append(steps, kind)
				if mode == "rpc_failure" && !recovered {
					return errors.New("RPC lost")
				}
				return nil
			})
			err := relay.RunOnce(context.Background())
			want := "[pending cancel accept]"
			if mode == "approval" {
				want = "[pending approval accept]"
			}
			if mode == "terminal" {
				want = "[pending accept]"
			}
			if mode == "rpc_failure" {
				want = "[pending cancel]"
			}
			if (err != nil) != (mode == "rpc_failure" || mode == "commit_failure") || fmt.Sprint(steps) != want {
				t.Fatal(err, steps, want)
			}
			if err != nil {
				recovered = true
				steps = nil
				if err := relay.RunOnce(context.Background()); err != nil || fmt.Sprint(steps) != "[pending cancel accept]" {
					t.Fatal("same immutable control did not retry", err, steps)
				}
			}
		})
	}
}

func TestSingleTestControlRejectsMalformedDeliveryBeforeRPC(t *testing.T) {
	q := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}, DefinitionVersion: 3, InputDigest: strings.Repeat("a", 64)}
	for _, mode := range []string{"missing_kind", "bad_kind", "null_terminal", "bad_id", "extra_field"} {
		t.Run(mode, func(t *testing.T) {
			v := map[string]any{"start": q, "control_id": "pid_99200005-0000-4000-8000-000000000005", "kind": "approval", "terminal": false}
			switch mode {
			case "missing_kind":
				delete(v, "kind")
			case "bad_kind":
				v["kind"] = "start"
			case "null_terminal":
				v["terminal"] = nil
			case "bad_id":
				v["control_id"] = "foreign"
			case "extra_field":
				v["effect_authorized"] = true
			}
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
				if sql != `SELECT zasp_temporal74.pending_controls()` {
					t.Fatal("malformed control accepted")
				}
				return json.Marshal([]any{v})
			})
			p := &temporalSecurityAgentProduct{executor: db}
			if err := p.singleTestControlRelay(func(context.Context, string, orchestration.StartRequest) error {
				t.Fatal("malformed control RPC")
				return nil
			}).RunOnce(context.Background()); err == nil {
				t.Fatal("malformed delivery accepted")
			}
		})
	}
}
