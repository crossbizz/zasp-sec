package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestFindingResponseControlDelivery(t *testing.T) {
	ref := orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}
	start := orchestration.StartRequest{Ref: ref, DefinitionVersion: 4, InputDigest: strings.Repeat("a", 64)}
	control := "pid_99200005-0000-4000-8000-000000000005"
	for _, mode := range []string{"approval", "cancel", "terminal", "ambiguous", "cancelled", "wrong_receipt"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, acks := 0, 0
			kind := "cancel"
			if mode == "approval" {
				kind = "approval"
			}
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == `SELECT zasp_temporal78.pending_controls()` {
					return json.Marshal([]any{map[string]any{"start": start, "control_id": control, "kind": kind, "terminal": mode == "terminal"}})
				}
				if sql != `SELECT zasp_temporal78.accept_control($1::jsonb)` {
					t.Fatal("unrelated control query", sql)
				}
				acks++
				fields := temporalStartFields(start)
				fields["control_id"] = control
				raw, _ := json.Marshal(args[0])
				expected, _ := json.Marshal(fields)
				if !jsonEqualWorker(raw, expected) {
					t.Fatal("changed finding control identity")
				}
				id, _ := orchestration.FindingResponseWorkflowID(ref)
				if mode == "wrong_receipt" {
					id = "security-agent-test/v1/wrong"
				}
				return json.Marshal(map[string]any{"control_id": control, "workflow_id": id, "accepted_at": "2026-09-24T10:00:00Z"})
			})
			product := &temporalSecurityAgentProduct{executor: db}
			factory, ok := any(product).(interface {
				findingResponseControlRelay(func(context.Context, string, orchestration.StartRequest) error) workerProcessor
			})
			if !ok {
				t.Fatal("finding control relay missing")
			}
			relay := factory.findingResponseControlRelay(func(_ context.Context, k string, q orchestration.StartRequest) error {
				calls++
				if q != start || k != kind {
					t.Fatal("changed finding decision")
				}
				if mode == "ambiguous" {
					return errors.New("decision acceptance unavailable")
				}
				if mode == "cancelled" {
					cancel()
				}
				return nil
			})
			err := relay.RunOnce(ctx)
			wantCalls, wantACK := 1, 1
			if mode == "terminal" {
				wantCalls = 0
			}
			if mode == "ambiguous" || mode == "cancelled" {
				wantACK = 0
			}
			if calls != wantCalls || acks != wantACK || (err != nil) != (mode == "ambiguous" || mode == "cancelled" || mode == "wrong_receipt") {
				t.Fatal("finding control delivery", calls, acks, err)
			}
		})
	}
}
