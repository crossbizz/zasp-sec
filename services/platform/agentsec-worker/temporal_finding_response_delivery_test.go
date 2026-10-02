package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestFindingResponseStartDelivery(t *testing.T) {
	ref := orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}
	request := orchestration.StartRequest{Ref: ref, DefinitionVersion: 4, InputDigest: strings.Repeat("a", 64)}
	for _, mode := range []string{"accepted", "ambiguous", "cancelled", "wrong_receipt"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			acks, calls := 0, 0
			db := singleDeliveryDatabaseFunc(func(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == `SELECT zasp_temporal78.pending()` {
					return json.Marshal([]orchestration.StartRequest{request})
				}
				if sql != `SELECT zasp_temporal78.accept_start($1::jsonb)` {
					t.Fatal("unrelated delivery boundary", sql)
				}
				acks++
				raw, _ := json.Marshal(args[0])
				expected, _ := json.Marshal(temporalStartFields(request))
				if !jsonEqualWorker(raw, expected) {
					t.Fatal("changed finding start identity")
				}
				id, _ := orchestration.FindingResponseWorkflowID(ref)
				if mode == "wrong_receipt" {
					id = "security-agent-test/v1/wrong"
				}
				return json.Marshal(map[string]any{"workflow_id": id, "accepted_at": "2026-09-24T10:00:00Z"})
			})
			product := &temporalSecurityAgentProduct{executor: db}
			factory, ok := any(product).(interface {
				findingResponseRelay(func(context.Context, orchestration.StartRequest) error) workerProcessor
			})
			if !ok {
				t.Fatal("finding start relay missing")
			}
			relay := factory.findingResponseRelay(func(_ context.Context, q orchestration.StartRequest) error {
				calls++
				if q != request {
					t.Fatal("changed finding workflow input")
				}
				if mode == "ambiguous" {
					return errors.New("ambiguous durable acceptance")
				}
				if mode == "cancelled" {
					cancel()
				}
				return nil
			})
			err := relay.RunOnce(ctx)
			wantACK := 1
			if mode == "ambiguous" || mode == "cancelled" {
				wantACK = 0
			}
			if calls != 1 || acks != wantACK || (err != nil) != (mode != "accepted") {
				t.Fatal("finding delivery result", calls, acks, err)
			}
		})
	}
}
