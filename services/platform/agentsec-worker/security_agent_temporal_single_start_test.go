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

func TestSingleTestStartRelayAcceptsOnlyExactDurableStart(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(fmt.Sprint(failStart), func(t *testing.T) {
			ref := orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}
			start := orchestration.StartRequest{Ref: ref, DefinitionVersion: 7, InputDigest: strings.Repeat("a", 64)}
			steps := []string{}
			db := singleDeliveryDatabaseFunc(func(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
				if sql == `SELECT zasp_temporal74.pending()` {
					steps = append(steps, "pending")
					return json.Marshal([]orchestration.StartRequest{start})
				}
				if sql != `SELECT zasp_temporal74.accept_start($1::jsonb)` {
					t.Fatal(sql)
				}
				steps = append(steps, "accept")
				raw, _ := json.Marshal(args[0])
				want, _ := json.Marshal(temporalStartFields(start))
				if !jsonEqualWorker(raw, want) {
					t.Fatal("altered admission", string(raw))
				}
				return json.Marshal(map[string]any{"workflow_id": "security-agent-test/v1/" + ref.OrganizationID + "/" + ref.WorkspaceID + "/" + ref.EnvironmentID + "/" + ref.RunID, "accepted_at": "2026-09-23T10:00:00Z"})
			})
			product := &temporalSecurityAgentProduct{executor: db}
			factory, ok := any(product).(interface {
				singleTestRelay(func(context.Context, orchestration.StartRequest) error) workerProcessor
			})
			if !ok {
				t.Fatal("specialized durable start relay missing")
			}
			relay := factory.singleTestRelay(func(ctx context.Context, q orchestration.StartRequest) error {
				steps = append(steps, "start")
				if q != start {
					t.Fatal("changed workflow start", q)
				}
				if failStart {
					return errors.New("ambiguous Temporal start")
				}
				return nil
			})
			err := relay.RunOnce(context.Background())
			want := "[pending start accept]"
			if failStart {
				want = "[pending start]"
			}
			if (err != nil) != failStart || fmt.Sprint(steps) != want {
				t.Fatal(err, steps, want)
			}
		})
	}
}
