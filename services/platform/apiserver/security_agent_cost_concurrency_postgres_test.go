package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Removing the public definition CAS would allow a waiting edit to overwrite
// an activation made against the same version. Exercise both observed orders,
// through registered API repositories, and require exactly one durable winner.
func TestProductionSecurityAgentCostEditActivationContention(t *testing.T) {
	for _, first := range []string{"activation", "edit"} {
		t.Run(first+"_wins", func(t *testing.T) {
			runSecurityAgentCostDefinitionFixture(t, func(ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, id string) {
				identity.FreshAuthenticated = true
				identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
				_, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "contention-validate-0001", ExpectedVersion: 2, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: "pid_bc000001-0000-4000-8000-000000000001", CorrelationID: "pid_bc000002-0000-4000-8000-000000000002", ReceiptID: "pid_bc000003-0000-4000-8000-000000000003"})
				if err != nil {
					t.Fatal(err)
				}
				value, err := repository.GetWorkflow(ctx, identity.Scope, "security_agent", id)
				if err != nil || value.Version != 3 {
					t.Fatalf("validated definition=%+v err=%v", value, err)
				}
				var body map[string]any
				if err := json.Unmarshal(value.Body, &body); err != nil {
					t.Fatal(err)
				}
				body["enabled"] = false
				body["max_ai_cost_nano_credits"] = int64(1000000000000)
				payload, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				intent, err := json.Marshal(map[string]any{"body": body, "resource_id": id, "expected_version": 3})
				if err != nil {
					t.Fatal(err)
				}
				connections := make([]*pgx.Conn, 2)
				repositories := make([]*PostgresRepository, 2)
				for i := range connections {
					config := owner.Config().Copy()
					config.User = "security_agent_v33_api_login"
					config.RuntimeParams["timezone"] = "UTC"
					connections[i], err = pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer connections[i].Close(context.Background())
					database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connections[i]})
					if err != nil {
						t.Fatal(err)
					}
					repositories[i], err = NewSecurityAgentPostgresRepository(database)
					if err != nil {
						t.Fatal(err)
					}
				}
				operate := func(callContext context.Context, index int, action string) (int64, error) {
					if action == "activation" {
						result, err := repositories[index].ActivateSecurityAgent(callContext, identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "contention-activate-0001", ExpectedVersion: 3, TargetActivation: "supervised", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: "pid_bd000001-0000-4000-8000-000000000001", CorrelationID: "pid_bd000002-0000-4000-8000-000000000002", ReceiptID: "pid_bd000003-0000-4000-8000-000000000003"})
						return result.Version, err
					}
					result, err := repositories[index].MutateWorkflow(callContext, identity, WorkflowMutation{Action: "update", Kind: "security_agent", ID: id, Operation: "updateSecurityAgent", IdempotencyKey: "contention-edit-0001", ExpectedVersion: 3, Intent: intent, Body: payload, AuditID: "pid_be000001-0000-4000-8000-000000000001", CorrelationID: "pid_be000002-0000-4000-8000-000000000002", ReceiptID: "pid_be000003-0000-4000-8000-000000000003"})
					return result.Version, err
				}
				transaction, err := connections[0].Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer transaction.Rollback(context.Background())
				if version, err := operate(ctx, 0, first); err != nil || version != 4 {
					t.Fatalf("first %s version=%d err=%v", first, version, err)
				}
				// Snapshot durable authority to detect side effects of rejected retries.
				const authoritySnapshot = `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_definitions t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_definition_versions t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_request_receipts t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_audit t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_security_agent_kill_switches t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_workflow_records t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_workflow_audit t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_workflow_receipts t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM zasp_workflow_idempotency t))::text`
				callContext, cancel := context.WithTimeout(ctx, 10*time.Second)
				type outcome struct {
					version int64
					err     error
				}
				done := make(chan outcome, 1)
				joined := false
				defer func() {
					cancel()
					_ = transaction.Rollback(context.Background())
					if !joined {
						<-done
					}
				}()
				second := "activation"
				if first == "activation" {
					second = "edit"
				}
				go func() {
					version, err := operate(callContext, 1, second)
					done <- outcome{version, err}
				}()
				for {
					var waiting bool
					if err := owner.QueryRow(callContext, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`, connections[1].PgConn().PID(), connections[0].PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case result := <-done:
						joined = true
						t.Fatalf("%s escaped uncommitted %s: %+v", second, first, result)
					case <-callContext.Done():
						t.Fatal("definition lock contention not observed")
					case <-time.After(10 * time.Millisecond):
					}
				}
				if err := transaction.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				result := <-done
				joined = true
				if !errors.Is(result.err, ErrRepositoryConflict) {
					t.Fatalf("losing %s version=%d err=%v", second, result.version, result.err)
				}
				loserKey, loserAudit := "contention-activate-0001", "pid_bd000001-0000-4000-8000-000000000001"
				if second == "edit" {
					loserKey, loserAudit = "contention-edit-0001", "pid_be000001-0000-4000-8000-000000000001"
				}
				var cleanLoser bool
				if err := owner.QueryRow(ctx, `SELECT
 NOT EXISTS(SELECT 1 FROM zasp_workflow_idempotency WHERE idempotency_key=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_workflow_receipts WHERE idempotency_key=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE idempotency_key=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_workflow_audit WHERE audit_id=$2)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE audit_id=$2)
 AND (SELECT count(*) FROM zasp_security_agent_definition_versions WHERE definition_id=$3 AND version>3)=1`, loserKey, loserAudit, id).Scan(&cleanLoser); err != nil || !cleanLoser {
					t.Fatalf("loser persisted receipt/audit/revision: clean=%v err=%v", cleanLoser, err)
				}
				var before string
				if err := owner.QueryRow(ctx, authoritySnapshot).Scan(&before); err != nil {
					t.Fatal(err)
				}
				// A repeated losing call must also leave every authority table unchanged.
				if _, err := operate(ctx, 1, second); !errors.Is(err, ErrRepositoryConflict) {
					t.Fatalf("repeat loser err=%v", err)
				}
				var after string
				if err := owner.QueryRow(ctx, authoritySnapshot).Scan(&after); err != nil || before != after {
					t.Fatalf("rejected retry changed authority: err=%v", err)
				}
				state, err := repository.GetSecurityAgentActivation(ctx, identity, id)
				wantActivation, wantCost := "draft", "1000000000000"
				if first == "activation" {
					wantActivation, wantCost = "supervised", "987654321"
				}
				if err != nil || state.Version != 4 || state.Activation != wantActivation || state.Enabled != (first == "activation") {
					t.Fatalf("winner state=%+v err=%v", state, err)
				}
				var exact bool
				if err := owner.QueryRow(ctx, `SELECT body->>'max_ai_cost_nano_credits'=$2 FROM zasp_security_agent_definitions WHERE definition_id=$1`, id, wantCost).Scan(&exact); err != nil || !exact {
					t.Fatalf("winner cost exact=%v err=%v", exact, err)
				}
			})
		})
	}
}
