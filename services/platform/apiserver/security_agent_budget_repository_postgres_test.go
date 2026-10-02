package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type budgetAdapterObservedDatabase struct {
	*PostgresJSONDatabase
	permitPayload json.RawMessage
}

func (db *budgetAdapterObservedDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	payload, err := db.PostgresJSONDatabase.QueryJSON(ctx, statement, args...)
	if statement == reservePlannerBudgetTestSQL {
		db.permitPayload = append(json.RawMessage(nil), payload...)
	}
	return payload, err
}

// Registered SQL and real repository decoding, with owner-configured limits.
// This does not establish a live provider price bound or worker integration.
func TestProductionSecurityAgentBudgetRepository(t *testing.T) {
	for _, mode := range []string{"heartbeat_zero", "heartbeat_unknown", "heartbeat_stop"} {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const org = "pid_6a000001-0000-4000-8000-000000000001"
				const workerID, lease = "budget-adapter-worker", "budget-adapter-lease-00001"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, org); err != nil {
					t.Fatal(err)
				}
				config, err := pgx.ParseConfig(dsn)
				if err != nil {
					t.Fatal(err)
				}
				config.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
				if err != nil {
					t.Fatal(err)
				}
				observed := &budgetAdapterObservedDatabase{PostgresJSONDatabase: database}
				repository, err := NewSecurityAgentWorkerRepository(observed)
				if err != nil {
					t.Fatal(err)
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 1); err != nil || count != 1 {
					t.Fatalf("schedule %d %v", count, err)
				}
				claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 1)
				if err != nil || len(claims) != 1 {
					t.Fatalf("claim %v %v", claims, err)
				}
				claim := claims[0]
				if mode != "heartbeat_stop" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET max_tokens=100,max_cost_nano_credits=200 WHERE organization_id=$1`, org); err != nil {
						t.Fatal(err)
					}
				}
				planner, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
				if err != nil {
					t.Fatal(err)
				}
				if err := repository.HeartbeatSecurityAgentRun(ctx, claim, workerID, lease, 120); err != nil {
					t.Fatal(err)
				}
				request := SecurityAgentBudgetReservation{ReservationID: "adapter-reservation", InputDigest: planner.InputDigest, Model: "fixture-model", CostPolicyVersion: "fixture-policy", CostUnit: "openrouter_credit", MaximumTokens: 100, MaximumCostNanoCredits: 200}
				permit, err := repository.ReserveSecurityAgentPlannerBudget(ctx, claim, workerID, lease, request)
				if mode == "heartbeat_stop" {
					if !errors.Is(err, ErrSecurityAgentBudgetStopped) || permit != (SecurityAgentBudgetPermit{}) {
						t.Fatalf("stop %v %v", permit, err)
					}
					var stopped bool
					if err := owner.QueryRow(ctx, `SELECT state='needs_human' AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL AND last_error_code='budget_usage_unknown' FROM zasp_security_agent_runs WHERE run_id=$1`, claim.RunID).Scan(&stopped); err != nil || !stopped {
						t.Fatalf("durable stop %v %v", stopped, err)
					}
					return
				}
				if err != nil || permit.Reservation != request || permit.Version <= claim.Version || !permit.ExpiresAt.After(claim.LeaseExpiresAt) {
					t.Fatalf("heartbeat permit %v %v; SQL=%s", permit, err, observed.permitPayload)
				}
				usage := SecurityAgentBudgetUsage{ReservationID: request.ReservationID, Known: mode == "heartbeat_zero"}
				if usage.Known {
					usage.OutputDigest = "sha256:" + strings.Repeat("3", 64)
				}
				ack, err := repository.SettleSecurityAgentPlannerBudget(ctx, claim, workerID, lease, usage)
				if err != nil || ack.Known != usage.Known || ack.ReservationID != request.ReservationID {
					t.Fatalf("settlement %v %v", ack, err)
				}
				var known bool
				if err := owner.QueryRow(ctx, `SELECT total_tokens IS NOT NULL AND cost_nano_credits IS NOT NULL FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, claim.RunID).Scan(&known); err != nil || known != usage.Known {
					t.Fatalf("durable accounting %v %v", known, err)
				}
				if !usage.Known && ack.StopReason != "budget_usage_unknown" {
					t.Fatalf("missing unknown stop: %v", ack)
				}
				var exact bool
				if usage.Known {
					if err := owner.QueryRow(ctx, `SELECT prompt_tokens=0 AND completion_tokens=0 AND total_tokens=0 AND cost_nano_credits=0 AND settled_at IS NOT NULL FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, claim.RunID).Scan(&exact); err != nil || !exact {
						t.Fatalf("zero charge not exact: %v %v", exact, err)
					}
				} else {
					if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND b.stop_reason='budget_usage_unknown' FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, claim.RunID).Scan(&exact); err != nil || !exact {
						t.Fatalf("unknown usage stop not durable: %v %v", exact, err)
					}
				}
			})
		})
	}
}
