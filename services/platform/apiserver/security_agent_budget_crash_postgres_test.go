//go:build darwin || linux

package apiserver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProductionSecurityAgentBudgetProcessLossRetainsUnknown(t *testing.T) {
	runSecurityAgentBudgetProcessLoss(t, []string{"crash_before_provider", "crash_after_response"})
}

func TestProductionSecurityAgentBudgetProcessLossRetainsSettled(t *testing.T) {
	runSecurityAgentBudgetProcessLoss(t, []string{"crash_settled_remaining", "crash_settled_exhausted"})
}

func runSecurityAgentBudgetProcessLoss(t *testing.T, modes []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	binary := securityAgentBudgetWorkerBinary(t, ctx)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const org = "pid_6a000001-0000-4000-8000-000000000001"
				settled := strings.HasPrefix(mode, "crash_settled_")
				remaining := mode == "crash_settled_remaining"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, org); err != nil {
					t.Fatal(err)
				}
				invoke := func(phase string) ([]byte, error) {
					command := exec.Command(binary, "-test.run=^TestSecurityAgentBudgetProviderOwnedPostgres$", "-test.v", "-test.timeout=30s")
					command.Dir = "../agentsec-worker"
					for _, entry := range os.Environ() {
						if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
							command.Env = append(command.Env, entry)
						}
					}
					command.Env = append(command.Env, "ZASP_BUDGET_PROVIDER_TEST_DSN="+dsn, "ZASP_BUDGET_PROVIDER_TEST_MODE="+phase)
					return runSandboxWorkerCommand(ctx, command)
				}
				output, err := invoke(mode)
				var exited *exec.ExitError
				calls := "0"
				if mode == "crash_after_response" || settled {
					calls = "1"
				}
				if !errors.As(err, &exited) || exited.ExitCode() != 86 || !strings.Contains(string(output), "owned budget crash boundary: provider_calls="+calls) || strings.Contains(string(output), "--- SKIP:") {
					t.Fatalf("wrong process-loss boundary: %v\n%s", err, output)
				}
				var before string
				var originalBudget string
				if err := owner.QueryRow(ctx, `SELECT (to_jsonb(b)-'stop_reason')::text FROM zasp_security_agent_run_budgets b WHERE organization_id=$1`, org).Scan(&originalBudget); err != nil {
					t.Fatal(err)
				}
				var retained bool
				if err := owner.QueryRow(ctx, `SELECT row_to_json(p)::text,attempt=1 AND maximum_tokens=1000 AND maximum_cost_nano_credits=200 AND CASE WHEN $2 THEN settled_at IS NOT NULL AND output_digest IS NOT NULL AND prompt_tokens=120 AND completion_tokens=40 AND total_tokens=160 AND cost_nano_credits=100 ELSE settled_at IS NULL AND output_digest IS NULL AND prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL END FROM zasp_security_agent_provider_reservations p WHERE organization_id=$1`, org, settled).Scan(&before, &retained); err != nil || !retained {
					t.Fatalf("lost or refunded reservation: %v %v", retained, err)
				}
				if tag, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND state='planning' AND attempt=1`, org); err != nil || tag.RowsAffected() != 1 {
					t.Fatalf("expire crashed lease: %v", err)
				}
				restartMode := "restart_unknown"
				marker := "owned budget processor joined: provider_calls=0 artifact_ids=0"
				if settled {
					restartMode = "restart_settled_exhausted"
				}
				if remaining {
					restartMode = "restart_settled_remaining"
					marker = "owned budget processor joined: provider_calls=1 artifact_ids=3"
				}
				output, err = invoke(restartMode)
				if err != nil || !strings.Contains(string(output), marker) || strings.Contains(string(output), "--- SKIP:") {
					t.Fatalf("restart duplicated provider work: %v\n%s", err, output)
				}
				var after string
				var currentBudget string
				if err := owner.QueryRow(ctx, `SELECT (to_jsonb(b)-'stop_reason')::text FROM zasp_security_agent_run_budgets b WHERE organization_id=$1`, org).Scan(&currentBudget); err != nil || currentBudget != originalBudget {
					t.Fatalf("restart reset deadline, limits or original authority: %v", err)
				}
				if err := owner.QueryRow(ctx, `SELECT row_to_json(p)::text FROM zasp_security_agent_provider_reservations p WHERE organization_id=$1 AND attempt=1`, org).Scan(&after); err != nil || after != before {
					t.Fatalf("restart changed original accounting: %v", err)
				}
				if remaining {
					var exact bool
					if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND count(DISTINCT reservation_id)=2 AND sum(total_tokens)=320 AND sum(cost_nano_credits)=200 AND bool_and(settled_at IS NOT NULL) AND count(*) FILTER(WHERE attempt=2 AND worker_id='budget-restarted-worker' AND total_tokens=160 AND cost_nano_credits=100)=1 FROM zasp_security_agent_provider_reservations WHERE organization_id=$1`, org).Scan(&exact); err != nil || !exact {
						t.Fatalf("retry not freshly reserved and fully charged: %v %v", exact, err)
					}
					if err := owner.QueryRow(ctx, `SELECT r.attempt=2 AND r.state='waiting_approval' AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND b.stop_reason IS NULL AND b.max_tokens=2000 AND b.max_cost_nano_credits=400 AND (SELECT count(*) FROM zasp_security_agent_plans)=1 AND (SELECT count(*) FROM zasp_security_agent_steps)=1 AND (SELECT count(*) FROM zasp_security_agent_approvals)=1 AND (SELECT count(*) FROM zasp_security_agent_planner_receipts)=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, org).Scan(&exact); err != nil || !exact {
						t.Fatalf("retry duplicated authority or enlarged allowance: %v %v", exact, err)
					}
					t.Log("settled crash/restart joined; original charge retained; new attempt freshly reserved and charged once")
					return
				}
				wantReason := "budget_usage_unknown"
				if settled {
					wantReason = "budget_tokens_exceeded"
				}
				var stopped bool
				if err := owner.QueryRow(ctx, `SELECT r.attempt=2 AND r.state='needs_human' AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND b.stop_reason=$2 AND (SELECT count(*) FROM zasp_security_agent_provider_reservations)=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_steps) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_approvals) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_planner_receipts) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, org, wantReason).Scan(&stopped); err != nil || !stopped {
					t.Fatalf("restart stop not durable: %v %v", stopped, err)
				}
				t.Logf("crashed worker joined with code86; new worker joined with no provider dispatch; reservation retained")
			})
		})
	}
}
