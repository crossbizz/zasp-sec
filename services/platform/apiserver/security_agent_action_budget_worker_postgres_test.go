//go:build darwin || linux

package apiserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProductionSecurityAgentBudgetStopsThroughActionWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "budget-action-worker.test")
	if output, err := runSandboxWorkerCommand(ctx, exec.Command("go", "test", "-race", "-c", "-o", binary, "../agentsec-worker")); err != nil {
		t.Fatalf("compile action worker: %v\n%s", err, output)
	}
	for _, mode := range []string{"expired", "fresh", "heartbeat", "inflight_heartbeat"} {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				command := exec.Command(binary, "-test.run=^TestSecurityAgentActionBudgetOwnedPostgres$", "-test.v", "-test.timeout=35s")
				command.Dir = "../agentsec-worker"
				for _, entry := range os.Environ() {
					if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
						command.Env = append(command.Env, entry)
					}
				}
				command.Env = append(command.Env, "ZASP_ACTION_BUDGET_TEST_DSN="+dsn, "ZASP_ACTION_BUDGET_TEST_MODE="+mode)
				output, err := runSandboxWorkerCommand(ctx, command)
				if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "owned action processor joined:") {
					t.Fatalf("owned action worker: %v\n%s", err, output)
				}
				t.Logf("owned worker joined:\n%s", output)
				var state, reason string
				var stored, effects, reservations, bundles, outcomes int
				if err := owner.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE state='stored'),
 (SELECT count(*) FROM zasp_security_agent_effects),
 (SELECT count(*) FROM zasp_security_agent_step_reservations),
 (SELECT count(*) FROM zasp_runtime_gateway_policy_bundles),
 (SELECT count(*) FROM zasp_security_agent_audit WHERE event_kind IN ('effect_verified','effect_cleaned'))
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)`).Scan(&state, &reason, &stored, &effects, &reservations, &bundles, &outcomes); err != nil {
					t.Fatal(err)
				}
				wantState, wantReason, wantStored := "needs_human", "budget_deadline_exceeded", 0
				if mode == "fresh" {
					wantState, wantReason, wantStored = "running", "", 1
				}
				if state != wantState || reason != wantReason || stored != wantStored || effects != 1 || reservations != 1 || bundles != 0 || outcomes != 0 {
					t.Fatalf("state=%s reason=%s stored=%d effects=%d reservations=%d bundles=%d outcomes=%d", state, reason, stored, effects, reservations, bundles, outcomes)
				}
			})
		})
	}
}
