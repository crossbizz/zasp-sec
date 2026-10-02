//go:build darwin || linux

package apiserver

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestProductionSecurityAgentPlannerTenantIsolationThroughWorker(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, connection *pgx.Conn, dsn string) {
		const organization = "pid_6a000001-0000-4000-8000-000000000001"
		const environment = "pid_6a000003-0000-4000-8000-000000000003"
		const foreignOrganization = "pid_9a000001-0000-4000-8000-000000000001"
		const foreignWorkspace = "pid_9a000002-0000-4000-8000-000000000002"
		const foreignEnvironment = "pid_9a000003-0000-4000-8000-000000000003"
		const foreignAsset = "pid_9a000020-0000-4000-8000-000000000020"
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$4,'repository','Foreign tenant asset','active',transaction_timestamp(),transaction_timestamp(),'asset')`, foreignOrganization, foreignWorkspace, foreignEnvironment, foreignAsset); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
			t.Fatal(err)
		}
		// Explicit controlled-transport allowance is copied into the immutable
		// run budget by real RunOnce admission, never patched into a claimed run.
		if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=body||'{"max_ai_cost_nano_credits":200}'::jsonb WHERE organization_id=$1`, organization); err != nil {
			t.Fatal(err)
		}
		targetSnapshot := func() string {
			t.Helper()
			var value string
			if err := connection.QueryRow(ctx, `SELECT jsonb_build_object(
 'assets',(SELECT jsonb_agg(to_jsonb(r) ORDER BY organization_id,id) FROM zasp_inventory_entities r),
 'environments',(SELECT jsonb_agg(to_jsonb(r) ORDER BY organization_id,id) FROM zasp_environments r),
 'paths',(SELECT jsonb_agg(to_jsonb(r) ORDER BY organization_id,id) FROM zasp_risk_attack_paths r)
)::text`).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		beforeTargets := targetSnapshot()
		binary := filepath.Join(t.TempDir(), "planner-worker.test")
		compile := exec.Command("go", "test", "-race", "-c", "-o", binary, "../agentsec-worker")
		if output, err := runSandboxWorkerCommand(ctx, compile); err != nil {
			t.Fatalf("compile owned planner worker: %v\n%s", err, output)
		}
		fixtureURL, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		fixtureURL.User = url.User("security_agent_v33_worker_login")
		for index, candidate := range []struct{ name, target, outcome, state string }{
			{"foreign_asset", foreignAsset, "planner_rejected", "failed"},
			{"foreign_environment", foreignEnvironment, "planner_rejected", "failed"},
			{"authorized_environment", environment, "accepted", "waiting_approval"},
		} {
			t.Run(candidate.name, func(t *testing.T) {
				// Each case gets a fresh definition/run; failed runs are not reset.
				definition := "pid_6a000004-0000-4000-8000-000000000004"
				if index > 0 {
					definition = fmt.Sprintf("pid_6a000030-0000-4000-8000-%012d", index)
					if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) SELECT organization_id,workspace_id,environment_id,$2,activation,version,definition_version,jsonb_set(body,'{id}',to_jsonb($2::text)),plan_catalog_version FROM zasp_security_agent_definitions WHERE organization_id=$1 AND definition_id='pid_6a000004-0000-4000-8000-000000000004'`, organization, definition); err != nil {
						t.Fatal(err)
					}
				}
				command := exec.Command(binary, "-test.run=^TestSecurityAgentPlannerWorkerOwnedPostgres$", "-test.v", "-test.timeout=30s")
				for _, entry := range os.Environ() {
					if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
						command.Env = append(command.Env, entry)
					}
				}
				command.Env = append(command.Env, "ZASP_PLANNER_TENANT_TEST_DSN="+fixtureURL.String(), "ZASP_PLANNER_TENANT_TEST_TARGET="+candidate.target, "ZASP_PLANNER_TENANT_TEST_DEFINITION="+definition)
				output, err := runSandboxWorkerCommand(ctx, command)
				if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "actual planner and processor completed one scoped database run") {
					t.Fatalf("owned planner worker: %v\n%s", err, output)
				}
				t.Logf("owned planner worker joined:\n%s", output)
				var state, outcome string
				var plans, steps, approvals, effects, controls, foreignRuns int
				if err := connection.QueryRow(ctx, `SELECT r.state,p.outcome,
 (SELECT count(*) FROM zasp_security_agent_plans),
 (SELECT count(*) FROM zasp_security_agent_steps),
 (SELECT count(*) FROM zasp_security_agent_approvals),
 (SELECT count(*) FROM zasp_security_agent_effects),
 (SELECT count(*) FROM zasp_security_agent_controls),
 (SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$3)
FROM zasp_security_agent_runs r JOIN zasp_security_agent_planner_receipts p USING(organization_id,workspace_id,environment_id,run_id)
WHERE r.organization_id=$1 AND r.definition_id=$2`, organization, definition, foreignOrganization).Scan(&state, &outcome, &plans, &steps, &approvals, &effects, &controls, &foreignRuns); err != nil {
					t.Fatal(err)
				}
				wantPrepared := 0
				if candidate.outcome == "accepted" {
					wantPrepared = 1
				}
				if state != candidate.state || outcome != candidate.outcome || plans != wantPrepared || steps != wantPrepared || approvals != wantPrepared || effects != 0 || controls != 0 || foreignRuns != 0 {
					t.Fatalf("state=%s outcome=%s plans=%d steps=%d approvals=%d effects=%d controls=%d foreignRuns=%d", state, outcome, plans, steps, approvals, effects, controls, foreignRuns)
				}
				var accounted bool
				if err := connection.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(b.max_cost_nano_credits=200 AND p.maximum_tokens=1000 AND p.maximum_cost_nano_credits=200 AND p.prompt_tokens=120 AND p.completion_tokens=40 AND p.total_tokens=160 AND p.cost_nano_credits=100 AND p.settled_at IS NOT NULL)
FROM zasp_security_agent_provider_reservations p
JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)
WHERE r.organization_id=$1 AND r.definition_id=$2`, organization, definition).Scan(&accounted); err != nil || !accounted {
					t.Fatalf("scoped planner request was not durably accounted: %v %v", accounted, err)
				}
				if wantPrepared == 1 {
					var plannedTarget string
					if err := connection.QueryRow(ctx, `SELECT plan->'steps'->0->>'target_id' FROM zasp_security_agent_plans WHERE organization_id=$1 AND definition_id=$2`, organization, definition).Scan(&plannedTarget); err != nil || plannedTarget != environment {
						t.Fatalf("authorized plan target=%s err=%v", plannedTarget, err)
					}
				}
				var leaked int
				if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_audit WHERE event_kind='planner_failed' AND (body::text LIKE '%'||$1||'%' OR body::text LIKE '%'||$2||'%')`, foreignAsset, foreignEnvironment).Scan(&leaked); err != nil || leaked != 0 {
					t.Fatalf("rejected candidate leaked into audit count=%d err=%v", leaked, err)
				}
				if targetSnapshot() != beforeTargets {
					t.Fatal("planner/worker changed a tenant target")
				}
			})
		}
	})
}
