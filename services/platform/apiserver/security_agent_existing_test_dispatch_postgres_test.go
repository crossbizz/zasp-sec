package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Registered worker login, but owner-seeded preparation. The temporary fixture
// grant exercises the unexposed candidate; no migration grants worker dispatch.
func exerciseSecurityAgentExistingTestDispatch(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, org, ws, env, testID, target, actor string) {
	t.Helper()
	const signature = "public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text)"
	var private bool
	if err := owner.QueryRow(ctx, `SELECT NOT has_function_privilege('security_agent_v33_worker_login',$1,'EXECUTE')`, signature).Scan(&private); err != nil || !private {
		t.Fatalf("dispatch must initially be private: %v", err)
	}
	if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO security_agent_v33_worker_login`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`)
	for i, mode := range []string{"run_test", "rerun_test", "stale_lease", "changed_plan", "changed_step", "disabled_control", "stale_evidence", "budget_stopped", "step_limit", "audit_wait_lease", "audit_wait_budget", "audit_wait_target", "runtime_current", "runtime_rotated", "runtime_revoked", "runtime_expired", "runtime_digest_changed", "audit_wait_runtime_credential"} {
		t.Run(mode, func(t *testing.T) {
			run := fmt.Sprintf("pid_890001%02d-0000-4000-8000-000000000001", i)
			step := fmt.Sprintf("pid_890002%02d-0000-4000-8000-000000000002", i)
			finding := fmt.Sprintf("pid_890003%02d-0000-4000-8000-000000000003", i)
			audit := fmt.Sprintf("pid_890004%02d-0000-4000-8000-000000000004", i)
			correlation := fmt.Sprintf("pid_890005%02d-0000-4000-8000-000000000005", i)
			action := "run_test"
			if mode == "rerun_test" {
				action = mode
			}
			const workerID, lease = "existing-test-dispatch-worker", "existing-test-dispatch-lease"
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='autonomous',body=body||jsonb_build_object('enabled',true,'autonomy','autonomous','trigger_kind','finding','trigger_source','credential','allowed_actions',jsonb_build_array($10),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$4,'definition_version',1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$7 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)
 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET actor_id=excluded.actor_id,definition=excluded.definition,definition_digest=excluded.definition_digest;
 INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$11,'posture','credential','Existing test trigger','high','open');
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,lease_owner,lease_token,lease_expires_at)
 SELECT organization_id,workspace_id,environment_id,$5,definition_id,version,$11,$7,'planning',$12,$9,clock_timestamp()+interval '1 hour' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,created_at,created_at+interval '1 hour',1,4000,1000000000000,10 FROM zasp_security_agent_runs WHERE run_id=$5;
 INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,$11,'finding',1,decode(repeat('cd',32),'hex'),run_id FROM zasp_security_agent_runs WHERE run_id=$5;
 INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,decode(repeat('cd',32),'hex'),'security-agent-actions-v1',p,digest(convert_to(p::text,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour'
 FROM zasp_security_agent_runs CROSS JOIN LATERAL (SELECT jsonb_build_object('version',1,'summary','Bounded existing test','steps',jsonb_build_array(jsonb_build_object('step_id',$6,'index',0,'action',$10,'target_id',$4,'test_definition_version',1,'test_target_id',$8,'test_target_kind','agent_endpoint','authorization','autonomous'))) AS p) document WHERE run_id=$5;
 UPDATE zasp_security_agent_runs SET plan_hash=(SELECT plan_hash FROM zasp_security_agent_plans WHERE run_id=$5) WHERE run_id=$5;
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
 SELECT organization_id,workspace_id,environment_id,run_id,$6,0,$10,digest(convert_to((plan->'steps'->0)::text,'UTF8'),'sha256'),'autonomous','authorized' FROM zasp_security_agent_plans WHERE run_id=$5;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,$10,true,$7) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, org, ws, env, testID, run, step, actor, target, lease, action, finding, workerID); err != nil {
				t.Fatal(err)
			}
			mutations := map[string]string{
				"stale_lease":      `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
				"changed_plan":     `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,target_id}','"pid_89009999-0000-4000-8000-000000000001"') WHERE run_id=$1`,
				"changed_step":     `UPDATE zasp_security_agent_steps SET input_digest=decode(repeat('ff',32),'hex') WHERE run_id=$1`,
				"disabled_control": `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE action_key='run_test' AND organization_id=(SELECT organization_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
				"stale_evidence":   `UPDATE zasp_risk_findings SET version=version+1 WHERE id=(SELECT trigger_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
				"budget_stopped":   `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_cost_exceeded' WHERE run_id=$1`,
				"step_limit":       `INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) SELECT organization_id,workspace_id,environment_id,run_id,'pid_89009998-0000-4000-8000-000000000001',1,action_key,input_digest,'allow','succeeded' FROM zasp_security_agent_steps WHERE run_id=$1; INSERT INTO zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=1`,
			}
			if sql := mutations[mode]; sql != "" {
				if _, err := owner.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol, run); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "runtime_") || mode == "audit_wait_runtime_credential" {
				seedExistingTestRuntimeTrigger(t, ctx, owner, org, ws, env, run, finding, mode)
			}
			var raw json.RawMessage
			invoke := func() error {
				return worker.QueryRow(ctx, `SELECT zasp_security_agent_test_dispatch($1,$2,$3,$4,$5,$6,$7,$8)`, org, ws, env, run, workerID, lease, audit, correlation).Scan(&raw)
			}
			var err error
			if strings.HasPrefix(mode, "audit_wait_") {
				// Simulate maintenance holding the audit relation. Unlike inserting
				// a conflicting audit row, this does not acquire org admission first.
				other, connectErr := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if connectErr != nil {
					t.Fatal(connectErr)
				}
				defer other.Close(context.Background())
				if _, err := other.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer other.Exec(context.Background(), `ROLLBACK`)
				if _, err := other.Exec(ctx, `LOCK TABLE zasp_security_agent_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				deadlineSQL := `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
				deadlineID := run
				if mode == "audit_wait_budget" {
					deadlineSQL = `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING deadline_at`
				}
				if mode == "audit_wait_runtime_credential" {
					deadlineSQL = `UPDATE zasp_gateway_credentials SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING expires_at`
					deadlineID = strings.Replace(run, "pid_890001", "pid_893001", 1)
				}
				if mode == "audit_wait_target" {
					deadlineSQL = `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING fresh_until`
					deadlineID = target
					defer owner.Exec(context.Background(), `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, target)
				}
				var deadline time.Time
				if err := owner.QueryRow(ctx, deadlineSQL, deadlineID).Scan(&deadline); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- invoke() }()
				joined := false
				defer func() {
					if !joined {
						other.Exec(context.Background(), `ROLLBACK`)
						<-done
					}
				}()
				observed := false
				for time.Now().Before(deadline) {
					if err := other.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND clock_timestamp()<$2::timestamptz`, worker.PgConn().PID(), deadline).Scan(&observed); err != nil {
						t.Fatal(err)
					}
					if observed {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !observed {
					t.Fatal("late audit blocker not observed before expiry")
				}
				for {
					var expired bool
					if err := other.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
						t.Fatal(err)
					}
					if expired {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if _, err := other.Exec(ctx, `ROLLBACK`); err != nil {
					t.Fatal(err)
				}
				err = <-done
				joined = true
			} else {
				err = invoke()
			}
			success := mode == "run_test" || mode == "rerun_test" || mode == "runtime_current"
			stopped := mode == "budget_stopped" || mode == "step_limit" || mode == "audit_wait_budget"
			if success || stopped {
				var result SecurityAgentExecuteResult
				if err != nil || decodeStrictDiscovery(raw, &result) != nil {
					t.Fatalf("dispatch=%s err=%v", raw, err)
				}
				if success && (result.State != "running" || result.EffectState != "pending" || result.RunID != run || result.StepID != step || result.Version != 2) {
					t.Fatalf("wrong pending result: %+v", result)
				}
				if stopped && (result.State != "needs_human" || result.StepID != "" || result.EffectState != "") {
					t.Fatalf("wrong budget stop: %+v", result)
				}
			} else {
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || (pg.Code != "40001" && pg.Code != "55000") {
					t.Fatalf("unsafe dispatch: %v", err)
				}
			}
			var testRun string
			if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_test_run',$4::text||chr(31)||$5::text||chr(31)||$6::text)`, org, ws, env, run, step, action).Scan(&testRun); err != nil {
				t.Fatal(err)
			}
			var links, effects, outbox, testRuns, receipts int
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_test_links WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1),(SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'run_id'=$2),(SELECT count(*) FROM zasp_red_team_runs WHERE run_id=$2),(SELECT count(*) FROM zasp_red_team_request_receipts WHERE resource_id=$2)`, run, testRun).Scan(&links, &effects, &outbox, &testRuns, &receipts); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if links != want || effects != want || outbox != want || testRuns != want || receipts != want {
				t.Fatalf("work counts=%d/%d/%d/%d/%d want=%d", links, effects, outbox, testRuns, receipts, want)
			}
			if strings.HasPrefix(mode, "audit_wait_") {
				var reservations, agentAudit, testAudit int
				var state string
				var reason *string
				if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_step_reservations WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1),(SELECT count(*) FROM zasp_red_team_audit WHERE body::text LIKE '%'||$2::text||'%'),(SELECT state FROM zasp_security_agent_runs WHERE run_id=$1),(SELECT stop_reason FROM zasp_security_agent_run_budgets WHERE run_id=$1)`, run, testRun).Scan(&reservations, &agentAudit, &testAudit, &state, &reason); err != nil {
					t.Fatal(err)
				}
				if reservations != 0 || agentAudit != 0 || testAudit != 0 {
					t.Fatalf("late expiry retained reservation/audit: %d/%d/%d", reservations, agentAudit, testAudit)
				}
				if mode == "audit_wait_budget" {
					if state != "needs_human" || reason == nil || *reason != "budget_deadline_exceeded" {
						t.Fatalf("budget stop not persisted: state=%s reason=%v", state, reason)
					}
				} else if state != "planning" || reason != nil {
					t.Fatalf("refusal changed durable run/budget: state=%s reason=%v", state, reason)
				}
			}
		})
	}
}
