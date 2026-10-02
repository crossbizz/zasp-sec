package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const existingTestPlannerContextSQL = `SELECT public.zasp_production_security_agent_existing_tests_planner_context($1,$2,$3,$4,$5,$6)`

// Real registered-worker context authority over owner-seeded admitted runs.
// This does not prove activation, planner reservation, acceptance or execution.
func TestSecurityAgentExistingTestPlannerContextPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		const workerID, lease = "existing-test-planner-worker", "existing-test-planner-lease"
		for i, mode := range []string{"run_test", "rerun_test", "stale_test", "disabled_test", "stale_evidence", "disabled_agent", "foreign_scope", "stale_lease", "budget_stopped", "evidence_wait_lease", "evidence_wait_budget", "evidence_wait_target", "runtime_current", "runtime_revoked", "runtime_expired", "runtime_digest_changed", "attack_path_current", "attack_path_stale", "legacy"} {
			t.Run(mode, func(t *testing.T) {
				run := fmt.Sprintf("pid_890001%02d-0000-4000-8000-000000000001", i+70)
				finding := fmt.Sprintf("pid_894002%02d-0000-4000-8000-000000000002", i)
				action := "run_test"
				if mode == "rerun_test" {
					action = mode
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=1,enabled=true WHERE definition_id=$4;
 UPDATE zasp_security_agent_definitions SET activation='supervised',body=body||jsonb_build_object('enabled',true,'autonomy','supervised','trigger_kind','finding','trigger_source','credential','allowed_actions',jsonb_build_array($9),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$4,'definition_version',1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$6,'posture','credential','Planner trigger','high','open');
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,lease_owner,lease_token,lease_expires_at)
 SELECT organization_id,workspace_id,environment_id,$5,definition_id,version,$6,$7,'planning',$8,$10,clock_timestamp()+interval '1 hour' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,created_at,created_at+interval '1 hour',1,4000,1000000000000,10 FROM zasp_security_agent_runs WHERE run_id=$5;
 INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,$6,'finding',1,decode(repeat('cd',32),'hex'),run_id FROM zasp_security_agent_runs WHERE run_id=$5`, pgx.QueryExecModeSimpleProtocol, org, ws, env, testID, run, finding, actor, workerID, action, lease); err != nil {
					t.Fatal(err)
				}
				mutations := map[string]string{
					"stale_test":     `UPDATE zasp_red_team_definitions SET version=2 WHERE definition_id=$1`,
					"disabled_test":  `UPDATE zasp_red_team_definitions SET enabled=false WHERE definition_id=$1`,
					"stale_evidence": `UPDATE zasp_risk_findings SET version=2 WHERE id=$1`,
					"disabled_agent": `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
					"stale_lease":    `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
					"budget_stopped": `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_cost_exceeded' WHERE run_id=$1`,
				}
				if mutation := mutations[mode]; mutation != "" {
					id := run
					if mode == "stale_test" || mode == "disabled_test" {
						id = testID
					}
					if mode == "stale_evidence" {
						id = finding
					}
					if _, err := owner.Exec(ctx, mutation, id); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(mode, "runtime_") {
					seedExistingTestRuntimeTrigger(t, ctx, owner, org, ws, env, run, finding, mode)
				}
				if strings.HasPrefix(mode, "attack_path_") {
					if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='observed',version=$5 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_6a000005-0000-4000-8000-000000000005');
 UPDATE zasp_security_agent_definitions SET body=body||'{"trigger_kind":"attack_path","trigger_source":"observed"}'::jsonb WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 UPDATE zasp_security_agent_runs SET trigger_id='pid_6a000005-0000-4000-8000-000000000005' WHERE run_id=$4;
 UPDATE zasp_security_agent_trigger_receipts SET trigger_kind='attack_path',trigger_id='pid_6a000005-0000-4000-8000-000000000005',trigger_version=$5 WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, org, ws, env, run, i+2); err != nil {
						t.Fatal(err)
					}
					if mode == "attack_path_stale" {
						if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET version=version+1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_6a000005-0000-4000-8000-000000000005')`, org, ws, env); err != nil {
							t.Fatal(err)
						}
					}
				}
				if mode == "legacy" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||'{"allowed_actions":["update_finding_response"],"verification_kind":"finding_state"}'::jsonb WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, org, ws, env); err != nil {
						t.Fatal(err)
					}
				}
				requestEnv := env
				if mode == "foreign_scope" {
					requestEnv = "pid_89409999-0000-4000-8000-000000000001"
				}
				var raw json.RawMessage
				invoke := func() error {
					return worker.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, requestEnv, run, workerID, lease).Scan(&raw)
				}
				var err error
				if strings.HasPrefix(mode, "evidence_wait_") {
					blocker, connectErr := pgx.ConnectConfig(ctx, owner.Config().Copy())
					if connectErr != nil {
						t.Fatal(connectErr)
					}
					defer blocker.Close(context.Background())
					if _, err := blocker.Exec(ctx, `BEGIN; LOCK TABLE zasp_risk_findings IN ACCESS EXCLUSIVE MODE`); err != nil {
						t.Fatal(err)
					}
					defer blocker.Exec(context.Background(), `ROLLBACK`)
					deadlineSQL := `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
					deadlineID := run
					if mode == "evidence_wait_budget" {
						deadlineSQL = `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING deadline_at`
					}
					if mode == "evidence_wait_target" {
						deadlineSQL = `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING fresh_until`
						deadlineID = "pid_89000011-0000-4000-8000-000000000001"
						defer owner.Exec(context.Background(), `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, deadlineID)
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
							blocker.Exec(context.Background(), `ROLLBACK`)
							<-done
						}
					}()
					observed := false
					for time.Now().Before(deadline) {
						if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND clock_timestamp()<$2::timestamptz`, worker.PgConn().PID(), deadline).Scan(&observed); err != nil {
							t.Fatal(err)
						}
						if observed {
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if !observed {
						t.Fatal("evidence lock wait not observed before expiry")
					}
					for {
						var expired bool
						if err := blocker.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
							t.Fatal(err)
						}
						if expired {
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if _, err := blocker.Exec(ctx, `ROLLBACK`); err != nil {
						t.Fatal(err)
					}
					err = <-done
					joined = true
				} else {
					err = invoke()
				}
				if mode == "legacy" {
					if err != nil {
						t.Fatal(err)
					}
					var legacy json.RawMessage
					if err := worker.QueryRow(ctx, `SELECT zasp_security_agent_planner_context_v33($1,$2,$3,$4,$5,$6)`, org, ws, env, run, workerID, lease).Scan(&legacy); err != nil || string(legacy) != string(raw) {
						t.Fatalf("legacy context changed: new=%s old=%s err=%v", raw, legacy, err)
					}
				} else if mode == "run_test" || mode == "rerun_test" || mode == "runtime_current" || mode == "attack_path_current" {
					if err != nil {
						t.Fatalf("configured existing test must produce planner context: %v", err)
					}
					var envelope struct {
						Context struct {
							AllowedActions []string `json:"allowed_actions"`
							AllowedTargets []string `json:"allowed_targets"`
							ExistingTest   struct {
								ID      string `json:"definition_id"`
								Version int    `json:"definition_version"`
							} `json:"existing_test"`
						} `json:"context"`
						Digest string `json:"input_digest"`
					}
					if err := json.Unmarshal(raw, &envelope); err != nil {
						t.Fatal(err)
					}
					if len(envelope.Context.AllowedActions) != 1 || envelope.Context.AllowedActions[0] != action || len(envelope.Context.AllowedTargets) != 1 || envelope.Context.AllowedTargets[0] != testID || envelope.Context.ExistingTest.ID != testID || envelope.Context.ExistingTest.Version != 1 || len(envelope.Digest) != 71 {
						t.Fatalf("wrong bounded context: %s", raw)
					}
					var canonical string
					if err := owner.QueryRow(ctx, `SELECT ($1::jsonb->'context')::text`, raw).Scan(&canonical); err != nil {
						t.Fatal(err)
					}
					if envelope.Digest != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(canonical))) {
						t.Fatalf("digest does not cover entire context: %s", raw)
					}
					first := string(raw)
					if err := invoke(); err != nil || string(raw) != first {
						t.Fatalf("context replay changed: %s %v", raw, err)
					}
					// The exact stored version must change the digest, even with the
					// same run, trigger, action and test ID.
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=2 WHERE definition_id=$1; UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{existing_test,definition_version}','2') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$2)`, pgx.QueryExecModeSimpleProtocol, testID, run); err != nil {
						t.Fatal(err)
					}
					if err := invoke(); err != nil {
						t.Fatal(err)
					}
					var changed struct {
						Digest string `json:"input_digest"`
					}
					if err := json.Unmarshal(raw, &changed); err != nil || changed.Digest == envelope.Digest {
						t.Fatalf("test version not bound to digest: %s %v", raw, err)
					}
				} else if mode == "budget_stopped" || mode == "evidence_wait_budget" {
					if err != nil {
						t.Fatal(err)
					}
					var durable bool
					reason := "budget_cost_exceeded"
					if mode == "evidence_wait_budget" {
						reason = "budget_deadline_exceeded"
					}
					if err := owner.QueryRow(ctx, `SELECT state='needs_human' AND last_error_code=$2 AND lease_token IS NULL FROM zasp_security_agent_runs WHERE run_id=$1`, run, reason).Scan(&durable); err != nil || !durable {
						t.Fatalf("budget stop rolled back: %v", err)
					}
					var stop map[string]json.RawMessage
					if err := json.Unmarshal(raw, &stop); err != nil || stop["budget_stop"] == nil {
						t.Fatalf("missing stop envelope: %s %v", raw, err)
					}
				} else {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != "40001" {
						t.Fatalf("unsafe context not refused: %s %v", raw, err)
					}
				}
				var untouched bool
				if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_steps WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_outbox)`, run).Scan(&untouched); err != nil || !untouched {
					t.Fatalf("context created execution state: %v", err)
				}
			})
		}
		t.Run("prior_plan", func(t *testing.T) {
			const run = "pid_89000188-0000-4000-8000-000000000001"
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=body||jsonb_build_object('allowed_actions',jsonb_build_array('run_test'),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$1::text,'definition_version',1)) WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$2)`, testID, run); err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			if err := worker.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, env, run, workerID, lease).Scan(&raw); err != nil {
				t.Fatalf("prior-plan positive control unavailable: %v", err)
			}
			var before, after string
			if err := owner.QueryRow(ctx, `INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,decode(repeat('cd',32),'hex'),'security-agent-actions-v1',p,digest(convert_to(p::text,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs CROSS JOIN LATERAL(SELECT jsonb_build_object('version',1,'summary','Already prepared','steps',jsonb_build_array(jsonb_build_object('step_id','pid_89409998-0000-4000-8000-000000000001','index',0,'action','run_test','target_id',$2::text,'test_definition_version',1,'test_target_id','pid_89000011-0000-4000-8000-000000000001','test_target_kind','agent_endpoint'))) p) document WHERE run_id=$1 RETURNING to_jsonb(zasp_security_agent_plans)::text`, run, testID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			var pg *pgconn.PgError
			if err := worker.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, env, run, workerID, lease).Scan(&raw); !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("prepared run replanned: %s %v", raw, err)
			}
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(p)::text FROM zasp_security_agent_plans p WHERE run_id=$1`, run).Scan(&after); err != nil || before != after {
				t.Fatalf("prior plan changed: %v", err)
			}
		})
		var raw json.RawMessage
		var pg *pgconn.PgError
		if err := api.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, env, "pid_89400100-0000-4000-8000-000000000001", workerID, lease).Scan(&raw); !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("API principal reached planner context: %v", err)
		}
	})
}
