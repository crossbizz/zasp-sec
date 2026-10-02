package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const existingTestPrepareSQL = `SELECT public.zasp_production_security_agent_existing_tests_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

// These assertions catch a missing preparation branch, unpinned test intent,
// bypassed supervised approval, and execution during preparation. Admission
// is owner-seeded; only preparation uses the real registered worker authority.
func TestSecurityAgentExistingTestPreparationPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		const workerID, lease = "existing-test-prepare-worker", "existing-test-prepare-lease"
		for i, mode := range []struct{ action, autonomy, state, stepState, authorization string }{
			{"run_test", "supervised", "waiting_approval", "waiting_approval", "approval_required"},
			{"rerun_test", "supervised", "waiting_approval", "waiting_approval", "approval_required"},
			{"run_test", "autonomous", "queued", "authorized", "autonomous"},
			{"rerun_test", "autonomous", "queued", "authorized", "autonomous"},
		} {
			t.Run(mode.action+"_"+mode.autonomy, func(t *testing.T) {
				run := fmt.Sprintf("pid_898001%02d-0000-4000-8000-000000000001", i)
				finding := fmt.Sprintf("pid_898002%02d-0000-4000-8000-000000000002", i)
				seedExistingTestPreparation(t, ctx, owner, org, ws, env, testID, actor, run, finding, mode.action, workerID, lease)
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation=$1,body=jsonb_set(body,'{autonomy}',to_jsonb($1::text)) WHERE (organization_id,workspace_id,environment_id)=($3,$4,$5) AND definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$2 AND (organization_id,workspace_id,environment_id)=($3,$4,$5))`, mode.autonomy, run, org, ws, env); err != nil {
					t.Fatal(err)
				}
				approvalID := fmt.Sprintf("pid_898003%02d-0000-4000-8000-000000000001", i)
				expiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond)
				var raw json.RawMessage
				if err := worker.QueryRow(ctx, existingTestPrepareSQL, org, ws, env, run, workerID, lease,
					approvalID, expiresAt,
					fmt.Sprintf("pid_898004%02d-0000-4000-8000-000000000001", i), "pid_89800500-0000-4000-8000-000000000001").Scan(&raw); err != nil {
					t.Fatalf("prepare pinned %s: %v", mode.action, err)
				}
				var result SecurityAgentPrepareResult
				wantApproval, wantApprovals := "", 0
				if mode.autonomy == "supervised" {
					wantApproval, wantApprovals = approvalID, 1
				}
				if err := json.Unmarshal(raw, &result); err != nil || result.RunID != run || result.State != mode.state || result.Version != 3 || result.ApprovalID != wantApproval || result.StepID == "" || result.PlanHash == "" {
					t.Fatalf("unexpected preparation envelope: %s (%v)", raw, err)
				}
				var pinned bool
				if err := owner.QueryRow(ctx, `SELECT p.plan->'steps'->0 = jsonb_build_object('step_id',s.step_id,'index',0,'action',$5::text,'target_id',$6::text,'test_definition_version',1,'test_target_id','pid_89000011-0000-4000-8000-000000000001','test_target_kind','agent_endpoint','authorization',$7::text)
 AND p.plan_hash=digest(convert_to(p.plan::text,'UTF8'),'sha256') AND r.plan_hash=p.plan_hash
 AND s.input_digest=digest(convert_to((p.plan->'steps'->0)::text,'UTF8'),'sha256')
 AND s.state=$8 AND s.authorization_result=$7
 AND r.state=$9 AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL
 AND s.step_id=$10 AND 'sha256:'||encode(p.plan_hash,'hex')=$11 AND r.version=$12
 AND p.expires_at=$13 AND (SELECT count(*) FROM zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4))=1
 FROM zasp_security_agent_plans p JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id)
 WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=($1,$2,$3,$4)`, org, ws, env, run, mode.action, testID, mode.authorization, mode.stepState, mode.state, result.StepID, result.PlanHash, result.Version, expiresAt).Scan(&pinned); err != nil || !pinned {
					t.Fatalf("stored exact intent/lease/hash mismatch: %t %v", pinned, err)
				}
				if mode.autonomy == "supervised" {
					var bound bool
					if err := owner.QueryRow(ctx, `SELECT a.approval_id=$5 AND a.step_id=$6 AND a.plan_hash=p.plan_hash
 AND a.state='pending' AND a.requester_id=$7 AND a.expires_at=$8
 FROM zasp_security_agent_approvals a JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id)
 WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4)`, org, ws, env, run, approvalID, result.StepID, actor, expiresAt).Scan(&bound); err != nil || !bound {
						t.Fatalf("approval not bound to exact intent: %t %v", bound, err)
					}
				}
				var effects, links, tests, outbox, approvals, reservations int
				if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_effects),
 (SELECT count(*) FROM zasp_security_agent_test_links),(SELECT count(*) FROM zasp_red_team_runs),
 (SELECT count(*) FROM zasp_red_team_outbox),(SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_step_reservations)`, run).Scan(&effects, &links, &tests, &outbox, &approvals, &reservations); err != nil {
					t.Fatal(err)
				}
				if effects+links+tests+outbox+reservations != 0 || approvals != wantApprovals {
					t.Fatalf("preparation executed or escalated: effects=%d links=%d tests=%d outbox=%d approvals=%d reservations=%d", effects, links, tests, outbox, approvals, reservations)
				}
			})
		}
		t.Run("private_helpers_denied", func(t *testing.T) {
			for _, statement := range []string{
				`SELECT public.zasp_production_security_agent_existing_tests_recheck_context($1,$2,$3,$4,$5,$6)`,
				`SELECT public.zasp_production_security_agent_existing_tests_prepare_core($1,$2,$3,$4,$5,$6,$4,clock_timestamp()+interval '1 minute',$4,$4)`,
				`SELECT public.zasp_production_security_agent_existing_tests_finish_prepare($1,$2,$3,$4,$5,$6,'{}'::jsonb)`,
			} {
				var raw json.RawMessage
				var pg *pgconn.PgError
				err := worker.QueryRow(ctx, statement, org, ws, env, "pid_89800100-0000-4000-8000-000000000001", workerID, lease).Scan(&raw)
				if !errors.As(err, &pg) || pg.Code != "42501" {
					t.Fatalf("private helper callable: %s %v", statement, err)
				}
			}
		})
	})
}

func seedExistingTestPreparation(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, testID, actor, run, finding, action, workerID, lease string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=1,enabled=true WHERE definition_id=$4;
 UPDATE zasp_security_agent_definitions SET activation='supervised',body=body||jsonb_build_object('enabled',true,'autonomy','supervised','trigger_kind','finding','trigger_source','credential','allowed_actions',jsonb_build_array($9),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$4,'definition_version',1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$6,'posture','credential','Preparation trigger','high','open');
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,version,attempt,lease_owner,lease_token,lease_expires_at)
 SELECT organization_id,workspace_id,environment_id,$5,definition_id,version,$6,$7,'planning',2,1,$8,$10,clock_timestamp()+interval '60 seconds' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,created_at,created_at+interval '60 seconds',1,100,200,10 FROM zasp_security_agent_runs WHERE run_id=$5;
 INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,$6,'finding',1,decode(repeat('cd',32),'hex'),run_id FROM zasp_security_agent_runs WHERE run_id=$5`, pgx.QueryExecModeSimpleProtocol, org, ws, env, testID, run, finding, actor, workerID, action, lease); err != nil {
		t.Fatal(err)
	}
}
