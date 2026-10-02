package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are dormant authority tests. Owner-inserted application/control rows
// below are fixtures, not evidence that any adapter can produce release61 work.
func TestSecurityAgentMultistepProgressionAuthorityPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		var installed bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_sa_multistep_prior.transition(text,text,jsonb)') IS NOT NULL`).Scan(&installed); err != nil || !installed {
			t.Fatalf("release61 ready-step transition authority absent: present=%t err=%v", installed, err)
		}
		for index, mode := range []string{"waiting", "approve_first", "early_approval", "self_approval", "stale_version", "foreign_scope", "fresh_auth", "expired_approval", "expired_plan", "stopped", "failed", "unknown", "cancelled", "reject", "cancel", "receipt", "receipt_replay", "inactive_control", "expired_control", "changed_control", "changed_deployment", "missing_reservation", "pending_effect", "receipt_approval", "late_cancel"} {
			t.Run(mode, func(t *testing.T) {
				admission := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 100+index)
				run := admission["run_id"].(string)
				admitted, err := orderedProgressionCall(ctx, worker, "admit", admission)
				if err != nil {
					t.Fatal(err)
				}
				steps := admitted["step_ids"].([]any)
				step0, step1 := steps[0].(string), steps[1].(string)
				request := orderedProgressionRequest(o, w, e, run, step1, "progress", "ordered-progress-worker", 3)
				connection := worker
				if mode == "approve_first" || mode == "early_approval" || mode == "self_approval" || mode == "fresh_auth" || mode == "expired_approval" || mode == "reject" {
					request = orderedProgressionRequest(o, w, e, run, step0, "approve", orderedProgressionApprover, 3)
					connection = api
				}
				switch mode {
				case "early_approval":
					request["step_id"] = step1
				case "self_approval":
					request["actor_id"] = actor
				case "stale_version":
					request["run_version"] = 2
				case "foreign_scope":
					request["organization_id"] = "pid_9a000001-0000-4000-8000-000000000001"
				case "fresh_auth":
					request["fresh_auth_at"] = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339Nano)
				case "reject":
					request["operation"] = "reject"
				case "cancel":
					request["operation"] = "cancel"
					request["actor_id"] = orderedProgressionApprover
					connection = api
				}
				mutations := map[string]string{
					"expired_approval": `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
					"expired_plan":     `UPDATE zasp_security_agent_run_budgets SET deadline_at=started_at+interval '1 microsecond' WHERE run_id=$1`,
					"stopped":          `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`,
					"failed":           `UPDATE zasp_security_agent_steps SET state='failed' WHERE run_id=$1 AND step_index=0`,
					"unknown":          `UPDATE zasp_security_agent_steps SET state='inconclusive' WHERE run_id=$1 AND step_index=0`,
					"cancelled":        `UPDATE zasp_security_agent_runs SET state='cancelled',completed_at=clock_timestamp() WHERE run_id=$1`,
				}
				if q := mutations[mode]; q != "" {
					if _, err = owner.Exec(ctx, q, run); err != nil {
						t.Fatal(err)
					}
				}
				withApplication := mode == "receipt" || mode == "receipt_replay" || mode == "inactive_control" || mode == "expired_control" || mode == "changed_control" || mode == "changed_deployment" || mode == "missing_reservation" || mode == "pending_effect" || mode == "receipt_approval" || mode == "late_cancel"
				if withApplication {
					approve := orderedProgressionRequest(o, w, e, run, step0, "approve", orderedProgressionApprover, 3)
					if _, err = orderedProgressionCall(ctx, api, "transition", approve); err != nil {
						t.Fatal(err)
					}
					seedOrderedApplicationAuthority(t, ctx, owner, o, w, e, run, step0)
					request["run_version"] = 4
					q := map[string]string{
						"inactive_control":    `UPDATE zasp_security_agent_controls SET state='disabled' WHERE run_id=$1`,
						"expired_control":     `UPDATE zasp_security_agent_controls SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
						"changed_control":     `UPDATE zasp_security_agent_controls SET version=version+1 WHERE run_id=$1`,
						"changed_deployment":  `UPDATE zasp_policy_deployment_work SET applied_generation=0 WHERE device_id=(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
						"missing_reservation": `DELETE FROM zasp_security_agent_step_reservations WHERE run_id=$1`,
						"pending_effect":      `UPDATE zasp_security_agent_effects SET state='pending' WHERE run_id=$1`,
					}[mode]
					if q != "" {
						if _, err = owner.Exec(ctx, q, run); err != nil {
							t.Fatal(err)
						}
					}
				}
				before := orderedAdmissionSnapshot(t, ctx, owner, run)
				got, err := orderedProgressionCall(ctx, connection, "transition", request)
				refuse := mode == "early_approval" || mode == "self_approval" || mode == "stale_version" || mode == "foreign_scope" || mode == "fresh_auth" || mode == "expired_approval" || mode == "inactive_control" || mode == "expired_control" || mode == "changed_control" || mode == "changed_deployment" || mode == "missing_reservation" || mode == "pending_effect"
				if refuse {
					if err == nil {
						t.Fatal("unsafe transition accepted", got)
					}
					if after := orderedAdmissionSnapshot(t, ctx, owner, run); after != before {
						t.Fatal("refusal changed durable authority")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := "waiting"
				switch mode {
				case "approve_first":
					want = "approved"
				case "expired_plan", "stopped", "failed", "unknown", "cancelled", "reject", "cancel":
					want = "blocked"
				case "receipt", "receipt_replay", "receipt_approval", "late_cancel":
					want = "ready"
				}
				if got["outcome"] != want {
					t.Fatalf("outcome=%v want=%s", got, want)
				}
				if mode == "receipt_replay" || mode == "approve_first" {
					snapshot := orderedAdmissionSnapshot(t, ctx, owner, run)
					restarted, err := pgx.ConnectConfig(ctx, connection.Config().Copy())
					if err != nil {
						t.Fatal(err)
					}
					replayed, err := orderedProgressionCall(ctx, restarted, "transition", request)
					restarted.Close(ctx)
					if err != nil || replayed["run_version"] != got["run_version"] {
						t.Fatal("restart replay", replayed, err)
					}
					if orderedAdmissionSnapshot(t, ctx, owner, run) != snapshot {
						t.Fatal("restart duplicated transition")
					}
				}
				if mode == "receipt_approval" {
					next := orderedProgressionRequest(o, w, e, run, step1, "approve", orderedProgressionApprover, 5)
					got, err = orderedProgressionCall(ctx, api, "transition", next)
					if err != nil || got["step_state"] != "authorized" {
						t.Fatal("ready successor approval", got, err)
					}
				}
				if mode == "late_cancel" {
					next := orderedProgressionRequest(o, w, e, run, step1, "cancel", orderedProgressionApprover, 5)
					if _, err = orderedProgressionCall(ctx, api, "transition", next); err != nil {
						t.Fatal(err)
					}
					next = orderedProgressionRequest(o, w, e, run, step1, "progress", "ordered-progress-worker", 6)
					got, err = orderedProgressionCall(ctx, worker, "transition", next)
					if err != nil || got["run_state"] != "cancelled" {
						t.Fatal("terminal parent reopened", got, err)
					}
					var cleanup bool
					if err = owner.QueryRow(ctx, `SELECT state='cleanup_pending' FROM zasp_security_agent_effects WHERE run_id=$1`, run).Scan(&cleanup); err != nil || !cleanup {
						t.Fatal("cancellation suppressed cleanup", cleanup, err)
					}
				}
				var approvals, effects, reservations int
				var successor string
				if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1 AND step_id=$2),(SELECT count(*) FROM zasp_security_agent_step_reservations WHERE run_id=$1 AND step_id=$2),(SELECT state FROM zasp_security_agent_steps WHERE run_id=$1 AND step_id=$2)`, run, step1).Scan(&approvals, &effects, &reservations, &successor); err != nil {
					t.Fatal(err)
				}
				if effects != 0 || reservations != 0 {
					t.Fatal("dormant authority dispatched successor")
				}
				if want == "ready" && approvals != 2 {
					t.Fatal("successor approval absent or duplicated", approvals)
				}
				if want != "ready" && approvals != 1 {
					t.Fatal("blocked successor gained approval", approvals)
				}
				if mode == "approve_first" && successor != "queued" {
					t.Fatal("first approval authorized successor", successor)
				}
				if mode == "approve_first" {
					var legacy json.RawMessage
					if err = worker.QueryRow(ctx, `SELECT zasp_security_agent_claim_runs_v23('ordered-worker','legacy-claim-lease',30,25)`).Scan(&legacy); err == nil && strings.Contains(string(legacy), run) {
						t.Fatal("legacy worker claimed dormant approved plan")
					}
					if err = worker.QueryRow(ctx, `SELECT zasp_security_agent_execute_run_v22($1,$2,$3,$4,'ordered-worker','ordered-admission-lease',$5,$6)`, o, w, e, run, admitted["approval_id"], admitted["dependency_id"]).Scan(&legacy); err == nil {
						t.Fatal("legacy worker executed dormant approved plan")
					}
				}
			})
		}
	})
}

const orderedProgressionApprover = "pid_8c000004-0000-4000-8000-000000000004"

func runOrderedProgressionFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string)) {
	t.Helper()
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner, _ := migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: owner, t: t})
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(ctx)
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'ordered-progression-org','ordered-progression-approver','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Ordered progression','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, orderedProgressionApprover); err != nil {
			t.Fatal(err)
		}
		exercise(ctx, owner, worker, api, o, w, e, testID, actor)
	})
}

func orderedProgressionRequest(o, w, e, r, s, operation, actor string, version int) map[string]any {
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": operation, "actor_id": actor, "run_version": version, "approval_version": 1, "fresh_auth_at": time.Now().UTC().Format(time.RFC3339Nano)}
}

func orderedProgressionCall(ctx context.Context, connection *pgx.Conn, function string, request map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(request)
	var result []byte
	var err error
	if function == "transition" {
		database, buildErr := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if buildErr != nil {
			return nil, buildErr
		}
		repository := &securityAgentMultistepAdmissionRepository{database: database}
		result, err = repository.transition(ctx, json.RawMessage(raw))
	} else {
		err = connection.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.`+function+`($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&result)
	}
	var got map[string]any
	if err == nil {
		err = json.Unmarshal(result, &got)
	}
	return got, err
}

func seedOrderedApplicationAuthority(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, r, s string) {
	t.Helper()
	// The canonical deployment identity binds each verified target's device,
	// credential, sequence, policy version, generation, and envelope digest.
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Ordered authority fixture','active');
 INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),digest(convert_to($4,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour');
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$4,$4,decode(repeat('03',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-01',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',clock_timestamp());
 INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,outcome_id,result_digest) SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,'cleanup_pending',$4,digest(input_digest||decode(repeat('ab',32),'hex'),'sha256') FROM zasp_security_agent_steps WHERE run_id=$4 AND step_id=$5;
 INSERT INTO zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest FROM zasp_security_agent_steps WHERE run_id=$4 AND step_id=$5;
 UPDATE zasp_security_agent_steps SET state='succeeded',version=version+1 WHERE run_id=$4 AND step_id=$5;
 INSERT INTO zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version,state,key_id,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest,stored_at,verified_at,desired_generation) VALUES($1,$2,$3,$4,$5,'apply',$4,$4,1,1,'verified','fixture-key-01',transaction_timestamp(),transaction_timestamp()+interval '10 minutes','closed',decode(repeat('ab',32),'hex'),'[]',decode(repeat('ab',64),'hex'),decode(repeat('ab',32),'hex'),transaction_timestamp(),transaction_timestamp(),1);
 UPDATE zasp_policy_deployment_work SET applied_generation=desired_generation WHERE device_id=$4;
 INSERT INTO zasp_security_agent_controls(organization_id,workspace_id,environment_id,control_id,run_id,step_id,action_key,target_id,state,expires_at) VALUES($1,$2,$3,$4,$4,$5,'create_temporary_policy',$3,'active',transaction_timestamp()+interval '10 minutes');
 INSERT INTO zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body)
 SELECT fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id,p.plan_hash,fx.step_id,fx.action_key,fx.input_digest,fx.result_digest,'temporary_policy_applied.v1',1,jsonb_build_object('deployment_id',zasp_discovery_canonical_id($1,$2,$3,'security_agent_ordered_deployment',$4||chr(31)||$5||chr(31)||encode(digest(convert_to(jsonb_build_array(jsonb_build_array($4,$4,1,1,1,repeat('ab',32)))::text,'UTF8'),'sha256'),'hex')),'control_id',$4,'control_version',1,'outcome_id',fx.outcome_id,'applied_at',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char((transaction_timestamp()+interval '10 minutes') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM zasp_security_agent_effects fx JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE fx.run_id=$4 AND fx.step_id=$5`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, s); err != nil {
		t.Fatal(err)
	}
}
