package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Owner-seeded histories exercise the real scoped SQL/API-role projection. They
// do not claim actual provider execution, policy application or a live tenant.
func TestSecurityAgentActionDetailsRegisteredPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,attempt)
SELECT organization_id,workspace_id,environment_id,'pid_78000006-0000-4000-8000-000000000006',definition_id,definition_version,'pid_6a000005-0000-4000-8000-000000000005','action-detail-fixture','running',1 FROM zasp_security_agent_definitions`,
			`INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,decode(repeat('c',64),'hex'),'security-agent-actions-v1',body,digest(convert_to(body::text,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour'
FROM zasp_security_agent_runs CROSS JOIN LATERAL (SELECT jsonb_build_object('steps',jsonb_build_array(
 jsonb_build_object('index',0,'step_id','pid_78000010-0000-4000-8000-000000000010','action','update_finding_response','target_id',trigger_id,'expected_version',2,'target_status','under_review','credential','protected-action-sentinel'),
 jsonb_build_object('index',1,'step_id','pid_78000011-0000-4000-8000-000000000011','action','create_temporary_policy','target_id',environment_id,'mode','block','scope',environment_id,'ttl_seconds',120,'raw_policy','protected-action-sentinel'),
 jsonb_build_object('index',2,'step_id','pid_78000012-0000-4000-8000-000000000012','action','isolate_session','target_id','pid_78000020-0000-4000-8000-000000000020','session_id','pid_78000020-0000-4000-8000-000000000020','device_id','pid_78000021-0000-4000-8000-000000000021','scope',environment_id,'ttl_seconds',300,'authorization_header','protected-action-sentinel'),
 jsonb_build_object('index',3,'step_id','pid_78000013-0000-4000-8000-000000000013','action','revoke_integration_connection','target_id','pid_78000022-0000-4000-8000-000000000022','integration_id','pid_78000023-0000-4000-8000-000000000023','provider_url','protected-action-sentinel','token','protected-action-sentinel')
)) body) fixture WHERE run_id='pid_78000006-0000-4000-8000-000000000006'`,
			`UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id)`,
			`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
SELECT organization_id,workspace_id,environment_id,run_id,s->>'step_id',(s->>'index')::integer,s->>'action',plan_hash,'allow','authorized' FROM zasp_security_agent_plans CROSS JOIN LATERAL jsonb_array_elements(plan->'steps') s`,
		} {
			if _, err := owner.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_api_login"
		api, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		for _, prefix := range []string{"6a", "9a"} {
			org := "pid_" + prefix + "000001-0000-4000-8000-000000000001"
			workspace := "pid_" + prefix + "000002-0000-4000-8000-000000000002"
			environment := "pid_" + prefix + "000003-0000-4000-8000-000000000003"
			var raw json.RawMessage
			if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)`, org, workspace, environment, runContextTestRunID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Detail  json.RawMessage `json:"detail"`
				Actions json.RawMessage `json:"action_details"`
			}
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			detail, err := decodeSecurityAgentStoredRunDetail(envelope.Detail, runContextTestRunID)
			if err != nil {
				t.Fatal(err)
			}
			actions, err := decodeSecurityAgentActionDetails(envelope.Actions, detail)
			if err != nil || len(actions) != 4 {
				t.Fatal("registered authority omitted the four persisted action details", err)
			}
			if strings.Contains(string(raw), "protected-action-sentinel") || actions[0].Arguments.ExpectedVersion != 2 || actions[1].Arguments.Scope != environment || *actions[1].TTLSeconds != 120 || actions[2].Arguments.Scope != environment || *actions[2].TTLSeconds != 300 || actions[3].Arguments.IntegrationID != "pid_78000023-0000-4000-8000-000000000023" {
				t.Fatal("projection leaked protected arguments or crossed scoped plans")
			}
		}
		var raw json.RawMessage
		if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)`, "pid_6a000001-0000-4000-8000-000000000001", "pid_9a000002-0000-4000-8000-000000000002", "pid_9a000003-0000-4000-8000-000000000003", runContextTestRunID).Scan(&raw); err != pgx.ErrNoRows {
			t.Fatal("mixed scope returned private action details", err)
		}
		exerciseActionDetailAuthorityRefusals(t, ctx, owner, api)
		exerciseStoppedActionDetailCleanup(t, ctx, owner, api, dsn)
		exerciseActionDetailEnvironmentCollision(t, ctx, owner, api)
		exerciseApprovalContextProjection(t, ctx, owner, api)
	})
}

func exerciseStoppedActionDetailCleanup(t *testing.T, ctx context.Context, owner, api *pgx.Conn, dsn string) {
	t.Helper()
	const runID = "pid_78000094-0000-4000-8000-000000000094"
	for _, statement := range []string{
		`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,attempt)
SELECT organization_id,workspace_id,environment_id,'pid_78000094-0000-4000-8000-000000000094',definition_id,definition_version,trigger_id,'stopped-action-fixture','needs_human',1 FROM zasp_security_agent_runs WHERE run_id='pid_78000006-0000-4000-8000-000000000006'`,
		`INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
SELECT organization_id,workspace_id,environment_id,'pid_78000094-0000-4000-8000-000000000094',definition_id,definition_version,trigger_digest,catalog_version,body,digest(convert_to(body::text,'UTF8'),'sha256'),expires_at
FROM zasp_security_agent_plans CROSS JOIN LATERAL (SELECT jsonb_build_object('steps',jsonb_build_array(jsonb_set(plan->'steps'->1,'{index}','0'))) body) p WHERE run_id='pid_78000006-0000-4000-8000-000000000006'`,
		`UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id) AND r.run_id='pid_78000094-0000-4000-8000-000000000094'`,
		`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
SELECT organization_id,workspace_id,environment_id,run_id,plan->'steps'->0->>'step_id',0,'create_temporary_policy',plan_hash,'allow','inconclusive' FROM zasp_security_agent_plans WHERE run_id='pid_78000094-0000-4000-8000-000000000094'`,
		`INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,stop_reason)
SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,clock_timestamp(),'budget_deadline_exceeded' FROM zasp_security_agent_runs WHERE run_id='pid_78000094-0000-4000-8000-000000000094'`,
		`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) SELECT organization_id,workspace_id,environment_id,'pid_78000021-0000-4000-8000-000000000021','Owned action display fixture','active' FROM zasp_security_agent_definitions`,
		`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at)
SELECT organization_id,workspace_id,environment_id,'pid_78000031-0000-4000-8000-000000000031',id,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),digest(convert_to(organization_id,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour' FROM zasp_gateway_devices WHERE id='pid_78000021-0000-4000-8000-000000000021'`,
		`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at)
SELECT organization_id,workspace_id,environment_id,CASE WHEN organization_id='pid_6a000001-0000-4000-8000-000000000001' THEN 'pid_78000032-0000-4000-8000-000000000032' ELSE 'pid_79000032-0000-4000-8000-000000000032' END,device_id,id,digest(convert_to(organization_id,'UTF8'),'sha256'),'runtime-gateway','ref:gateway/public/action-fixture-key',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'action-fixture-key','Ed25519',clock_timestamp() FROM zasp_gateway_enrollment_tokens WHERE id='pid_78000031-0000-4000-8000-000000000031'`,
		`INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state)
SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,'pending' FROM zasp_security_agent_steps WHERE run_id='pid_78000094-0000-4000-8000-000000000094'`,
		`INSERT INTO zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,action_key,phase,device_id,credential_id,sequence,policy_version,state,key_id,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest,stored_at)
SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,'apply','pid_78000021-0000-4000-8000-000000000021',CASE WHEN organization_id='pid_6a000001-0000-4000-8000-000000000001' THEN 'pid_78000032-0000-4000-8000-000000000032' ELSE 'pid_79000032-0000-4000-8000-000000000032' END,10,10,'stored','action-fixture-key',clock_timestamp(),clock_timestamp()+interval '2 minutes','closed',decode(repeat('05',32),'hex'),'[]'::jsonb,decode(repeat('06',64),'hex'),decode(repeat('07',32),'hex'),clock_timestamp() FROM zasp_security_agent_effects WHERE run_id='pid_78000094-0000-4000-8000-000000000094'`,
		`CREATE ROLE action_detail_cleanup_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`,
	} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	var registered bool
	if err := owner.QueryRow(ctx, `SELECT zasp_security_agent_register_action_principal(session_user,'action_detail_cleanup_login')`).Scan(&registered); err != nil || !registered {
		t.Fatal("cleanup role registration failed", err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "action_detail_cleanup_login"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	var claimed json.RawMessage
	if err := worker.QueryRow(ctx, `SELECT zasp_security_agent_claim_session_policy_effects('action-detail-cleanup','action-detail-cleanup-lease',60,1)`).Scan(&claimed); err != nil {
		t.Fatal("assembled budget cleanup claim failed", err)
	}
	var leased, pending, missingOutcomes int
	if err := owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='leased'),count(*) FILTER(WHERE state='cleanup_pending'),count(*) FILTER(WHERE outcome_id IS NULL AND result_digest IS NULL) FROM zasp_security_agent_effects WHERE run_id=$1`, runID).Scan(&leased, &pending, &missingOutcomes); err != nil || leased != 1 || pending != 1 || missingOutcomes != 2 {
		t.Fatalf("actual stopped reclaim states leased=%d pending=%d missing=%d err=%v", leased, pending, missingOutcomes, err)
	}
	for _, prefix := range []string{"6a", "9a"} {
		var raw json.RawMessage
		if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)`, "pid_"+prefix+"000001-0000-4000-8000-000000000001", "pid_"+prefix+"000002-0000-4000-8000-000000000002", "pid_"+prefix+"000003-0000-4000-8000-000000000003", runID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		got, err := decodeSecurityAgentRunContextEnvelope(raw, runID)
		if err != nil || len(got.ActionDetails) != 1 || got.ActionDetails[0].Rollback.State != "pending" || got.ActionDetails[0].Verification.State != "pending" || got.ActionDetails[0].Result == nil || got.ActionDetails[0].Result.OutcomeID != "" {
			t.Fatal("real stopped partial cleanup was not readable without inventing success", err)
		}
	}
}
