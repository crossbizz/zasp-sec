package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionRedTeamTargetRejectsAuthoritativeProductionEnvironment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_e2e"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook, runner.UpProductionRuntimeQueueReplay} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, migrations.ProductionRedTeamSafety().UpSQL()); err != nil {
		t.Fatal(err)
	}
	var candidate string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_red_team_safety_live_fingerprint()`).Scan(&candidate); err != nil {
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if candidate != migrations.ProductionRedTeamSafetySemanticFingerprint() {
		t.Fatalf("candidate v37 fingerprint=%s", candidate)
	}
	if err := runner.UpProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	const org = "pid_10000001-0000-4000-8000-000000000001"
	const workspace = "pid_10000002-0000-4000-8000-000000000002"
	const environment = "pid_10000003-0000-4000-8000-000000000003"
	const target = "pid_94000001-0000-4000-8000-000000000001"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Red Team safety proof','staging') ON CONFLICT(organization_id,workspace_id,id) DO UPDATE SET environment_class='staging'`, org, workspace, environment); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
VALUES($1,$2,$3,$4,'agent_endpoint','Red Team safety target','active',transaction_timestamp(),transaction_timestamp(),'agent',transaction_timestamp(),transaction_timestamp()+interval '1 hour',jsonb_build_object('red_team',jsonb_build_object('enabled',true,'endpoint','https://adapter.customer.example/v1/evaluate','credential_reference','ref:red-team/safety_proof_0001','target_kinds',jsonb_build_array('agent_endpoint'))))`, org, workspace, environment, target); err != nil {
		t.Fatal(err)
	}
	validTarget := func() bool {
		t.Helper()
		var valid bool
		if err := connection.QueryRow(ctx, `SELECT zasp_red_team_target_valid($1,$2,$3,$4,'agent_endpoint')`, org, workspace, environment, target).Scan(&valid); err != nil {
			t.Fatal(err)
		}
		return valid
	}
	if !validTarget() {
		t.Fatal("fresh configured staging target rejected")
	}
	const safety = `{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}`
	allowed := func() bool {
		t.Helper()
		var value bool
		if err := connection.QueryRow(ctx, `SELECT zasp_red_team_safety_authorized($1,$2,$3,$4,'agent_endpoint',$5::jsonb)`, org, workspace, environment, target, safety).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if allowed() {
		t.Fatal("unregistered credential authorized")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_attack_lab_credential_bindings(organization_id,workspace_id,environment_id,binding_id,target_id,credential_reference,credential_class,version,reference_digest,state,created_at,valid_until) VALUES($1,$2,$3,'pid_94000002-0000-4000-8000-000000000002',$4,'ref:red-team/safety_proof_0001','read_only',1,decode(repeat('ab',32),'hex'),'active',transaction_timestamp()-interval '1 day',transaction_timestamp()+interval '1 hour')`, org, workspace, environment, target); err != nil {
		t.Fatal(err)
	}
	if !allowed() {
		t.Fatal("exact trusted staging credential rejected")
	}
	for _, check := range []struct{ name, mutate, restore string }{
		{"environment mismatch", `UPDATE zasp_environments SET environment_class='test' WHERE id=$3`, `UPDATE zasp_environments SET environment_class='staging' WHERE id=$3`},
		{"credential class mismatch", `UPDATE zasp_attack_lab_credential_bindings SET credential_class='test_write' WHERE environment_id=$3`, `UPDATE zasp_attack_lab_credential_bindings SET credential_class='read_only' WHERE environment_id=$3`},
		{"revoked credential", `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE environment_id=$3`, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE environment_id=$3`},
		{"expired credential", `UPDATE zasp_attack_lab_credential_bindings SET valid_until=transaction_timestamp()-interval '1 minute' WHERE environment_id=$3`, `UPDATE zasp_attack_lab_credential_bindings SET valid_until=transaction_timestamp()+interval '1 hour' WHERE environment_id=$3`},
		{"credential reference drift", `UPDATE zasp_attack_lab_credential_bindings SET credential_reference='ref:red-team/changed_ref_0001' WHERE environment_id=$3`, `UPDATE zasp_attack_lab_credential_bindings SET credential_reference='ref:red-team/safety_proof_0001' WHERE environment_id=$3`},
		{"stale discovery", `UPDATE zasp_inventory_entities SET first_seen_at=transaction_timestamp()-interval '2 hours',last_seen_at=transaction_timestamp()-interval '1 hour',observed_at=transaction_timestamp()-interval '1 hour',fresh_until=transaction_timestamp()-interval '1 minute' WHERE id=$4`, `UPDATE zasp_inventory_entities SET last_seen_at=transaction_timestamp(),observed_at=transaction_timestamp(),fresh_until=transaction_timestamp()+interval '1 hour' WHERE id=$4`},
	} {
		t.Run(check.name, func(t *testing.T) {
			// Parameter types are explicit even for unused scope components.
			for index, sql := range []string{check.mutate, check.restore} {
				if _, err := connection.Exec(ctx, `WITH scope AS(SELECT $1::text,$2::text,$3::text,$4::text) `+sql, org, workspace, environment, target); err != nil {
					t.Fatal(err)
				}
				if index == 0 && allowed() {
					t.Fatal("unsafe authority accepted")
				}
			}
			if !allowed() {
				t.Fatal("restored authority rejected")
			}
		})
	}
	for _, principal := range []string{"safety_api", "safety_agent_worker", "safety_red_worker", "safety_outbox", "safety_adapter"} {
		if _, err := connection.Exec(ctx, `CREATE ROLE `+pgx.Identifier{principal}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_security_agent_register_principals('zasp_e2e','safety_api','safety_agent_worker'); SELECT zasp_red_team_register_principals('zasp_e2e','safety_red_worker','safety_outbox','safety_adapter')`); err != nil {
		t.Fatal(err)
	}
	connect := func(principal string) *pgx.Conn {
		t.Helper()
		config := connection.Config().Copy()
		config.User = principal
		value, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { value.Close(context.Background()) })
		return value
	}
	api, worker := connect("safety_api"), connect("safety_red_worker")
	const definition = "pid_94000003-0000-4000-8000-000000000003"
	const run = "pid_94000004-0000-4000-8000-000000000004"
	const actor = "pid_94000005-0000-4000-8000-000000000005"
	const correlation = "pid_94000006-0000-4000-8000-000000000006"
	var result json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_red_team_create_definition($1,$2,$3,$4,'safety-create-0001',$5,'Safety proof',$6,'agent_endpoint','["prompt_injection"]'::jsonb,$7::jsonb,$8)`, org, workspace, environment, actor, definition, target, safety, correlation).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,'safety-run-000001',$5,1,$6,$7)`, org, workspace, environment, actor, definition, run, correlation).Scan(&result); err != nil || !bytes.Contains(result, []byte(`"status": "queued"`)) {
		t.Fatalf("safe queue result=%s err=%v", result, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE environment_id=$1`, environment); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'safety-worker',$5,60)`, org, workspace, environment, run, bytes.Repeat([]byte{'a'}, 32)).Scan(&result); err == nil {
		t.Fatal("worker claimed after credential revocation")
	}
	var state string
	var attempt int
	if err := connection.QueryRow(ctx, `SELECT state,attempt FROM zasp_red_team_runs WHERE run_id=$1`, run).Scan(&state, &attempt); err != nil || state != "queued" || attempt != 0 {
		t.Fatalf("denied claim mutated run: %s/%d %v", state, attempt, err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_red_team_update_definition($1,$2,$3,$4,'safety-update-001',$5,1,'Safety proof',$6,'agent_endpoint','["prompt_injection"]'::jsonb,$7::jsonb,true,$8)`, org, workspace, environment, actor, definition, target, safety, correlation).Scan(&result); err == nil {
		t.Fatal("update accepted revoked credential")
	}
	if err := api.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,'safety-run-000002',$5,1,'pid_94000007-0000-4000-8000-000000000007',$6)`, org, workspace, environment, actor, definition, correlation).Scan(&result); err == nil {
		t.Fatal("queue accepted revoked credential")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE environment_id=$1`, environment); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'safety-worker',$5,60)`, org, workspace, environment, run, bytes.Repeat([]byte{'a'}, 32)).Scan(&result); err != nil || !bytes.Contains(result, []byte(`"disposition": "claimed"`)) {
		t.Fatalf("safe claim result=%s err=%v", result, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_environments SET environment_class='production' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, org, workspace, environment); err != nil {
		t.Fatal(err)
	}
	if validTarget() {
		t.Fatal("production target remained eligible despite authoritative production environment")
	}
	if allowed() {
		t.Fatal("production environment authorized")
	}
	if err := runner.DownProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_queue_replay_live_fingerprint()`).Scan(&candidate); err != nil || candidate != migrations.ProductionRuntimeQueueReplaySemanticFingerprint() {
		t.Fatalf("rollback fingerprint=%s err=%v", candidate, err)
	}
	if !validTarget() {
		t.Fatal("rollback did not restore exact prior target semantics")
	}
	if err := runner.UpProductionRedTeamSafety(ctx); err != nil {
		t.Fatal(err)
	}
	if validTarget() {
		t.Fatal("reapply lost production protection")
	}
	for _, sql := range []string{
		`GRANT EXECUTE ON FUNCTION zasp_red_team_safety_authorized(text,text,text,text,text,jsonb) TO PUBLIC`,
		`DO $drift$ DECLARE body text;BEGIN SELECT pg_get_functiondef('zasp_red_team_safety_authorized(text,text,text,text,text,jsonb)'::regprocedure) INTO body; EXECUTE replace(body,'binding.valid_until>transaction_timestamp()','true');END $drift$`,
		`INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(38,'unknown_future',repeat('a',64))`,
	} {
		tx, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT zasp_production_red_team_safety_readiness($1,$2)`, migrations.ProductionRedTeamSafety().Checksum(), migrations.ProductionRedTeamSafetySemanticFingerprint()).Scan(&ready); err != nil || ready {
			tx.Rollback(ctx)
			t.Fatalf("drift readiness=%v err=%v", ready, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
