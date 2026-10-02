package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Real registered55/API-role writes, not an HTTP capability substitute.
func TestSecurityAgentExistingTestVersionedDefinitionPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, definition, actor string) {
		exerciseSecurityAgentExistingTestDefinition(t, ctx, owner, api, org, ws, env, definition, actor, true)
		runner := precisionMigrationRunner(t, owner)
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("used versioned release rolled back")
		}
		if version, err := runner.Version(ctx); err != nil || version != 55 {
			t.Fatalf("refused rollback changed release: %d %v", version, err)
		}
	})
}

func runVersionedExistingTestFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string, string), starters ...func(*testing.T) string) {
	t.Helper()
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const ws = "pid_6a000002-0000-4000-8000-000000000002"
		const env = "pid_6a000003-0000-4000-8000-000000000003"
		const target = "pid_89000011-0000-4000-8000-000000000001"
		const definition = "pid_89000012-0000-4000-8000-000000000002"
		const actor = "pid_89000014-0000-4000-8000-000000000004"
		if _, err := owner.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3);
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 VALUES($1,$2,$3,$4,'agent_endpoint','Versioned draft target','active',now(),now(),'agent',now(),now()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/versioned_draft_0001","target_kinds":["agent_endpoint"]}}');
 SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,'pid_89000013-0000-4000-8000-000000000003',$4,'ref:red-team/versioned_draft_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 VALUES($1,$2,$3,$5,'Versioned draft test',$4,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$6)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, target, definition, actor); err != nil {
			t.Fatal(err)
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
		exercise(ctx, owner, api, org, ws, env, definition, actor)
	}, starters...)
}

func TestSecurityAgentExistingTestVersionedCutoverPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		const agentID = "pid_89000051-0000-4000-8000-000000000001"
		body := map[string]any{"id": agentID, "name": "Cutover draft", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{env}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 1, "allowed_actions": []string{"run_test"}, "verification_kind": "test_run", "definition_version": 1, "enabled": false, "existing_test": map[string]any{"definition_id": testID, "definition_version": 1}}
		stored, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		delete(body, "id")
		intent, err := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
		if err != nil {
			t.Fatal(err)
		}
		write := func() error {
			var result json.RawMessage
			return api.QueryRow(ctx, postgresSecurityAgentExistingTestDefinitionMutateSQL, "create", agentID, org, ws, env, actor, "createSecurityAgent", "existing-test-cutover-0001", int64(0), intent, stored, "pid_89000052-0000-4000-8000-000000000001", "pid_89000053-0000-4000-8000-000000000001", "pid_89000054-0000-4000-8000-000000000001", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&result)
		}
		assertAbsent := func() {
			t.Helper()
			var absent bool
			if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE definition_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_definition_versions WHERE definition_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_workflow_records WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_workflow_receipts WHERE resource_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_workflow_audit WHERE resource_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_workflow_idempotency WHERE idempotency_key='existing-test-cutover-0001')`, agentID).Scan(&absent); err != nil || !absent {
				t.Fatalf("refused write left state: absent=%v err=%v", absent, err)
			}
		}
		runner := precisionMigrationRunner(t, owner)
		// Rollback wins before a previously validated request reaches SQL.
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		var pg *pgconn.PgError
		if err := write(); !errors.As(err, &pg) || pg.Code != "42883" {
			t.Fatalf("post-rollback write did not fail at missing55 authority: %v", err)
		}
		assertAbsent()
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		// The rollback's relation lock is already held when the write arrives.
		if _, err := owner.Exec(ctx, "BEGIN; LOCK TABLE public.zasp_workflow_records IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatal(err)
		}
		denied := write()
		if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		if !errors.As(denied, &pg) || pg.Code != "55P03" {
			t.Fatalf("write crossed cutover lock: %v", denied)
		}
		assertAbsent()
		// Mutation wins and retains its fence until commit. Registered rollback
		// must refuse while that real write transaction remains open.
		if _, err := api.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer api.Exec(context.Background(), "ROLLBACK")
		if err := write(); err != nil {
			t.Fatal(err)
		}
		var fenced bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=3 FROM pg_locks WHERE pid=$1 AND granted AND mode='RowExclusiveLock' AND relation IN ('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_definitions'::regclass,'public.zasp_security_agent_definition_versions'::regclass)`, api.PgConn().PID()).Scan(&fenced); err != nil || !fenced {
			t.Fatalf("write fence absent: %v %v", fenced, err)
		}
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("rollback crossed open mutation")
		}
		if _, err := api.Exec(ctx, "COMMIT"); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("rollback removed committed draft history")
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT d.body=$2::jsonb AND d.version=1 AND v.definition=d.body AND v.actor_id=$3 FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions v USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE d.definition_id=$1`, agentID, stored, actor).Scan(&exact); err != nil || !exact {
			t.Fatalf("committed cutover draft changed: %v %v", exact, err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 55 {
			t.Fatalf("cutover changed55: %d %v", version, err)
		}
	})
}
