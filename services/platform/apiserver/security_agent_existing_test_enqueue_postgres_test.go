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

// A shared core must preserve the public enqueue behavior without opening a
// second direct entry point to API or worker roles. This is candidate SQL on a
// registered54 fixture, not registered55 or deployment acceptance.
func TestSecurityAgentExistingTestEnqueueCorePostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		var originalFunction string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure)`).Scan(&originalFunction); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, migrations.SecurityAgentExistingTestEnqueueCandidateSQL()); err != nil {
			t.Fatal(err)
		}
		var savedExact bool
		if err := owner.QueryRow(ctx, `SELECT replace(pg_get_functiondef('zasp_existing_tests_predecessor.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure),'FUNCTION zasp_existing_tests_predecessor.zasp_red_team_run_test(','FUNCTION public.zasp_red_team_run_test(')=$1`, originalFunction).Scan(&savedExact); err != nil || !savedExact {
			t.Fatalf("predecessor body not retained exactly: %v", err)
		}
		for _, identity := range []string{
			"public.zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text)",
			"public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text)",
			"public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)",
			"zasp_existing_tests_predecessor.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)",
		} {
			var safe bool
			if err := owner.QueryRow(ctx, `SELECT proowner='zasp_discovery_authority'::regrole AND prosecdef AND proconfig=ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',oid,'EXECUTE') AND NOT has_function_privilege('security_agent_v33_api_login',oid,'EXECUTE') AND NOT has_function_privilege('security_agent_v33_worker_login',oid,'EXECUTE') FROM pg_proc WHERE oid=$1::regprocedure`, identity).Scan(&safe); err != nil || !safe {
				t.Fatalf("unsafe private identity %s: %v", identity, err)
			}
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const ws = "pid_6a000002-0000-4000-8000-000000000002"
		const env = "pid_6a000003-0000-4000-8000-000000000003"
		const target = "pid_89000011-0000-4000-8000-000000000001"
		const definition = "pid_89000012-0000-4000-8000-000000000002"
		const actor = "pid_89000014-0000-4000-8000-000000000004"
		const runID = "pid_89000015-0000-4000-8000-000000000005"
		const correlation = "pid_89000016-0000-4000-8000-000000000006"
		const signature = "public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text)"
		var private bool
		if err := owner.QueryRow(ctx, `SELECT NOT has_function_privilege('public',$1,'EXECUTE')`, signature).Scan(&private); err != nil || !private {
			t.Fatalf("core not installed privately: %v", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3);
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 VALUES($1,$2,$3,$4,'agent_endpoint','Shared core target','active',now(),now(),'agent',now(),now()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/shared_core_0001","target_kinds":["agent_endpoint"]}}');
 SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,'pid_89000013-0000-4000-8000-000000000003',$4,'ref:red-team/shared_core_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 VALUES($1,$2,$3,$5,'Shared core test',$4,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$6)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, target, definition, actor); err != nil {
			t.Fatal(err)
		}
		connect := func(login string) *pgx.Conn {
			t.Helper()
			config, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			config.User = login
			conn, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close(context.Background()) })
			return conn
		}
		api := connect("security_agent_v33_api_login")
		worker := connect("security_agent_v33_worker_login")
		var originalDefinition, originalTarget json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(d) FROM zasp_red_team_definitions d WHERE definition_id=$1`, definition).Scan(&originalDefinition); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(e) FROM zasp_inventory_entities e WHERE id=$1`, target).Scan(&originalTarget); err != nil {
			t.Fatal(err)
		}
		args := []any{org, ws, env, actor, "existing-test-core-0001", definition, int64(1), runID, correlation}
		for _, conn := range []*pgx.Conn{api, worker} {
			_, err := conn.Exec(ctx, `SELECT zasp_security_agent_test_enqueue_core($1,$2,$3,$4,$5,$6,$7,$8,$9)`, args...)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("private core direct call=%v", err)
			}
			_, err = conn.Exec(ctx, `SELECT zasp_security_agent_test_link_enqueue($1,$2,$3,$4,$5,$6)`, org, ws, env, runID, definition, correlation)
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("private link direct call=%v", err)
			}
			_, err = conn.Exec(ctx, `SELECT * FROM zasp_security_agent_test_links`)
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("private link table read=%v", err)
			}
		}
		var first, replay json.RawMessage
		const enqueue = `SELECT zasp_red_team_run_test($1,$2,$3,$4,$5,$6,$7,$8,$9)`
		if err := api.QueryRow(ctx, enqueue, args...).Scan(&first); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, enqueue, args...).Scan(&replay); err != nil {
			t.Fatal(err)
		}
		var equal bool
		if err := owner.QueryRow(ctx, `SELECT ($1::jsonb-'replayed')=($2::jsonb-'replayed') AND $1::jsonb->'replayed'='false'::jsonb AND $2::jsonb->'replayed'='true'::jsonb`, first, replay).Scan(&equal); err != nil || !equal {
			t.Fatalf("non-identical replay: %s %s %v", first, replay, err)
		}
		var runs, outbox, receipts int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_red_team_runs WHERE run_id=$1),(SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1),(SELECT count(*) FROM zasp_red_team_request_receipts WHERE resource_id=$1)`, runID).Scan(&runs, &outbox, &receipts); err != nil || runs != 1 || outbox != 1 || receipts != 1 {
			t.Fatalf("enqueue counts=%d/%d/%d: %v", runs, outbox, receipts, err)
		}
		_, err := worker.Exec(ctx, enqueue, args...)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("worker public enqueue=%v", err)
		}
		// A changed selected version must conflict with the original receipt.
		args[6] = int64(2)
		_, err = api.Exec(ctx, enqueue, args...)
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("changed intent replay=%v", err)
		}
		for _, tc := range []struct {
			name, change, restore string
			index                 int
			value                 any
		}{
			{name: "stale_version", index: 6, value: int64(2)},
			{name: "foreign_workspace", index: 1, value: "pid_9a000002-0000-4000-8000-000000000002"},
			{name: "foreign_environment", index: 2, value: "pid_9a000003-0000-4000-8000-000000000003"},
			{name: "revoked_credential", change: `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE target_id=$1`, restore: `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE target_id=$1`},
			{name: "disabled_test", change: `UPDATE zasp_red_team_definitions SET enabled=false WHERE target_id=$1`, restore: `UPDATE zasp_red_team_definitions SET enabled=true WHERE target_id=$1`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if tc.change != "" {
					if _, err := owner.Exec(ctx, tc.change, target); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := owner.Exec(ctx, tc.restore, target); err != nil {
							t.Error(err)
						}
					}()
				}
				invalid := []any{org, ws, env, actor, "existing-test-denied-" + tc.name, definition, int64(1), "pid_89000017-0000-4000-8000-000000000007", correlation}
				if tc.value != nil {
					invalid[tc.index] = tc.value
				}
				_, err := api.Exec(ctx, enqueue, invalid...)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "P0002" {
					t.Fatalf("unsafe new enqueue accepted: %v", err)
				}
			})
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT to_jsonb(d) FROM zasp_red_team_definitions d WHERE definition_id=$1)=$2::jsonb AND (SELECT to_jsonb(e) FROM zasp_inventory_entities e WHERE id=$3)=$4::jsonb`, definition, originalDefinition, target, originalTarget).Scan(&equal); err != nil || !equal {
			t.Fatalf("enqueue changed existing definition/target: %v", err)
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_red_team_runs WHERE definition_id=$1),(SELECT count(*) FROM zasp_red_team_outbox WHERE payload->>'definition_id'=$1),(SELECT count(*) FROM zasp_red_team_request_receipts WHERE resource_id IN($2,$3))`, definition, runID, "pid_89000017-0000-4000-8000-000000000007").Scan(&runs, &outbox, &receipts); err != nil || runs != 1 || outbox != 1 || receipts != 1 {
			t.Fatalf("denials created work: %d/%d/%d %v", runs, outbox, receipts, err)
		}
		t.Run("durable_link", func(t *testing.T) {
			exerciseSecurityAgentExistingTestLink(t, ctx, owner, org, ws, env, definition, target, actor)
		})
		t.Run("guarded_dispatch", func(t *testing.T) {
			exerciseSecurityAgentExistingTestDispatch(t, ctx, owner, worker, org, ws, env, definition, target, actor)
		})
		t.Run("definition_binding", func(t *testing.T) {
			exerciseSecurityAgentExistingTestDefinition(t, ctx, owner, api, org, ws, env, definition, actor, false)
		})
	})
}
