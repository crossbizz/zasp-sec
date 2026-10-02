package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Calibration observes an owned fixture only. The runner always uses its
// compiled pin and never adopts a live fingerprint as authorization.
func TestSecurityAgentExistingTestCompiledFingerprintPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		metadata := migrations.ProductionSecurityAgentExistingTests()
		if _, err := owner.Exec(ctx, metadata.UpSQL()); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Position > 0 {
				position := int(pg.Position) - 1
				t.Logf("migration error near: %s", metadata.UpSQL()[max(0, position-180):min(len(metadata.UpSQL()), position+180)])
			}
			t.Fatalf("existing-test migration: %#v", err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_security_agent_existing_tests_checksum',$1),('production_security_agent_existing_tests_fingerprint',$2)`, metadata.Checksum(), migrations.SecurityAgentExistingTestsFingerprint()); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(55,$1,$2)`, metadata.Name(), metadata.Checksum()); err != nil {
			t.Fatal(err)
		}
		var live string
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_live_fingerprint()`).Scan(&live); err != nil {
			t.Fatal(err)
		}
		if live != migrations.SecurityAgentExistingTestsFingerprint() {
			t.Fatalf("compiled existing-test fingerprint differs: actual=%s", live)
		}
	})
}

func TestSecurityAgentExistingTestReleasePostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const lifecycleIdentity = `SELECT jsonb_agg(jsonb_build_object('body',pg_get_functiondef(p.oid),'owner',p.proowner::regrole::text,'acl',p.proacl::text) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid))::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_security_agent_activate','zasp_security_agent_simulate','zasp_red_team_cancel_run','zasp_red_team_claim_run','zasp_red_team_heartbeat_run','zasp_red_team_cancel_claimed_run','zasp_red_team_finish_run','zasp_red_team_finish_run_v38','zasp_red_team_retry_run','zasp_red_team_resolve_invocation')`
		var lifecycleBefore string
		if err := owner.QueryRow(ctx, lifecycleIdentity).Scan(&lifecycleBefore); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatalf("register existing-test release: %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 55 {
			t.Fatalf("registered version=%d err=%v", version, err)
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
		// A registered API caller with stale compiled pins must fail before any
		// underlying mutation, even if it can execute the legacy entrypoint.
		_, pinErr := api.Exec(ctx, `SELECT public.zasp_production_security_agent_existing_tests_mutate_definition('create','','','','','','createSecurityAgent','existing-test-stale-pins',0,'{}','{}','','','','wrong','wrong')`)
		var pinFailure *pgconn.PgError
		if !errors.As(pinErr, &pinFailure) || pinFailure.Code != "55000" || pinFailure.Message != "existing test definition release unavailable" {
			t.Fatalf("versioned draft did not reject stale authority: %v", pinErr)
		}
		_, pinErr = api.Exec(ctx, `SELECT public.zasp_production_security_agent_existing_tests_replay_definition('','','','','createSecurityAgent','existing-test-stale-pins','{}','wrong','wrong')`)
		if !errors.As(pinErr, &pinFailure) || pinFailure.Code != "55000" || pinFailure.Message != "existing test definition release unavailable" {
			t.Fatalf("versioned replay did not reject stale authority: %v", pinErr)
		}
		var ready bool
		for _, signature := range []string{
			"public.zasp_production_security_agent_existing_tests_invocation_resolve(text,text,text,text,text,text,bytea,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text)",
			"public.zasp_production_security_agent_existing_tests_invocation_complete(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text)",
		} {
			if err := owner.QueryRow(ctx, `SELECT has_function_privilege('zasp_red_team_adapter',$1,'EXECUTE') AND NOT has_function_privilege('public',$1,'EXECUTE') AND NOT has_function_privilege('zasp_red_team_worker',$1,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_api',$1,'EXECUTE')`, signature).Scan(&ready); err != nil || !ready {
				t.Fatalf("unsafe journal wrapper ACL %s: %v", signature, err)
			}
		}
		for _, signature := range []string{
			"public.zasp_production_security_agent_existing_tests_controls(text,text,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_set_control(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text)",
			"public.zasp_production_security_agent_existing_tests_replay_definition(text,text,text,text,text,text,jsonb,text,text)",
		} {
			if err := owner.QueryRow(ctx, `SELECT has_function_privilege('security_agent_v33_api_login',$1,'EXECUTE') AND NOT has_function_privilege('public',$1,'EXECUTE') AND NOT has_function_privilege('security_agent_v33_worker_login',$1,'EXECUTE')`, signature).Scan(&ready); err != nil || !ready {
				t.Fatalf("unsafe draft/replay ACL %s: %v", signature, err)
			}
		}
		if err := owner.QueryRow(ctx, `SELECT p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND has_function_privilege('security_agent_v33_worker_login',p.oid,'EXECUTE') AND NOT has_function_privilege('security_agent_v33_api_login',p.oid,'EXECUTE') AND NOT has_function_privilege('public',p.oid,'EXECUTE') FROM pg_proc p WHERE p.oid='public.zasp_production_security_agent_existing_tests_schedule(text,integer,text,text)'::regprocedure`).Scan(&ready); err != nil || !ready {
			t.Fatalf("scheduler boundary owner/ACL: %v", err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_client_ready($1,$2)`, migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("old54 client accepted55: ready=%v err=%v", ready, err)
		}
		for _, role := range []string{"public", "security_agent_v33_api_login", "security_agent_v33_worker_login"} {
			for _, signature := range []string{
				"public.zasp_production_security_agent_existing_tests_candidate_binding(text,text,text,jsonb,text)",
				"public.zasp_production_security_agent_existing_tests_controls_guard(text,text,text,text)",
				"public.zasp_production_security_agent_existing_tests_control_core(text,text,text,text,text,text,text,boolean,bigint,timestamptz,text,text,text)",
				"public.zasp_production_security_agent_existing_tests_trigger(text,text,text,text,text,text,bigint)",
				"public.zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)",
				"public.zasp_production_security_agent_existing_tests_invocation_start_core(text,text,text,text,bytea,text,bytea)",
				"public.zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text)",
				"public.zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint)",
				"public.zasp_production_security_agent_existing_tests_authorize_invocation(text,text,text,text,text)",
				"public.zasp_production_security_agent_existing_tests_invocation_complete_core(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea)",
				"public.zasp_production_security_agent_existing_tests_invocation_receipt(text,text,text,text,integer,text)",
				"public.zasp_production_security_agent_existing_tests_activate_core(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)",
				"public.zasp_production_security_agent_existing_tests_simulate_core(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text)",
				"public.zasp_production_security_agent_existing_tests_sim_evidence(text,text,text,jsonb)",
			} {
				if err := owner.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE')`, role, signature).Scan(&ready); err != nil || ready {
					t.Fatalf("private lifecycle core exposed to %s: %s %v", role, signature, err)
				}
			}
			if err := owner.QueryRow(ctx, `SELECT has_function_privilege($1,'public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text)','EXECUTE')`, role).Scan(&ready); err != nil || ready {
				t.Fatalf("incomplete invocation protocol exposed to %s: %v", role, err)
			}
		}
		for _, mutation := range []string{
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_admit(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean) TO zasp_security_agent_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_schedule(text,integer,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_resolve(text,text,text,text,text,text,bytea,text,text,text) TO zasp_security_agent_api`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_resolve(text,text,text,text,text,text,bytea,text,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text) TO zasp_security_agent_api`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_complete(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text) TO zasp_security_agent_api`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_complete(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_authorize_invocation(text,text,text,text,text) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_authorize_invocation(text,text,text,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text) TO zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint) TO zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text) RESET search_path`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text) FROM zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text) RESET search_path`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text) FROM zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) RESET search_path`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) FROM zasp_red_team_worker`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_client_ready(text,text) FROM zasp_red_team_worker`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_client_ready(text,text) FROM zasp_red_team_adapter`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_complete_core(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_complete_core(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_receipt(text,text,text,text,integer,text) TO PUBLIC`,
			`GRANT SELECT ON zasp_security_agent_test_invocations TO zasp_red_team_adapter`,
			`ALTER TABLE zasp_security_agent_test_invocations NO FORCE ROW LEVEL SECURITY`,
			`ALTER TABLE zasp_security_agent_test_invocations ALTER COLUMN started_at DROP DEFAULT`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_invocation_start_core(text,text,text,text,bytea,text,bytea) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_invocation_start_core(text,text,text,text,bytea,text,bytea) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_legacy_run(text,text,text,text,text) TO PUBLIC`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_legacy_run(text,text,text,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_claim_run(text,text,text,text,text,bytea,integer) TO zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_heartbeat_run(text,text,text,text,text,bytea,integer) TO zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea) TO zasp_red_team_worker`,
			`ALTER FUNCTION public.zasp_red_team_heartbeat_run(text,text,text,text,text,bytea,integer) RESET search_path`,
			`ALTER FUNCTION public.zasp_red_team_cancel_claimed_run(text,text,text,text,text,bytea,bytea) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb) TO zasp_red_team_worker`,
			`ALTER FUNCTION public.zasp_red_team_finish_run(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION public.zasp_red_team_finish_run_v38(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint) TO zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text) TO zasp_red_team_adapter`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_activate_core(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_simulate_core(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text) TO zasp_security_agent_worker`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_activate_core(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) RESET search_path`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_simulate_core(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text) RESET search_path`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_activate_core(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) OWNER TO zasp_e2e`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_simulate_core(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text) OWNER TO zasp_e2e`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO PUBLIC`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text) TO zasp_security_agent_api`,
			`ALTER FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) RESET search_path`,
			`ALTER FUNCTION zasp_existing_tests_predecessor.zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO PUBLIC`,
			`GRANT EXECUTE ON FUNCTION zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text) TO zasp_security_agent_worker`,
			`ALTER TABLE zasp_security_agent_test_links NO FORCE ROW LEVEL SECURITY`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text) TO zasp_red_team_adapter`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text) RESET search_path`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text) FROM zasp_red_team_worker`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_cancel_core(text,text,text,text,bigint,text,bytea,bytea) TO zasp_red_team_worker`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_cancel_core(text,text,text,text,bigint,text,bytea,bytea) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text) TO zasp_red_team_adapter`,
			`REVOKE EXECUTE ON FUNCTION zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text) FROM zasp_red_team_worker`,
			`ALTER FUNCTION zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text) TO zasp_security_agent_api`,
			`ALTER FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) RESET search_path`,
			`UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_run_context_fingerprint'`,
			`GRANT EXECUTE ON FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO PUBLIC; UPDATE zasp_schema_metadata SET value=zasp_production_security_agent_existing_tests_live_fingerprint() WHERE key='production_security_agent_existing_tests_fingerprint'`,
		} {
			if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			metadata := migrations.ProductionSecurityAgentExistingTests()
			if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_client_ready($1,$2)`, metadata.Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatalf("drift accepted: ready=%v err=%v", ready, err)
			}
			if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE existing_test_rollback_noinherit NOLOGIN NOINHERIT; GRANT zasp_discovery_authority TO existing_test_rollback_noinherit; SET ROLE existing_test_rollback_noinherit`); err != nil {
			t.Fatal(err)
		}
		_, denied := owner.Exec(ctx, migrations.ProductionSecurityAgentExistingTests().DownSQL())
		if _, err := owner.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		var pg *pgconn.PgError
		if !errors.As(denied, &pg) || pg.Code != "42501" || pg.Message != "existing test rollback authority unavailable" {
			t.Fatalf("NOINHERIT rollback authority accepted: %v", denied)
		}
		if _, err := owner.Exec(ctx, `DROP ROLE existing_test_rollback_noinherit`); err != nil {
			t.Fatal(err)
		}
		command, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id,created_at)
 SELECT organization_id,workspace_id,environment_id,definition_id,99,'draft',body||$1::jsonb,digest(convert_to((body||$1::jsonb)::text,'UTF8'),'sha256'),'pid_89000041-0000-4000-8000-000000000001',clock_timestamp()
 FROM zasp_security_agent_definitions WHERE organization_id='pid_6a000001-0000-4000-8000-000000000001'`, `{"existing_test":{"definition_id":"pid_89000042-0000-4000-8000-000000000001","definition_version":1}}`)
		if err != nil || command.RowsAffected() != 1 {
			t.Fatalf("retained registered history setup: %v", err)
		}
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("registered rollback accepted retained history")
		}
		if version, err := runner.Version(ctx); err != nil || version != 55 {
			t.Fatalf("refused rollback changed55: version=%d err=%v", version, err)
		}
		var retained int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_definition_versions WHERE organization_id='pid_6a000001-0000-4000-8000-000000000001' AND version=99 AND definition ? 'existing_test'`).Scan(&retained); err != nil || retained != 1 {
			t.Fatalf("refused rollback lost retained history: %d %v", retained, err)
		}
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_definition_versions WHERE organization_id='pid_6a000001-0000-4000-8000-000000000001' AND version=99 AND actor_id='pid_89000041-0000-4000-8000-000000000001'`); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatalf("rollback unused55: %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 54 {
			t.Fatalf("restored version=%d err=%v", version, err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_client_ready($1,$2)`, migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("exact54 readiness not restored: ready=%v err=%v", ready, err)
		}
		var lifecycleAfter string
		if err := owner.QueryRow(ctx, lifecycleIdentity).Scan(&lifecycleAfter); err != nil || lifecycleAfter != lifecycleBefore {
			t.Fatalf("rollback changed inherited lifecycle bodies/owner/ACL: %v", err)
		}
		var remaining int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'zasp_production_security_agent_existing_tests')`).Scan(&remaining); err != nil || remaining != 0 {
			t.Fatalf("rollback leaked version55 functions: %d %v", remaining, err)
		}
	})
}
