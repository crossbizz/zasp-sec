package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// Actual registered consumers cross53->54->55->54->53 on the same connections. Fresh
// construction is checked too; this is readiness, not live worker execution.
func TestSecurityAgentRunContextConsumersPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	runner := installAuditExports(t, ctx, admin)
	if err := runner.UpProductionSecurityAgentBudgets(ctx); err != nil {
		t.Fatal(err)
	}
	databaseFor := func(connection *pgx.Conn) *PostgresJSONDatabase {
		t.Helper()
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	apiDB := databaseFor(sandboxSessionAPI(t, ctx, admin))
	ingestDB := databaseFor(precisionRecoveryIngest(t, ctx, admin))
	if _, err := admin.Exec(ctx, `CREATE ROLE context_release_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE context_release_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE context_release_action LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
SELECT zasp_security_agent_register_principals(session_user,'context_release_api','context_release_worker');
SELECT zasp_security_agent_register_action_principal(session_user,'context_release_action')`); err != nil {
		t.Fatal(err)
	}
	workerDB := func(name string) *PostgresJSONDatabase {
		t.Helper()
		config := admin.Config().Copy()
		config.User = name
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { connection.Close(context.Background()) })
		return databaseFor(connection)
	}
	plannerDB, actionDB := workerDB("context_release_worker"), workerDB("context_release_action")
	api, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(apiDB, &sessionQueryIndex{}, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	ingest, err := runtimeevent.NewPostgresPreciseProductionIngestRepository(ingestDB)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewSecurityAgentWorkerRepository(plannerDB)
	if err != nil {
		t.Fatal(err)
	}
	action, err := NewSecurityAgentActionRepository(actionDB)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{"warm API", func() error { return api.Ready(ctx) }},
		{"warm ingest", func() error { return ingest.ReadyPrecision(ctx) }},
		{"warm planner", func() error { return planner.Ready(ctx) }},
		{"warm action", func() error { return action.Ready(ctx) }},
		{"fresh API", func() error {
			r, e := NewPostgresRepositoryWithRuntimeSessionSearchIndex(apiDB, &sessionQueryIndex{}, "zasp-runtime-sessions-v2")
			if e != nil {
				return e
			}
			return r.Ready(ctx)
		}},
		{"fresh ingest", func() error {
			r, e := runtimeevent.NewPostgresPreciseProductionIngestRepository(ingestDB)
			if e != nil {
				return e
			}
			return r.ReadyPrecision(ctx)
		}},
		{"fresh planner", func() error {
			r, e := NewSecurityAgentWorkerRepository(plannerDB)
			if e != nil {
				return e
			}
			return r.Ready(ctx)
		}},
		{"fresh action", func() error {
			r, e := NewSecurityAgentActionRepository(actionDB)
			if e != nil {
				return e
			}
			return r.Ready(ctx)
		}},
	}
	checkAll := func(stage string, wantReady bool) {
		t.Helper()
		for _, check := range checks {
			err := check.run()
			if (err == nil) != wantReady {
				t.Errorf("%s %s readiness=%v, want ready=%v", stage, check.name, err, wantReady)
			}
		}
	}
	checkAll("53", true)
	if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
		t.Fatal(err)
	}
	checkAll("54", true)
	if _, err := admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	checkAll("tampered54", false)
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=zasp_production_security_agent_run_context_live_fingerprint() WHERE key='production_security_agent_run_context_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	checkAll("rebased54", false)
	if _, err := admin.Exec(ctx, `REVOKE ALL ON FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) FROM PUBLIC; UPDATE zasp_schema_metadata SET value='`+migrations.SecurityAgentRunContextFingerprint()+`' WHERE key='production_security_agent_run_context_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	checkAll("restored54", true)
	if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
		t.Fatal(err)
	}
	checkAll("55", true)
	if _, err := admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	checkAll("tampered55", false)
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=zasp_production_security_agent_existing_tests_live_fingerprint() WHERE key='production_security_agent_existing_tests_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	checkAll("rebased55", false)
	if _, err := admin.Exec(ctx, `REVOKE ALL ON FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM PUBLIC; UPDATE zasp_schema_metadata SET value='`+migrations.SecurityAgentExistingTestsFingerprint()+`' WHERE key='production_security_agent_existing_tests_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	checkAll("restored55", true)
	if err := runner.DownProductionSecurityAgentExistingTests(ctx); err != nil {
		t.Fatal(err)
	}
	checkAll("rollback54", true)
	if err := runner.DownProductionSecurityAgentRunContext(ctx); err != nil {
		t.Fatal(err)
	}
	checkAll("rollback53", true)
}
