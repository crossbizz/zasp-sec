package apiserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// A budget upgrade must not take unrelated API/runtime consumers offline.
// This exercises the actual v52 predecessor graph with registered roles, not
// a fabricated readiness result. This direct artifact fixture isolates drift;
// registered runner/up/down acceptance has its own migration test.
func TestSecurityAgentBudgetUpgradePreservesUnrelatedConsumers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	runner := installAuditExports(t, ctx, admin)
	if version, err := runner.Version(ctx); err != nil || version != 52 {
		t.Fatalf("predecessor version=%d error=%v", version, err)
	}
	databaseFor := func(connection *pgx.Conn) *PostgresJSONDatabase {
		t.Helper()
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		return database
	}
	api, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(databaseFor(sandboxSessionAPI(t, ctx, admin)), &sessionQueryIndex{}, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	ingest, err := runtimeevent.NewPostgresPreciseProductionIngestRepository(databaseFor(precisionRecoveryIngest(t, ctx, admin)))
	if err != nil {
		t.Fatal(err)
	}
	// Registered workers must enforce the same compiled release trust root as
	// the API, including connections warmed before cutover and fresh startup.
	if _, err := admin.Exec(ctx, `CREATE ROLE budget_release_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE budget_release_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE budget_release_action LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
SELECT zasp_security_agent_register_principals(session_user,'budget_release_api','budget_release_worker');
SELECT zasp_security_agent_register_action_principal(session_user,'budget_release_action')`); err != nil {
		t.Fatal(err)
	}
	workerDatabase := func(name string) *PostgresJSONDatabase {
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
	plannerDB := workerDatabase("budget_release_worker")
	actionDB := workerDatabase("budget_release_action")
	planner, err := NewSecurityAgentWorkerRepository(plannerDB)
	if err != nil {
		t.Fatal("v52 planner construction", err)
	}
	action, err := NewSecurityAgentActionRepository(actionDB)
	if err != nil {
		t.Fatal("v52 action construction", err)
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{"api", func() error { return api.Ready(ctx) }},
		{"runtime-ingest", func() error { return ingest.ReadyPrecision(ctx) }},
		{"planner-worker", func() error { return planner.Ready(ctx) }},
		{"action-worker", func() error { return action.Ready(ctx) }},
		{"fresh-planner", func() error { _, err := NewSecurityAgentWorkerRepository(plannerDB); return err }},
		{"fresh-action", func() error { _, err := NewSecurityAgentActionRepository(actionDB); return err }},
	}
	for _, check := range checks {
		if err := check.run(); err != nil {
			t.Fatal("v52 predecessor rejected", check.name, err)
		}
	}
	readRelease := func() (string, string, bool) {
		t.Helper()
		var live, expected string
		var secure bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_live_fingerprint(),(SELECT value FROM zasp_schema_metadata WHERE key='production_audit_exports_fingerprint'),zasp_production_runtime_sandbox_binding_security_ready()`).Scan(&live, &expected, &secure); err != nil {
			t.Fatal(err)
		}
		return live, expected, secure
	}
	before, expected, secureBefore := readRelease()
	if before != expected || !secureBefore {
		t.Fatal("invalid predecessor fingerprint/security baseline")
	}
	// Shared compiled candidate identity covers the assembled up template/down.
	// This direct installation is not CLI or production rollout proof.
	fingerprint := migrations.SecurityAgentBudgetCandidateFingerprint()
	checksum := migrations.SecurityAgentBudgetCandidateChecksum()
	if _, err := admin.Exec(ctx, migrations.SecurityAgentBudgetCandidateSQL()); err != nil {
		t.Fatal("install release envelope draft", err)
	}
	var candidate string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_live_fingerprint()`).Scan(&candidate); err != nil {
		t.Fatal(err)
	}
	if candidate != fingerprint {
		t.Fatalf("unregistered v53 candidate fingerprint=%s", candidate)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(53,'production_security_agent_budgets',$1)`, checksum); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_security_agent_budgets_checksum',$1),('production_security_agent_budgets_fingerprint',$2)`, checksum, fingerprint); err != nil {
		t.Fatal(err)
	}
	after, expectedAfter, secureAfter := readRelease()
	if err := ctx.Err(); err != nil {
		t.Fatal("fixture context expired before compatibility check", err)
	}
	t.Logf("v52 readiness inputs: live fingerprint changed=%t; pinned fingerprint unchanged=%t; structural security before=%t after=%t", before != after, expected == expectedAfter, secureBefore, secureAfter)
	for _, check := range checks {
		if err := check.run(); err != nil {
			if ctx.Err() != nil {
				t.Fatal("fixture context expired during compatibility check", ctx.Err())
			}
			t.Error("budget upgrade disabled unrelated consumer", check.name, err)
		}
	}
	// Metadata cannot turn changed executable authority into a trusted release.
	// Keep the old compiled v52 pins and warmed consumers unchanged throughout.
	var originalHelper string
	if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_security_agent_budget_stopped(text,text,text,text)'::regprocedure)`).Scan(&originalHelper); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.zasp_security_agent_budget_stopped(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT false'`); err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Error("consumer accepted budget helper drift", check.name)
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=zasp_production_security_agent_budgets_live_fingerprint() WHERE key='production_security_agent_budgets_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Error("consumer accepted metadata-rebased budget helper drift", check.name)
		}
	}
	if _, err := admin.Exec(ctx, originalHelper); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_budgets_fingerprint'`, fingerprint); err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if err := check.run(); err != nil {
			t.Fatal("restored helper rejected", check.name, err)
		}
	}
	for _, statement := range []string{
		`UPDATE zasp_schema_versions SET checksum=repeat('f',64) WHERE version=53`,
		`UPDATE zasp_schema_metadata SET value=repeat('f',64) WHERE key='production_security_agent_budgets_checksum'`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Error("consumer accepted coherently changed v53 checksum", check.name)
		}
	}
	var readinessDefinition string
	if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_production_security_agent_budgets_readiness(text,text)'::regprocedure)`).Scan(&readinessDefinition); err != nil {
		t.Fatal(err)
	}
	oldGuard := "expected_checksum = '" + checksum + "'"
	if strings.Count(readinessDefinition, oldGuard) != 1 {
		t.Fatal("compiled checksum guard fixture did not identify one literal")
	}
	if _, err := admin.Exec(ctx, strings.Replace(readinessDefinition, oldGuard, "expected_checksum = '"+strings.Repeat("f", 64)+"'", 1)); err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Error("consumer accepted changed compiled pin and matching metadata", check.name)
		}
	}
	// Rebaseline both SQL roots coherently after executable helper drift. Only
	// application-supplied pins distinguish this from the compiled candidate.
	if _, err := admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.zasp_security_agent_budget_stopped(organization_value text,workspace_value text,environment_value text,run_value text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT false'`); err != nil {
		t.Fatal(err)
	}
	var rebasedFingerprint string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_live_fingerprint(),pg_get_functiondef('public.zasp_production_security_agent_budgets_readiness(text,text)'::regprocedure)`).Scan(&rebasedFingerprint, &readinessDefinition); err != nil {
		t.Fatal(err)
	}
	oldFingerprintGuard := "expected_fingerprint = '" + fingerprint + "'"
	if rebasedFingerprint == fingerprint || strings.Count(readinessDefinition, oldFingerprintGuard) != 1 {
		t.Fatal("coherent rebaseline fixture did not change authority")
	}
	if _, err := admin.Exec(ctx, strings.Replace(readinessDefinition, oldFingerprintGuard, "expected_fingerprint = '"+rebasedFingerprint+"'", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_budgets_fingerprint'`, rebasedFingerprint); err != nil {
		t.Fatal(err)
	}
	var internallyReady bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_readiness($1,$2)`, strings.Repeat("f", 64), rebasedFingerprint).Scan(&internallyReady); err != nil || !internallyReady {
		t.Fatal("fixture did not reach internally consistent replacement roots", internallyReady, err)
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Error("updated consumer accepted coherent SQL-root rebaseline", check.name)
		}
	}
}
