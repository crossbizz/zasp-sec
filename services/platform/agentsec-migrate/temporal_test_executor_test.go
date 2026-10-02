package main

import "testing"

// The public CLI must select74 and preserve registered-principal checks. A
// successful private migration helper alone is not a deployable authority.
func TestTemporalTestExecutorInstalledReleasePostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	for _, command := range []string{"up-temporal-discovery", "up-temporal-admission"} {
		if err := runReleaseMigration(f.ctx, f.registered, []string{command}); err != nil {
			t.Fatal(command, err)
		}
	}
	wrong := *f.registered
	wrong.registration.api = f.registration.discovery
	if err := runReleaseMigration(f.ctx, &wrong, []string{"up-temporal-test-executor"}); err == nil {
		t.Fatal("wrong registration installed74")
	}
	var intact bool
	if err := f.owner.QueryRow(f.ctx, `SELECT to_regnamespace('zasp_temporal74') IS NULL AND zasp_temporal73.current_ready()`).Scan(&intact); err != nil || !intact {
		t.Fatal("denied install changed73", intact, err)
	}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(f.ctx, f.registered, []string{"up-temporal-test-executor"}); err != nil {
			t.Fatal("installed CLI", i, err)
		}
		if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-temporal-test-executor"}); err != nil {
			t.Fatal("registered readiness", err)
		}
	}
	for _, change := range []string{`GRANT EXECUTE ON FUNCTION zasp_temporal74.human(text,text,text,text) TO PUBLIC`, `ALTER TABLE zasp_temporal74.service_grants NO FORCE ROW LEVEL SECURITY`, `ALTER TABLE zasp_temporal74.service_grants DISABLE TRIGGER immutable`,
		`GRANT EXECUTE ON FUNCTION zasp_temporal65.capture() TO PUBLIC`,
		`ALTER FUNCTION zasp_temporal65.capture() SET search_path TO public,pg_catalog`,
		`CREATE OR REPLACE FUNCTION zasp_temporal65.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT NULL::text'`,
		`CREATE OR REPLACE FUNCTION zasp_temporal74.outbox65_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT NULL::text'`,
		`GRANT EXECUTE ON FUNCTION zasp_temporal74.decision_owner(zasp_temporal74.control_intents) TO zasp_security_agent_api`,
		`ALTER TABLE zasp_temporal74.control_intents DISABLE TRIGGER immutable`,
		`ALTER TABLE zasp_temporal74.control_receipts NO FORCE ROW LEVEL SECURITY`,
	} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(f.ctx, change); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err = tx.QueryRow(f.ctx, `SELECT zasp_temporal74.current_ready()`).Scan(&ready); err != nil || ready {
			t.Fatal("catalog drift accepted", change, ready, err)
		}
		if err = tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_temporal74.predecessor_functions SET definition='changed' WHERE signature='zasp_temporal65.capture()'`); err == nil {
		t.Fatal("saved65 identity mutable")
	}
}
