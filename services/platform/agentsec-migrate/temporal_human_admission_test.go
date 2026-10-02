package main

import "testing"

// Catches a human-admission release available only through a private Runner,
// or compatibility projection accepting a changed effective executor catalog.
func TestTemporalHumanAdmissionInstalledReleasePostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	for _, command := range []string{"up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector"} {
		if err := runReleaseMigration(f.ctx, f.registered, []string{command}); err != nil {
			t.Fatal(command, err)
		}
	}
	wrong := *f.registered
	wrong.registration.api = f.registration.discovery
	if err := runReleaseMigration(f.ctx, &wrong, []string{"up-temporal-human-admission"}); err == nil {
		t.Fatal("wrong registration installed76")
	}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(f.ctx, f.registered, []string{"up-temporal-human-admission"}); err != nil {
			t.Fatal("actual76 CLI", i, err)
		}
		if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-temporal-human-admission"}); err != nil {
			t.Fatal("registered76 readiness", err)
		}
	}
	for _, change := range []string{
		`GRANT EXECUTE ON FUNCTION zasp_temporal76.resource(jsonb) TO PUBLIC`,
		`ALTER TABLE zasp_temporal76.admissions DISABLE TRIGGER immutable`,
		`ALTER TABLE zasp_security_agent_request_receipts DISABLE TRIGGER zasp_temporal76_capture`,
		`DROP POLICY zasp_temporal76_owner ON zasp_security_agent_runs`,
		`ALTER FUNCTION zasp_temporal74.context(text,text,text,text) SET search_path TO public,pg_catalog`,
		`ALTER FUNCTION zasp_temporal74.context_parent(text,text,text,text,jsonb) SET search_path TO public,pg_catalog`,
		`ALTER TABLE zasp_temporal74.run_owners DROP CONSTRAINT run_owners_source_kind_check`,
		`ALTER FUNCTION zasp_temporal76.executor74_fingerprint() SET search_path TO public,pg_catalog`,
	} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.ctx, change); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := tx.QueryRow(f.ctx, `SELECT zasp_temporal76.current_ready() OR zasp_temporal75.current_ready() OR zasp_temporal74.current_ready()`).Scan(&ready); err != nil || ready {
			t.Fatal("effective76 drift accepted", change, ready, err)
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
}
