package main

import (
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Exercise the shipped command dispatcher and registered Runner against the
// same installed lineage as the worker, including repeat and drift rejection.
func TestTemporalAdmissionInstalledReleasePostgres(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	if err := f.registered.UpProductionTemporalDiscovery(f.ctx); err != nil {
		t.Fatal("accepted72", err)
	}
	wrong := *f.registered
	wrong.registration.api = f.registration.discovery
	if err := runReleaseMigration(f.ctx, &wrong, []string{"up-temporal-admission"}); err == nil {
		t.Fatal("wrong principal registration installed73")
	}
	var intact bool
	if err := f.owner.QueryRow(f.ctx, `SELECT to_regnamespace('zasp_temporal73') IS NULL AND zasp_temporal72.current_ready()`).Scan(&intact); err != nil || !intact {
		t.Fatal("failed installation changed predecessor", intact, err)
	}
	for i := 0; i < 2; i++ {
		if err := runReleaseMigration(f.ctx, f.registered, []string{"up-temporal-admission"}); err != nil {
			t.Fatal("installed CLI dispatch", i, err)
		}
		if err := registerForwardRelease(f.ctx, f.owner, f.registration, []string{"up-temporal-admission"}); err != nil {
			t.Fatal("final registered readiness", err)
		}
	}
	var fingerprint string
	if err := f.owner.QueryRow(f.ctx, `SELECT zasp_temporal73.fingerprint()`).Scan(&fingerprint); err != nil || fingerprint != migrations.TemporalAdmissionFingerprint() {
		t.Fatal("independent installed catalog", fingerprint, err)
	}
	for _, change := range []string{
		`ALTER TABLE public.zasp_security_agent_runs DISABLE TRIGGER zasp_temporal73_capacity`,
		`GRANT EXECUTE ON FUNCTION zasp_temporal73.active_count(text,text,text,text) TO PUBLIC`,
		`ALTER TABLE zasp_temporal73.commands NO FORCE ROW LEVEL SECURITY`,
		`ALTER FUNCTION zasp_temporal73.unresolved(text,text,text,text) SECURITY INVOKER`,
	} {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(f.ctx, change); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err = tx.QueryRow(f.ctx, `SELECT zasp_temporal73.current_ready()`).Scan(&ready); err != nil || ready {
			t.Fatal("catalog drift accepted", change, ready, err)
		}
		if err = tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
}
