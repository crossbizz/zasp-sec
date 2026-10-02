package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Compile-time fingerprint calibration is confined to an owned test database.
// The production runner never substitutes a live digest for its compiled pin.
func TestSecurityAgentRunContextCompiledFingerprintPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		metadata := migrations.ProductionSecurityAgentRunContext()
		if _, err := owner.Exec(ctx, metadata.UpSQL()); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_security_agent_run_context_checksum',$1),('production_security_agent_run_context_fingerprint',$2)`, metadata.Checksum(), migrations.SecurityAgentRunContextFingerprint()); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(54,$1,$2)`, metadata.Name(), metadata.Checksum()); err != nil {
			t.Fatal(err)
		}
		var fingerprint string
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_live_fingerprint()`).Scan(&fingerprint); err != nil {
			t.Fatal(err)
		}
		if fingerprint != migrations.SecurityAgentRunContextFingerprint() {
			t.Fatalf("compiled run context fingerprint differs: actual=%s", fingerprint)
		}
	})
}

// Exercises the registered release, pinned readiness, authority drift refusal,
// and rollback. This is local database acceptance, not a deployment claim.
func TestSecurityAgentRunContextReleasePostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		runner := precisionMigrationRunner(t, owner)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES('pid_6a000001-0000-4000-8000-000000000001')`); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatalf("register run-context release: %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 54 {
			t.Fatalf("registered version=%d: %v", version, err)
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_client_ready($1,$2)`, migrations.SecurityAgentBudgetCandidateChecksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("old budget binary must refuse54: ready=%v error=%v", ready, err)
		}
		for _, mutation := range []string{
			`DROP INDEX zasp_security_agent_activity_audit_v54_idx`,
			`DROP INDEX zasp_security_agent_activity_trigger_v54_idx`,
			`DROP INDEX zasp_security_agent_activity_plan_v54_idx`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint) TO PUBLIC`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_run_context_lock_env(text,text,text) TO PUBLIC`,
			`ALTER FUNCTION zasp_production_security_agent_run_context_lock_env(text,text,text) OWNER TO zasp_discovery_authority`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_run_context_lock_env(text,text,text) TO security_agent_v33_api_login`,
			`GRANT EXECUTE ON FUNCTION zasp_production_security_agent_run_context_lock_target(text,text,text,text) TO PUBLIC`,
			`GRANT EXECUTE ON FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) TO PUBLIC`,
			`ALTER FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) RESET search_path`,
			`UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_budgets_fingerprint'`,
			`GRANT EXECUTE ON FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) TO PUBLIC; UPDATE zasp_schema_metadata SET value=zasp_production_security_agent_run_context_live_fingerprint() WHERE key='production_security_agent_run_context_fingerprint'`,
		} {
			if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			metadata := migrations.ProductionSecurityAgentRunContext()
			if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_readiness($1,$2)`, metadata.Checksum(), migrations.SecurityAgentRunContextFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatalf("drifted release accepted readiness: ready=%v error=%v", ready, err)
			}
			if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
		}
		if err := runner.DownProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatalf("rollback to53: %v", err)
		}
		var retained int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_org_admissions WHERE organization_id='pid_6a000001-0000-4000-8000-000000000001'`).Scan(&retained); err != nil || retained != 1 {
			t.Fatalf("rollback lost retained53 budget authority: count=%d error=%v", retained, err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 53 {
			t.Fatalf("rollback version=%d: %v", version, err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_client_ready($1,$2)`, migrations.SecurityAgentBudgetCandidateChecksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("exact53 readiness not restored: ready=%v error=%v", ready, err)
		}
		var removed bool
		for _, signature := range []string{"public.zasp_production_security_agent_run_context_lock_env(text,text,text)", "public.zasp_production_security_agent_run_context_lock_target(text,text,text,text)"} {
			if err := owner.QueryRow(ctx, `SELECT to_regprocedure($1) IS NULL`, signature).Scan(&removed); err != nil || !removed {
				t.Fatalf("rollback left private lock helper %s: removed=%v error=%v", signature, removed, err)
			}
		}
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)') IS NULL`).Scan(&removed); err != nil || !removed {
			t.Fatalf("rollback left private test binding reader: removed=%v error=%v", removed, err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_regclass('public.zasp_security_agent_activity_audit_v54_idx') IS NULL AND to_regclass('public.zasp_security_agent_activity_trigger_v54_idx') IS NULL AND to_regclass('public.zasp_security_agent_activity_plan_v54_idx') IS NULL`).Scan(&removed); err != nil || !removed {
			t.Fatalf("rollback left54 activity index: removed=%v error=%v", removed, err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_security_agent_run_context_v54(text,text,text,text)') IS NULL`).Scan(&removed); err != nil || !removed {
			t.Fatalf("rollback left54 projection: removed=%v error=%v", removed, err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_run_context_audit(text,text,text,text,bytea,text,text)') IS NULL`).Scan(&removed); err != nil || !removed {
			t.Fatalf("rollback left54 audit reader: removed=%v error=%v", removed, err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_run_context_targets(text,text,text,text,bytea,text,text,text,text,integer)') IS NULL`).Scan(&removed); err != nil || !removed {
			t.Fatalf("rollback left54 forward reader: removed=%v error=%v", removed, err)
		}
	})
}
