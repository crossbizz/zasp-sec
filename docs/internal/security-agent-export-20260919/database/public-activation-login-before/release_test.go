package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func applyExport58(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentExports(ctx); err != nil {
		// A failed Runner transaction has rolled back. Inspect an isolated rollback-
		// only transaction to report the actual catalog pin or SQL diagnostic.
		tx, debugErr := owner.Begin(ctx)
		if debugErr != nil {
			t.Fatalf("Runner58=%v diagnostic=%v", err, debugErr)
		}
		defer tx.Rollback(context.Background())
		_, debugErr = tx.Exec(ctx, migrations.ProductionSecurityAgentExports().UpSQL())
		if debugErr != nil {
			t.Fatalf("Runner58=%v SQL diagnostic=%#v", err, debugErr)
		}
		var fp string
		debugErr = tx.QueryRow(ctx, `SELECT zasp_sa_export_live_fingerprint()`).Scan(&fp)
		t.Fatalf("Runner58=%v observed fingerprint=%s diagnostic=%v", err, fp, debugErr)
	}
}

// This catches loss of predecessor catalog/ACLs and destructive downgrade of
// disabled controls, which are still retained product history.
func TestSecurityAgentExportReleasePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		const catalog = `SELECT zasp_sa_attack_lab_live_fingerprint(),(SELECT jsonb_object_agg(oid::regprocedure::text,COALESCE(proacl::text,''))::text FROM pg_proc WHERE pronamespace='public'::regnamespace)`
		var beforeFP, beforeACL string
		if err := owner.QueryRow(ctx, catalog).Scan(&beforeFP, &beforeACL); err != nil {
			t.Fatal(err)
		}
		if beforeFP != migrations.SecurityAgentAttackLabFingerprint() {
			t.Fatal("fixture57 catalog differs")
		}
		applyExport58(t, ctx, owner)
		var ready bool
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("registered58 readiness=%v error=%v", ready, err)
		}
		if err := api.QueryRow(ctx, `SELECT zasp_sa_export_workflow_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("installed workflow admission=%v %v", ready, err)
		}
		var closed bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace='zasp_sa_export_prior'::regnamespace AND (has_function_privilege('zasp_security_agent_api',p.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE'))) AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_sa_export_workflow_readiness','zasp_sa_export_mutate_definition','zasp_sa_export_replay_definition','zasp_sa_export_activate','zasp_sa_export_controls','zasp_sa_export_set_control','zasp_sa_export_definition_value','zasp_sa_export_definition_detail','zasp_sa_export_definition_page') AND (p.proowner<>'zasp_discovery_authority'::regrole OR NOT p.prosecdef OR NOT has_function_privilege('zasp_security_agent_api',p.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE')))`).Scan(&closed); err != nil || !closed {
			t.Fatalf("public definition owner/ACL=%v %v", closed, err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; GRANT EXECUTE ON FUNCTION zasp_sa_export_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text,text,text) TO zasp_security_agent_worker`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_workflow_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("admission ACL drift accepted: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; ALTER TABLE zasp_sa_export_links ADD COLUMN unexpected text`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("live column drift accepted: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK; CREATE ROLE export_release_executor LOGIN INHERIT; CREATE ROLE export_release_cleanup LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; CREATE FUNCTION public.export_fixture_unexpected_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER export_fixture_unexpected BEFORE INSERT ON zasp_sa_export_links FOR EACH ROW EXECUTE FUNCTION public.export_fixture_unexpected_trigger()`); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Errorf("live trigger drift accepted: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if err := runner.RegisterComplianceWorkers(ctx, "export_release_executor", "export_release_cleanup"); err != nil {
			t.Fatalf("actual Runner registration58: %v", err)
		}
		if err := runner.DownProductionSecurityAgentExports(ctx); err != nil {
			t.Fatal(err)
		}
		var afterFP, afterACL string
		if err := owner.QueryRow(ctx, catalog).Scan(&afterFP, &afterACL); err != nil {
			t.Fatal(err)
		}
		if afterFP != beforeFP || afterACL != beforeACL {
			t.Fatalf("empty downgrade did not restore57: fingerprint %s -> %s; sameACL=%v", beforeFP, afterFP, beforeACL == afterACL)
		}
		applyExport58(t, ctx, owner)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'create_evidence_export',false,$4)`, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentExports(ctx); err == nil {
			t.Fatal("disabled export control history was destructively downgraded")
		}
		var version int64
		if err := owner.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 58 {
			t.Fatalf("refused downgrade changed registry: %d %v", version, err)
		}
	})
}
