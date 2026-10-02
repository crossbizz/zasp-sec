package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Real registered audit principals must retain52/53 compatibility and bind54
// to application pins even if SQL readiness and stored metadata are rebased.
func TestAuditExportRunContextConsumersPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.register(t, ctx)
	worker, outbox := auditExportWorkerConnections(t, ctx, f)
	databases := make([]*PostgresJSONDatabase, 0, 3)
	for _, connection := range []*pgx.Conn{f.api, worker, outbox} {
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		databases = append(databases, database)
	}
	repository, err := NewAuditExportRepository(databases[0])
	if err != nil {
		t.Fatal(err)
	}
	check := func(stage string, installed, trusted bool) {
		t.Helper()
		for i, database := range databases {
			available, err := database.SecurityAgentRunContextAvailable(ctx)
			if (err == nil) != trusted || (trusted && available != installed) {
				t.Errorf("%s principal%d available=%v err=%v", stage, i, available, err)
			}
		}
		if err := repository.Ready(ctx); (err == nil) != trusted {
			t.Errorf("%s warm API readiness=%v", stage, err)
		}
		if _, err := NewAuditExportRepository(databases[0]); (err == nil) != trusted {
			t.Errorf("%s fresh API construction=%v", stage, err)
		}
	}
	check("52", false, true)
	runner := precisionMigrationRunner(t, f.admin)
	if err := runner.UpProductionSecurityAgentBudgets(ctx); err != nil {
		t.Fatal(err)
	}
	check("53", false, true)
	if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
		t.Fatal(err)
	}
	check("54", true, true)
	var originalReadiness string
	if err := f.admin.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_production_security_agent_run_context_readiness(text,text)'::regprocedure)`).Scan(&originalReadiness); err != nil {
		t.Fatal(err)
	}
	// The readiness body normalizes embedded pins for fingerprinting. Rewriting
	// its fingerprint literal plus metadata must not fool compiled client pins.
	if _, err := f.admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_production_security_agent_run_context_client_ready(text,text) TO PUBLIC;
DO $attack$ DECLARE actual text; definition text; BEGIN
 actual:=zasp_production_security_agent_run_context_live_fingerprint();
 SELECT pg_get_functiondef('public.zasp_production_security_agent_run_context_readiness(text,text)'::regprocedure) INTO definition;
 EXECUTE replace(definition,'`+migrations.SecurityAgentRunContextFingerprint()+`',actual);
 UPDATE zasp_schema_metadata SET value=actual WHERE key='production_security_agent_run_context_fingerprint';
END $attack$`); err != nil {
		t.Fatal(err)
	}
	var databaseAccepts bool
	if err := f.admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&databaseAccepts); err != nil || !databaseAccepts {
		t.Fatalf("control did not coherently rebase database readiness: ready=%v err=%v", databaseAccepts, err)
	}
	check("coherently rebased54", true, false)
	if _, err := f.admin.Exec(ctx, originalReadiness); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `REVOKE ALL ON FUNCTION zasp_production_security_agent_run_context_client_ready(text,text) FROM PUBLIC; UPDATE zasp_schema_metadata SET value='`+migrations.SecurityAgentRunContextFingerprint()+`' WHERE key='production_security_agent_run_context_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	check("restored54", true, true)
	if err := runner.DownProductionSecurityAgentRunContext(ctx); err != nil {
		t.Fatal(err)
	}
	check("rollback53", false, true)
}
