package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Explain the installed claim's actual candidate CTEs, not a separately maintained
// copy. Only the final read is substituted for the row-locking mutation.
func reconciliationCandidateQuery(t *testing.T, ctx context.Context, connection *pgx.Conn) string {
	t.Helper()
	var body string
	if err := connection.QueryRow(ctx, "SELECT prosrc FROM pg_proc WHERE oid='zasp_connector_claim_reconciliation(text,integer,integer)'::regprocedure").Scan(&body); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(body, "WITH ")
	end := strings.Index(body, ",\n  selected AS")
	if start < 0 || end < start {
		t.Fatal("installed claim candidate query missing")
	}
	return body[start:end] + " SELECT effect.id FROM zasp_connector_effects effect JOIN fair ON (fair.organization_id,fair.workspace_id,fair.environment_id,fair.id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id) ORDER BY fair.organization_rank,effect.updated_at,effect.id LIMIT 25"
}

func reconciliationLanePlanPredecessor(t *testing.T, ctx context.Context) (*pgx.Conn, *migrations.Runner) {
	t.Helper()
	admin, runner, _, _ := redTeamInvocationFixture(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return admin, runner
}

func TestReconciliationLanePlanMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	priorDrift, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const changeClaimBody = `DO $test$ DECLARE definition text; BEGIN SELECT pg_get_functiondef('public.zasp_connector_claim_reconciliation(text,integer,integer)'::regprocedure) INTO definition; EXECUTE replace(definition,'742516322','742516323'); END $test$;`
	if _, err := priorDrift.Exec(ctx, changeClaimBody); err != nil {
		priorDrift.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := priorDrift.Exec(ctx, migrations.ProductionReconciliationLanePlan().UpSQL()); err == nil {
		priorDrift.Rollback(ctx)
		t.Fatal("upgrade accepted changed predecessor claim body")
	}
	priorDrift.Rollback(ctx)
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, migrations.ProductionReconciliationLanePlan().UpSQL()); err != nil {
		probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	var security bool
	if err := probe.QueryRow(ctx, "SELECT zasp_production_reconciliation_lane_plan_security_ready()").Scan(&security); err != nil || !security {
		t.Fatal(err)
	}
	err = probe.QueryRow(ctx, "SELECT zasp_production_reconciliation_lane_plan_live_fingerprint()").Scan(&fingerprint)
	probe.Rollback(ctx)
	if err != nil || fingerprint != migrations.ProductionReconciliationLanePlanSemanticFingerprint() {
		t.Fatalf("candidate46 fingerprint=%s error=%v", fingerprint, err)
	}
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal("rollback", err)
	}
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal("repeat upgrade", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 46 {
		t.Fatalf("catalog=%d error=%v", version, err)
	}
	for _, role := range []string{"invocation_discovery_api", "invocation_discovery_worker"} {
		config := admin.Config().Copy()
		config.User = role
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		if role == "invocation_discovery_api" {
			connector := &ConnectorRepository{database: database}
			if err := connector.Ready(ctx); err != nil {
				t.Fatal("API connector startup", err)
			}
			repository, err := NewPostgresRepository(database)
			if err != nil || repository.Ready(ctx) != nil {
				t.Fatal("schema46 API startup rejected", err)
			}
		} else {
			repository, err := newDiscoveryRepositoryForAuthority(database, DiscoveryDatabaseAuthorityWorker, 5*time.Second)
			if err != nil || repository.Ready(ctx) != nil {
				t.Fatal("schema46 discovery worker startup rejected", err)
			}
		}
		var ready bool
		err = connection.QueryRow(ctx, "SELECT zasp_production_reconciliation_lane_plan_readiness($1,$2)", migrations.ProductionReconciliationLanePlan().Checksum(), migrations.ProductionReconciliationLanePlanSemanticFingerprint()).Scan(&ready)
		connection.Close(ctx)
		if err != nil || !ready {
			t.Fatalf("%s readiness=%t error=%v", role, ready, err)
		}
	}
	for _, mutation := range []string{
		changeClaimBody,
		`INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(47,'future_release',repeat('0',64))`,
		`ALTER FUNCTION zasp_connector_claim_reconciliation(text,integer,integer) RESET search_path`,
		`GRANT EXECUTE ON FUNCTION zasp_connector_claim_reconciliation(text,integer,integer) TO PUBLIC`,
		`REVOKE EXECUTE ON FUNCTION zasp_connector_claim_reconciliation(text,integer,integer) FROM zasp_discovery_worker`,
	} {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec(ctx, mutation); err != nil {
			transaction.Rollback(ctx)
			t.Fatal(err)
		}
		var ready bool
		err = transaction.QueryRow(ctx, "SELECT zasp_production_reconciliation_lane_plan_readiness($1,$2)", migrations.ProductionReconciliationLanePlan().Checksum(), migrations.ProductionReconciliationLanePlanSemanticFingerprint()).Scan(&ready)
		if err != nil || ready {
			transaction.Rollback(ctx)
			t.Fatalf("drift admitted %s ready=%t error=%v", mutation, ready, err)
		}
		var marker string
		if err := transaction.QueryRow(ctx, postgresProductionRecoverySchemaVersionSQL, expectedProductionRecoverySchemaChecksum(), expectedProductionRecoverySchemaFingerprint(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint()).Scan(&marker); err == nil {
			transaction.Rollback(ctx)
			t.Fatal("API startup accepted drift", mutation)
		}
		if _, err := transaction.Exec(ctx, migrations.ProductionReconciliationLanePlan().DownSQL()); err == nil {
			transaction.Rollback(ctx)
			t.Fatal("rollback accepted drift", mutation)
		}
		transaction.Rollback(ctx)
	}
}
