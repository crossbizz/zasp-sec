package apiserver

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// An evolved installation must retain the real non-Temporal worker boundary;
// a low-level SDK worker constructor cannot catch this readiness failure.
func TestTemporalInstalledWorkerRepositoryPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-executor")
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-workflow")
		if diagnosticPath := os.Getenv("ZASP_TEST_FUNCTION_INVENTORY"); diagnosticPath != "" {
			var raw []byte
			if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('schema',n.nspname,'name',p.proname,'signature',p.oid::regprocedure::text,'owner',p.proowner::regrole::text,'acl',COALESCE(p.proacl::text,''),'definition',pg_get_functiondef(p.oid)) ORDER BY n.nspname,p.proname,p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE ((n.nspname='public' AND p.proname LIKE 'zasp_%') OR n.nspname LIKE 'zasp_%') AND p.prokind='f'`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(diagnosticPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-compatibility")
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal("installed69 worker constructor", err)
		}
		if err := repository.Ready(ctx); err != nil {
			t.Fatal("installed69 worker readiness", err)
		}
	})
}

func TestTemporalCompatibilityCatalogPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-executor")
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-workflow")
		assertTemporalExtractionRefusesChangedSource(t, ctx, owner, migrations.ProductionTemporalCompatibility(), "zasp_temporal70", "public.zasp_sa_manual_recheck(text,text,text,text)")
		if _, err := owner.Exec(ctx, migrations.ProductionTemporalCompatibility().UpSQL()); err != nil {
			t.Fatal("compile70", err)
		}
		var pin string
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal70.fingerprint()`).Scan(&pin); err != nil {
			t.Fatal(err)
		}
		if pin != migrations.TemporalCompatibilityFingerprint() {
			t.Fatalf("compiled70 pin=%s", pin)
		}
	})
}

func TestTemporalLegacyLinkedInstalledPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for _, command := range []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests"} {
			runTemporalMigrationCLI(t, ctx, owner, command)
		}
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
		if err != nil {
			t.Fatal(err)
		}
		repo, err := NewLinkedRedTeamExecutionRepository(db)
		if err != nil {
			t.Fatal("installed legacy linked constructor", err)
		}
		if err := repo.Ready(ctx); err != nil {
			t.Fatal("installed legacy linked readiness", err)
		}
		for _, role := range []string{"zasp_security_agent_worker", "zasp_red_team_adapter"} {
			var ready bool
			if err := redWorker.QueryRow(ctx, `SELECT zasp_temporal71.client_ready($1,$2,$3)`, migrations.ProductionTemporalLegacyTests().Checksum(), migrations.TemporalLegacyTestsFingerprint(), role).Scan(&ready); err != nil || ready {
				t.Fatal("wrong role readiness", role, ready, err)
			}
		}
		for _, schema := range []string{"zasp_temporal70", "zasp_temporal71"} {
			var privateGrant bool
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname ~ '^(body|guard)' AND (has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE') OR has_function_privilege('zasp_red_team_worker',p.oid,'EXECUTE') OR has_function_privilege('zasp_red_team_adapter',p.oid,'EXECUTE')))`, schema).Scan(&privateGrant); err != nil || privateGrant {
				t.Fatal("private extraction grant", schema, privateGrant, err)
			}
		}
		for _, conn := range []*pgx.Conn{worker, api, redWorker, adapter} {
			_, err := conn.Exec(ctx, `SELECT zasp_temporal71.adapter_protocol($1,$2,$3,$4)`, o, w, e, testID)
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Fatal("unlinked or wrong principal classifier admitted", err)
			}
		}
		// A present but altered installation cannot fall back to public readiness.
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_temporal71.op01(text,text,text,text,text,text) FROM zasp_red_team_worker`); err != nil {
			t.Fatal(err)
		}
		var alteredReady bool
		if err := tx.QueryRow(ctx, `SELECT zasp_temporal71.current_ready()`).Scan(&alteredReady); err != nil || alteredReady {
			t.Error("altered installed ACL remained ready", alteredReady, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := repo.Ready(ctx); err != nil {
			t.Fatal("rollback did not restore readiness", err)
		}
	})
}

func TestTemporalLegacyTestsCatalogPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for _, command := range []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility"} {
			runTemporalMigrationCLI(t, ctx, owner, command)
		}
		assertTemporalExtractionRefusesChangedSource(t, ctx, owner, migrations.ProductionTemporalLegacyTests(), "zasp_temporal71", "public.zasp_production_security_agent_existing_tests_invocation_comple(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea)")
		if _, err := owner.Exec(ctx, migrations.ProductionTemporalLegacyTests().UpSQL()); err != nil {
			t.Fatal("compile71", err)
		}
		var pin string
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal71.fingerprint()`).Scan(&pin); err != nil {
			t.Fatal(err)
		}
		if pin != migrations.TemporalLegacyTestsFingerprint() {
			t.Fatalf("compiled71 pin=%s", pin)
		}
	})
}

func assertTemporalExtractionRefusesChangedSource(t *testing.T, ctx context.Context, owner *pgx.Conn, migration migrations.Metadata, schema, signature string) {
	t.Helper()
	for _, change := range []string{"GRANT EXECUTE ON FUNCTION " + signature + " TO zasp_security_agent_worker", "ALTER FUNCTION " + signature + " SET search_path TO pg_catalog"} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, change); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, migration.UpSQL())
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55000" {
			t.Error("changed source extraction not refused", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT to_regnamespace($1) IS NULL`, schema).Scan(&absent); err != nil || !absent {
			t.Fatal("rejected extraction was not atomic", absent, err)
		}
	}
}
