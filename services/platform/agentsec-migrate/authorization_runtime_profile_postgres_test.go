package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// One owned-native group exercises the shipped CLI with fresh/upgrade/replay
// and rejection boundaries. It never reads a deployed DSN or launches a worker.
func TestAuthorizationRuntimeProfileNative(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	build := exec.CommandContext(buildCtx, "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("owned CLI build: %v %s", err, output)
	}
	for _, start := range []string{"empty", "canonical61", "logical78_projection79"} {
		t.Run(start, func(t *testing.T) {
			dsn := startMigrationPostgres(t)
			ctx, stop := context.WithTimeout(context.Background(), 8*time.Minute)
			defer stop()
			owner := connectMigrationPostgres(t, ctx, dsn)
			defer owner.Close(context.Background())
			operator := "zasp_test"
			if start == "canonical61" {
				// Retained historical 61 has the established zasp_e2e scope owner.
				// Fresh installation above deliberately uses a different owner and
				// the portable native 67 cutover, not a renamed production login.
				if _, err := owner.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
					t.Fatal(err)
				}
				parsed, err := url.Parse(dsn)
				if err != nil {
					t.Fatal(err)
				}
				parsed.User = url.User("zasp_e2e")
				dsn, operator = parsed.String(), "zasp_e2e"
				owner = connectMigrationPostgres(t, ctx, dsn)
				defer owner.Close(context.Background())
			}
			values := map[string]string{migrationPrincipalEnvironment: operator, postgresDSNEnvironment: dsn, "ZASP_MIGRATION_TIMEOUT": "7m"}
			for i, key := range []string{discoveryAPIPrincipalEnvironment, discoveryWorkerPrincipalEnvironment, runtimeIngestPrincipalEnvironment, runtimeWorkerPrincipalEnvironment, outboxWorkerPrincipalEnvironment, runtimeGatewayPrincipalEnvironment, discoverySchedulerPrincipalEnvironment, projectionRiskPrincipalEnvironment, projectionGraphPrincipalEnvironment, projectionSearchPrincipalEnvironment, runtimeCoordinatorPrincipalEnvironment, runtimeArchivePrincipalEnvironment, runtimeIndexPrincipalEnvironment, runtimeCorrelationPrincipalEnvironment, runtimeProjectionPrincipalEnvironment, gatewayControlPrincipalEnvironment, securityAgentAPIPrincipalEnvironment, securityAgentWorkerPrincipalEnvironment, securityAgentActionPrincipalEnvironment, redTeamWorkerPrincipalEnvironment, redTeamOutboxPrincipalEnvironment, redTeamAdapterPrincipalEnvironment, attackLabControllerPrincipalEnvironment, attackLabOutboxPrincipalEnvironment, attackLabProxyPrincipalEnvironment, recoveryWorkerPrincipalEnvironment, recoveryOutboxPrincipalEnvironment, policyDeploymentPrincipalEnvironment, "ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL", "ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL"} {
				name := fmt.Sprintf("profile_login_%02d", i)
				values[key] = name
				if _, err := owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
					t.Fatal(err)
				}
			}
			run := func(command string, wantSuccess bool) {
				t.Helper()
				cmd := exec.CommandContext(ctx, binary, command)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
				for key, value := range values {
					cmd.Env = append(cmd.Env, key+"="+value)
				}
				output, err := cmd.CombinedOutput()
				if (err == nil) != wantSuccess {
					var namespaces []string
					_ = owner.QueryRow(ctx, `SELECT COALESCE(array_agg(nspname::text ORDER BY nspname),ARRAY[]::text[]) FROM pg_namespace WHERE nspname ~ '^zasp_(temporal[0-9]+($|_)|authorization[0-9]+($|_))'`).Scan(&namespaces)
					t.Logf("owned native boundary namespaces=%v", namespaces)
					registration, _ := loadDiscoveryPrincipalRegistration(func(k string) string { return values[k] })
					diagnostic, _ := migrations.NewRunner(profileDiagnosticDatabase{Database: &migrationDatabase{connection: owner}, t: t})
					version, versionErr := diagnostic.Version(ctx)
					t.Logf("owned native version=%d error=%v", version, versionErr)
					diagnosticErr := runReleaseMigration(ctx, &registeredReleaseMigrationRunner{releaseMigrationRunner: diagnostic, queryer: owner, registration: registration}, []string{command})
					t.Logf("owned native diagnostic command=%s error=%v", command, diagnosticErr)
					t.Fatalf("%s success=%v: %v %s", command, wantSuccess, err, output)
				}
			}
			values[migrationPrincipalEnvironment] = "wrong_operator"
			run("up-authorization-runtime-profile", false)
			var absent bool
			if err := owner.QueryRow(ctx, `SELECT to_regclass('public.zasp_schema_versions') IS NULL`).Scan(&absent); err != nil || !absent {
				t.Fatal("wrong configured operator reached DDL", err)
			}
			values[migrationPrincipalEnvironment] = operator
			if start == "canonical61" {
				run("up-to-60", true)
				historical, _ := migrations.NewRunner(&migrationDatabase{connection: owner})
				if err := historical.UpProductionSecurityAgentMultistep(ctx); err != nil {
					t.Fatal("established retained 61 fixture", err)
				}
			}
			if start == "logical78_projection79" {
				run("up-to-60", true)
				for _, command := range temporalProfileCommands {
					run(command, true)
				}
				run("up-authorization-projection", true)
			}
			run("up-authorization-runtime-profile", true)
			run("register-temporal-executor-principals", true)
			run("register-temporal-executor-principals", true)
			values[migrationPrincipalEnvironment] = "wrong_operator"
			run("up-authorization-runtime-profile", false)
			run("register-temporal-executor-principals", false)
			values[migrationPrincipalEnvironment] = operator
			executor := values["ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL"]
			values["ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL"] = values["ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL"]
			run("register-temporal-executor-principals", false)
			values["ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL"] = "Invalid-Login"
			run("register-temporal-executor-principals", false)
			values["ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL"] = executor
			run("up-authorization-runtime-profile", true)
			var count int
			var catalog bool
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM public.zasp_schema_versions),zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_identity.structural_ready($1)`, migrations.AuthorizationIdentityProfileChecksum()).Scan(&count, &catalog); err != nil || count != 61 || !catalog {
				t.Fatal("exact current profile missing", count, catalog, err)
			}
			// A partial profile is not evidence that runtime families are complete.
			var runtime bool
			if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.runtime_ready()`).Scan(&runtime); err != nil {
				t.Fatal(err)
			}
			t.Logf("compiled native catalog ready; runtime readiness independently=%v", runtime)
			if _, err := owner.Exec(ctx, `CREATE SCHEMA zasp_authorization81`); err != nil {
				t.Fatal(err)
			}
			run("up-authorization-runtime-profile", false)
			if _, err := owner.Exec(ctx, `DROP SCHEMA zasp_authorization81`); err != nil {
				t.Fatal(err)
			}
			// Corrupt only this owned fixture as its superuser. Normal writes must
			// remain protected by the production immutable-authority trigger.
			if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica; UPDATE zasp_authorization80_worker.registration SET checksum=repeat('0',64); COMMIT`); err != nil {
				t.Fatal(err)
			}
			run("up-authorization-runtime-profile", false)
			if err := owner.QueryRow(ctx, `SELECT checksum=repeat('0',64) FROM zasp_authorization80_worker.registration`).Scan(&absent); err != nil || !absent {
				t.Fatal("drift was silently repaired", err)
			}
		})
	}
}

type profileDiagnosticDatabase struct {
	migrations.Database
	t *testing.T
}

func (d profileDiagnosticDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	d.t.Log("owned native diagnostic transaction began")
	tx, err := d.Database.Begin(ctx)
	return profileDiagnosticTransaction{Transaction: tx, t: d.t}, err
}

type profileDiagnosticTransaction struct {
	migrations.Transaction
	t *testing.T
}

func (tx profileDiagnosticTransaction) Exec(ctx context.Context, q string, args ...any) error {
	err := tx.Transaction.Exec(ctx, q, args...)
	if err != nil {
		tx.t.Logf("owned SQL exec error at %.100s: %v", q, err)
	}
	return err
}
func (tx profileDiagnosticTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	return profileDiagnosticRow{Row: tx.Transaction.QueryRow(ctx, q, args...), t: tx.t, q: q, tx: tx.Transaction, ctx: ctx}
}

type profileDiagnosticRow struct {
	migrations.Row
	t   *testing.T
	q   string
	tx  migrations.Transaction
	ctx context.Context
}

func (r profileDiagnosticRow) Scan(args ...any) error {
	err := r.Row.Scan(args...)
	if err != nil {
		r.t.Logf("owned SQL scan error at %.200s: %v", r.q, err)
	}
	if len(args) == 1 {
		if b, ok := args[0].(*bool); ok && !*b && (strings.Contains(r.q, "ready(") || strings.Contains(r.q, "readiness(")) {
			r.t.Logf("owned native readiness false: %.400s", r.q)
			if strings.Contains(r.q, "public.zasp_sa_multistep_readiness") {
				var predecessor bool
				var fingerprint string
				err := r.tx.QueryRow(r.ctx, `SELECT zasp_sa_multistep_prior.predecessor_ready($1,$2),public.zasp_sa_multistep_registered_live_fingerprint()`, migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&predecessor, &fingerprint)
				r.t.Logf("owned registered61 predecessor=%v actualFingerprint=%s expectedFingerprint=%s error=%v", predecessor, fingerprint, migrations.SecurityAgentMultistepRegisteredFingerprint(), err)
			}
		}
	}
	return err
}
