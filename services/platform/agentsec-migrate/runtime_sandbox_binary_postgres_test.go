package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The parent owns an isolated PostgreSQL cluster at49 with all login roles.
// This exercises main(), argument/env loading, migration and registration in a
// compiled child process. It leaves the empty fixture at49 for older controls.
func verifySandboxMigrationBinary(t *testing.T, ctx context.Context, dsn string, connection *pgx.Conn, principals []string) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := testprocess.Run(ctx, build); err != nil {
		t.Fatalf("build migration executable: %v %s", err, output)
	}
	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "ZASP_POSTGRES_DSN="+dsn, "ZASP_MIGRATION_TIMEOUT=30s")
	run := func(argument string, settings []string, succeeds bool) {
		t.Helper()
		command := exec.Command(binary, argument)
		command.Env = append(append([]string{}, environment...), settings...)
		output, err := testprocess.Run(ctx, command)
		if ctx.Err() != nil || (err == nil) != succeeds {
			t.Fatalf("migration binary %s success=%t: %v output=%q", argument, succeeds, err, output)
		}
		if strings.Contains(string(output), dsn) {
			t.Fatal("migration executable exposed its database connection string")
		}
	}
	check := func(version int) {
		t.Helper()
		var actual int
		if err := connection.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&actual); err != nil || actual != version {
			t.Fatal("binary changed unexpected schema version", actual, version, err)
		}
	}
	// Removing the explicit50 classification from main must break this: missing
	// principal configuration must reject before any schema mutation.
	missing := []string{}
	for _, entry := range principals {
		if !strings.HasPrefix(entry, "ZASP_RUNTIME_INDEX_DB_PRINCIPAL=") {
			missing = append(missing, entry)
		}
	}
	run("up-to-50", missing, false)
	check(49)
	var before string
	if err := connection.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY authority_role)::text FROM zasp_runtime_principal_bindings b`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		run("up-to-50", principals, true)
		check(50)
		var ready bool
		var after string
		if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2) AND zasp_runtime_principals_ready()`, migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("binary50 did not establish compiled readiness", ready, err)
		}
		if err := connection.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY authority_role)::text FROM zasp_runtime_principal_bindings b`).Scan(&after); err != nil || after != before {
			t.Fatal("binary50 changed existing principal bindings", err)
		}
	}
	run("up", principals, false)
	check(50)
	run("up-to-52", principals, false)
	check(50)
	run("down-to-49", nil, true)
	check(49)
	run("down-to-49", nil, true)
	check(49)
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_readiness($1,$2) AND zasp_runtime_principals_ready()`, migrations.ProductionRuntimeCorrelationRouting().Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("binary rollback did not restore compiled49 readiness", ready, err)
	}
	t.Log("compiled executable with explicit environment: invalid50 config preserves49; install/retry50; compiled readiness and immutable bindings; plain up/unknown52 rejected; clean rollback/retry49")
}
