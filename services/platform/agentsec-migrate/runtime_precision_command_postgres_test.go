package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Invoke the built application, including main's configuration, principal
// registration and final readiness, against an owned disposable PostgreSQL.
func TestPrecisionReleaseBinaryPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	admin := connectMigrationPostgres(t, ctx, dsn)
	defer admin.Close(context.Background())
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	build := exec.Command("go", "build", "-race", "-o", binary, ".")
	if output, err := testprocess.Run(ctx, build); err != nil {
		t.Fatalf("build migration binary: %v %s", err, output)
	}
	environment := []string{"ZASP_POSTGRES_DSN=" + dsn, "ZASP_MIGRATION_TIMEOUT=30s", "ZASP_MIGRATION_DB_PRINCIPAL=zasp_test"}
	// Never inherit ambient database or authority configuration into the child.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			environment = append(environment, entry)
		}
	}
	for i, key := range []string{discoveryAPIPrincipalEnvironment, discoveryWorkerPrincipalEnvironment, runtimeIngestPrincipalEnvironment, runtimeWorkerPrincipalEnvironment, outboxWorkerPrincipalEnvironment, runtimeGatewayPrincipalEnvironment, discoverySchedulerPrincipalEnvironment, projectionRiskPrincipalEnvironment, projectionGraphPrincipalEnvironment, projectionSearchPrincipalEnvironment, runtimeCoordinatorPrincipalEnvironment, runtimeArchivePrincipalEnvironment, runtimeIndexPrincipalEnvironment, runtimeCorrelationPrincipalEnvironment, runtimeProjectionPrincipalEnvironment, gatewayControlPrincipalEnvironment, securityAgentAPIPrincipalEnvironment, securityAgentWorkerPrincipalEnvironment, securityAgentActionPrincipalEnvironment, redTeamWorkerPrincipalEnvironment, redTeamOutboxPrincipalEnvironment, redTeamAdapterPrincipalEnvironment, attackLabControllerPrincipalEnvironment, attackLabOutboxPrincipalEnvironment, attackLabProxyPrincipalEnvironment, recoveryWorkerPrincipalEnvironment, recoveryOutboxPrincipalEnvironment, policyDeploymentPrincipalEnvironment} {
		name := fmt.Sprintf("zasp_cli51_login_%02d", i)
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		environment = append(environment, key+"="+name)
	}
	run := func(arguments []string, env []string, wantSuccess bool) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 35*time.Second)
		defer stop()
		command := exec.Command(binary, arguments...)
		command.Env = env
		output, err := testprocess.Run(bounded, command)
		if bounded.Err() != nil || (err == nil) != wantSuccess {
			t.Fatalf("binary %v success=%v: %v %s", arguments, wantSuccess, err, output)
		}
	}
	version := func(want int64) {
		t.Helper()
		var got int64
		if err := admin.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&got); err != nil || got != want {
			t.Fatal("binary target", got, want, err)
		}
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('versions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY version) FROM zasp_schema_versions r),'metadata',(SELECT jsonb_agg(to_jsonb(r) ORDER BY key) FROM zasp_schema_metadata r),'bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY authority_role) FROM zasp_runtime_principal_bindings r))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	run([]string{"up-to-50"}, environment, true)
	version(50)
	before := snapshot()
	missing := []string{}
	for _, entry := range environment {
		if !strings.HasPrefix(entry, runtimeCoordinatorPrincipalEnvironment+"=") {
			missing = append(missing, entry)
		}
	}
	run([]string{"up-to-51"}, missing, false)
	if snapshot() != before {
		t.Fatal("invalid registration changed predecessor state")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_sandbox_binding_checksum'`); err != nil {
		t.Fatal(err)
	}
	brokenPredecessor := snapshot()
	run([]string{"up-to-51"}, environment, false)
	if snapshot() != brokenPredecessor {
		t.Fatal("binary installed51 over a drifted predecessor")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_sandbox_binding_checksum'`, migrations.ProductionRuntimeSandboxBinding().Checksum()); err != nil {
		t.Fatal(err)
	}
	run([]string{"up-to-51"}, environment, true)
	version(51)
	checkReady := func() {
		t.Helper()
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2) AND zasp_runtime_principals_ready()`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("binary registered51 readiness", ready, err)
		}
	}
	checkReady()
	outboxConfig := admin.Config().Copy()
	outboxConfig.User = "zasp_cli51_login_04"
	outbox, err := pgx.ConnectConfig(ctx, outboxConfig)
	if err != nil {
		t.Fatal(err)
	}
	var outboxReady bool
	if err := outbox.QueryRow(ctx, `SELECT zasp_discovery_principal_ready('zasp_outbox_worker') AND zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&outboxReady); err != nil || !outboxReady {
		t.Fatal("registered outbox precision authority", outboxReady, err)
	}
	if err := outbox.Close(ctx); err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	run([]string{"up-to-51"}, environment, true)
	if snapshot() != before {
		t.Fatal("idempotent binary invocation changed registry or bindings")
	}
	for _, arguments := range [][]string{{"up"}, {"up-to-48"}, {"up-to-49"}, {"up-to-50"}, {"down"}, {"down-to-49"}, {"up-to-51", "extra"}} {
		run(arguments, environment, false)
		if snapshot() != before {
			t.Fatal("mixed command changed51", arguments)
		}
	}
	// Existing51 must not turn idempotency into permission to ignore drift.
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	drifted := snapshot()
	run([]string{"up-to-51"}, environment, false)
	if snapshot() != drifted {
		t.Fatal("rejected drift repaired or altered release state")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_precision_checksum'`, migrations.ProductionRuntimePrecision().Checksum()); err != nil {
		t.Fatal(err)
	}
	checkReady()
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(52,'unsupported_future_release',repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	future := snapshot()
	run([]string{"up-to-51"}, environment, false)
	if snapshot() != future {
		t.Fatal("binary rewrote future release")
	}
	t.Log("built migration executable proves explicit50→51, registration, compiled readiness, exact retry, drift/future/mixed refusal; historical down commands cannot remove51")
}
