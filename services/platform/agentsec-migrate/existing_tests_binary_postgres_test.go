package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The owned offline container mounts a freshly compiled executable. This test
// never uses a deployed DSN or an executable obtained from the application PATH.
func TestExistingTestsReleaseBinaryPostgres(t *testing.T) {
	binary := os.Getenv("ZASP_TEST_MIGRATE_BINARY")
	if binary == "" {
		t.Skip("owned migration executable not supplied")
	}
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	admin := connectMigrationPostgres(t, ctx, dsn)
	defer admin.Close(context.Background())
	environment := []string{"ZASP_POSTGRES_DSN=" + dsn, "ZASP_MIGRATION_TIMEOUT=30s", "ZASP_MIGRATION_DB_PRINCIPAL=zasp_test"}
	for index, key := range []string{
		discoveryAPIPrincipalEnvironment, discoveryWorkerPrincipalEnvironment, runtimeIngestPrincipalEnvironment,
		runtimeWorkerPrincipalEnvironment, outboxWorkerPrincipalEnvironment, runtimeGatewayPrincipalEnvironment,
		discoverySchedulerPrincipalEnvironment, projectionRiskPrincipalEnvironment, projectionGraphPrincipalEnvironment,
		projectionSearchPrincipalEnvironment, runtimeCoordinatorPrincipalEnvironment, runtimeArchivePrincipalEnvironment,
		runtimeIndexPrincipalEnvironment, runtimeCorrelationPrincipalEnvironment, runtimeProjectionPrincipalEnvironment,
		gatewayControlPrincipalEnvironment, securityAgentAPIPrincipalEnvironment, securityAgentWorkerPrincipalEnvironment,
		securityAgentActionPrincipalEnvironment, redTeamWorkerPrincipalEnvironment, redTeamOutboxPrincipalEnvironment,
		redTeamAdapterPrincipalEnvironment, attackLabControllerPrincipalEnvironment, attackLabOutboxPrincipalEnvironment,
		attackLabProxyPrincipalEnvironment, recoveryWorkerPrincipalEnvironment, recoveryOutboxPrincipalEnvironment,
		policyDeploymentPrincipalEnvironment,
	} {
		name := fmt.Sprintf("zasp_cli55_login_%02d", index)
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		environment = append(environment, key+"="+name)
	}
	run := func(command string, success bool) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 40*time.Second)
		defer stop()
		process := exec.Command(binary, command)
		process.Env = environment
		output, err := testprocess.Run(bounded, process)
		if bounded.Err() != nil || (err == nil) != success {
			var lastVersion int64
			stateErr := admin.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM zasp_schema_versions`).Scan(&lastVersion)
			t.Fatalf("%s success=%v at schema%d (state error=%v): %v %s", command, success, lastVersion, stateErr, err, output)
		}
		if !success && !strings.Contains(string(output), "release migration failed") && !strings.Contains(string(output), "release principal registration or readiness failed") {
			t.Fatalf("unexpected refusal: %s", output)
		}
	}
	version := func(want int64) {
		t.Helper()
		var got int64
		if err := admin.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&got); err != nil || got != want {
			t.Fatalf("version=%d want=%d err=%v", got, want, err)
		}
	}
	ready55 := func() {
		t.Helper()
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_readiness($1,$2) AND zasp_security_agent_principals_ready()`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("schema55 readiness=%v err=%v", ready, err)
		}
	}
	snapshot := func() string {
		t.Helper()
		var state string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('versions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY version) FROM zasp_schema_versions r),'metadata',(SELECT jsonb_agg(to_jsonb(r) ORDER BY key) FROM zasp_schema_metadata r),'functions',(SELECT md5(string_agg(pg_get_functiondef(p.oid)||p.proowner::text||COALESCE(p.proacl::text,''),E'\n' ORDER BY p.proname,pg_get_function_identity_arguments(p.oid))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_%' AND p.prokind='f'))::text`).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	// The actual executable must bootstrap registration inside the migration
	// chain, without an operator first invoking a separate predecessor command.
	run("up-to-55", true)
	version(55)
	ready55()
	before := snapshot()
	run("up-to-55", true)
	ready55()
	if snapshot() != before {
		t.Fatal("idempotent replay changed release")
	}
	run("up", false)
	run("up-to-54", false)
	if snapshot() != before {
		t.Fatal("historical command changed release")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_existing_tests_checksum'`); err != nil {
		t.Fatal(err)
	}
	drift := snapshot()
	run("up-to-55", false)
	run("down-to-54", false)
	if snapshot() != drift {
		t.Fatal("drift refusal changed release")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_existing_tests_checksum'`, migrations.ProductionSecurityAgentExistingTests().Checksum()); err != nil {
		t.Fatal(err)
	}
	run("down-to-54", true)
	version(54)
	run("down-to-54", true)
	version(54)
	run("up-to-55", true)
	version(55)
	ready55()
}
