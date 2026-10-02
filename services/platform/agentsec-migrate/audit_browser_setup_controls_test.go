package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestAuditBrowserSetupInputBoundary(t *testing.T) {
	good := map[string]string{"ZASP_AUDIT_BROWSER_SETUP": "true", "ZASP_AUDIT_BROWSER_SETUP_PORT": "54321", "ZASP_AUDIT_BROWSER_SETUP_DSN": "postgres://zasp_e2e@127.0.0.1:54321/postgres?sslmode=disable"}
	for _, key := range []string{"ZASP_AUDIT_BROWSER_SETUP", "ZASP_AUDIT_BROWSER_SETUP_PORT", "ZASP_AUDIT_BROWSER_SETUP_DSN"} {
		input := make(map[string]string)
		for k, v := range good {
			input[k] = v
		}
		delete(input, key)
		if _, err := validateAuditBrowserSetup(input); err == nil {
			t.Errorf("missing %s accepted", key)
		}
	}
	for _, dsn := range []string{"", "postgres://zasp_e2e@localhost:54321/postgres?sslmode=disable", "postgres://zasp_e2e@127.0.0.1:054321/postgres?sslmode=disable", "postgres://zasp_e2e_api@127.0.0.1:54321/postgres?sslmode=disable", "postgres://zasp_e2e@127.0.0.1:54321/other?sslmode=disable", good["ZASP_AUDIT_BROWSER_SETUP_DSN"] + "&options=-crole=owner", good["ZASP_AUDIT_BROWSER_SETUP_DSN"] + "&host=evil.invalid"} {
		input := make(map[string]string)
		for k, v := range good {
			input[k] = v
		}
		input["ZASP_AUDIT_BROWSER_SETUP_DSN"] = dsn
		if _, err := validateAuditBrowserSetup(input); err == nil {
			t.Error("unsafe DSN accepted")
		}
	}
	for _, key := range []string{"PGOPTIONS", "PGSERVICEFILE", "PGHOST", "ZASP_POSTGRES_DSN"} {
		input := make(map[string]string)
		for k, v := range good {
			input[k] = v
		}
		input[key] = ""
		if _, err := validateAuditBrowserSetup(input); err == nil {
			t.Errorf("ambient connection setting %s accepted", key)
		}
	}
	if got, err := validateAuditBrowserSetup(good); err != nil || got != good["ZASP_AUDIT_BROWSER_SETUP_DSN"] {
		t.Fatal("owned input refused", err)
	}
}

func TestAuditBrowserSetupOwnedPostgres(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(fmt.Sprintf("target_registered_%v", registered), func(t *testing.T) { auditBrowserSetupOwnedPostgres(t, registered) })
	}
}

func auditBrowserSetupOwnedPostgres(t *testing.T, registered bool) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	owner := connectMigrationPostgres(t, ctx, dsn)
	defer owner.Close(context.Background())
	if _, err := owner.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.User("zasp_e2e")
	admin := connectMigrationPostgres(t, ctx, parsed.String())
	defer admin.Close(context.Background())
	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "PG") && !strings.HasPrefix(entry, "ZASP_") {
			environment = append(environment, entry)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(env []string, want bool) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 25*time.Second)
		defer stop()
		child := exec.Command(binary, "-test.run=^TestProductionCombinedE2EAuditBrowserSetup$", "-test.v", "-test.timeout=23s")
		child.Env = env
		output, err := testprocess.Run(bounded, child)
		if bounded.Err() != nil || (err == nil) != want || strings.Contains(string(output), "SKIP") {
			t.Fatalf("explicit setup success=%v: %v %s", want, err, output)
		}
		if want && !strings.Contains(string(output), "compiled Runner") {
			t.Fatal("missing actual registration completion")
		}
	}
	// Explicit execution cannot earn success from the normal package skip.
	run(environment, false)
	environment = append(environment, "ZASP_AUDIT_BROWSER_SETUP=true", "ZASP_AUDIT_BROWSER_SETUP_PORT="+parsed.Port(), "ZASP_AUDIT_BROWSER_SETUP_DSN="+parsed.String())
	runner, err := migrations.NewRunner(&migrationDatabase{connection: admin})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-48"}); err != nil {
		version, _ := runner.Version(ctx)
		t.Fatalf("release target failed at installed version %d: %v", version, err)
	}
	snapshot := func(includeExport bool) string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor) FROM pg_auth_members m),'discovery',(SELECT jsonb_agg(to_jsonb(b) ORDER BY authority_role) FROM zasp_discovery_principal_bindings b),'runtime',(SELECT jsonb_agg(to_jsonb(b) ORDER BY authority_role) FROM zasp_runtime_principal_bindings b),'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY version) FROM zasp_schema_versions v),'metadata',(SELECT jsonb_agg(to_jsonb(m) ORDER BY key) FROM zasp_schema_metadata m),'export',CASE WHEN $1 THEN (SELECT jsonb_agg(to_jsonb(b) ORDER BY principal_name) FROM zasp_audit_export_api_bindings b) ELSE NULL END)::text`, includeExport).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	values := map[string]string{migrationPrincipalEnvironment: "zasp_e2e"}
	for index, key := range []string{discoveryAPIPrincipalEnvironment, discoveryWorkerPrincipalEnvironment, runtimeIngestPrincipalEnvironment, runtimeWorkerPrincipalEnvironment, outboxWorkerPrincipalEnvironment, runtimeGatewayPrincipalEnvironment, discoverySchedulerPrincipalEnvironment, projectionRiskPrincipalEnvironment, projectionGraphPrincipalEnvironment, projectionSearchPrincipalEnvironment, runtimeCoordinatorPrincipalEnvironment, runtimeArchivePrincipalEnvironment, runtimeIndexPrincipalEnvironment, runtimeCorrelationPrincipalEnvironment, runtimeProjectionPrincipalEnvironment, gatewayControlPrincipalEnvironment, securityAgentAPIPrincipalEnvironment, securityAgentWorkerPrincipalEnvironment, securityAgentActionPrincipalEnvironment, redTeamWorkerPrincipalEnvironment, redTeamOutboxPrincipalEnvironment, redTeamAdapterPrincipalEnvironment, attackLabControllerPrincipalEnvironment, attackLabOutboxPrincipalEnvironment, attackLabProxyPrincipalEnvironment, recoveryWorkerPrincipalEnvironment, recoveryOutboxPrincipalEnvironment, policyDeploymentPrincipalEnvironment} {
		name := fmt.Sprintf("zasp_audit_browser_%02d", index)
		if index == 0 {
			if registered {
				name = "zasp_e2e_api"
			}
		}
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		values[key] = name
	}
	registration, err := loadDiscoveryPrincipalRegistration(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if err := registerReleasePrincipals(ctx, admin, registration); err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-52"}); err != nil {
		t.Fatal("registered48 to compiled52", err)
	}
	if err := registerReleasePrincipals(ctx, admin, registration); err != nil {
		t.Fatal(err)
	}
	if !registered {
		if _, err := admin.Exec(ctx, `CREATE ROLE zasp_e2e_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		before := snapshot(true)
		run(environment, false)
		if snapshot(true) != before {
			t.Fatal("unregistered fixed target refusal changed exact grants/bindings/release")
		}
		t.Log("unregistered fixed API target refused on compiled52 without state changes")
		return
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_checksum'`); err != nil {
		t.Fatal(err)
	}
	drift := snapshot(true)
	run(environment, false)
	if snapshot(true) != drift {
		t.Fatal("drift refusal changed state")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_audit_exports_checksum'`, migrations.ProductionAuditExports().Checksum()); err != nil {
		t.Fatal(err)
	}
	unchanged := snapshot(false)
	run(environment, true)
	if snapshot(false) != unchanged {
		t.Fatal("registration widened roles or changed predecessor bindings/release")
	}
	registeredSnapshot := snapshot(true)
	run(environment, true)
	if snapshot(true) != registeredSnapshot {
		t.Fatal("replay changed binding or grants")
	}
	var exact bool
	if err := admin.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(principal_name='zasp_e2e_api') FROM zasp_audit_export_api_bindings`).Scan(&exact); err != nil || !exact {
		t.Fatal("fixed API binding missing", err)
	}
	t.Log("owned compiled52 Runner registration, refusal, replay and unchanged grants/bindings verified")
}
