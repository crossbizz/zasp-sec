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

func globalControlBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("ZASP_TEST_MIGRATE_BINARY")
	if binary == "" {
		t.Skip("owned freshly compiled executable not supplied")
	}
	return binary
}

func TestGlobalExecutionControlBinaryPreflight(t *testing.T) {
	binary := globalControlBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, args := range [][]string{{"security-agent-global-read", "extra"}, {"security-agent-global-set", "extra"}, {"security-agent-global-set"}} {
		command := exec.Command(binary, args...)
		command.Env = []string{"ZASP_MIGRATION_TIMEOUT=5s", "ZASP_POSTGRES_DSN=postgres" + "://private-marker:credential@127.0.0.1:1/private-receipt"}
		output, err := testprocess.Run(ctx, command)
		if err == nil || !strings.Contains(string(output), "release migration configuration rejected") || strings.Contains(string(output), "private") || strings.Contains(string(output), "credential") {
			t.Fatalf("invalid arguments reached database or leaked input: %v %s", err, output)
		}
	}
}

// Only run the compiled linux/arm64 test inside the owned offline container.
// All durable assertions use an independent bootstrap connection.
func TestGlobalExecutionControlBinaryPostgres(t *testing.T) {
	binary := globalControlBinary(t)
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	admin := connectMigrationPostgres(t, ctx, dsn)
	defer admin.Close(context.Background())
	var directory string
	if err := admin.QueryRow(ctx, `SHOW data_directory`).Scan(&directory); err != nil || !strings.HasPrefix(directory, "/tmp/TestGlobalExecutionControlBinaryPostgres") || !strings.HasSuffix(directory, "/data") || admin.Config().Host != "127.0.0.1" || admin.Config().User != "zasp_test" {
		t.Fatal("refusing non-owned PostgreSQL fixture", directory, err)
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE global_cli_migration LOGIN SUPERUSER`); err != nil {
		t.Fatal(err)
	}
	operatorDSN := fmt.Sprintf("postgres://global_cli_migration@127.0.0.1:%d/postgres?sslmode=disable", admin.Config().Port)
	environment := []string{"ZASP_POSTGRES_DSN=" + operatorDSN, "ZASP_MIGRATION_TIMEOUT=30s", "ZASP_MIGRATION_DB_PRINCIPAL=global_cli_migration"}
	for index, key := range []string{
		discoveryAPIPrincipalEnvironment, discoveryWorkerPrincipalEnvironment, runtimeIngestPrincipalEnvironment, runtimeWorkerPrincipalEnvironment, outboxWorkerPrincipalEnvironment, runtimeGatewayPrincipalEnvironment,
		discoverySchedulerPrincipalEnvironment, projectionRiskPrincipalEnvironment, projectionGraphPrincipalEnvironment, projectionSearchPrincipalEnvironment, runtimeCoordinatorPrincipalEnvironment, runtimeArchivePrincipalEnvironment, runtimeIndexPrincipalEnvironment, runtimeCorrelationPrincipalEnvironment, runtimeProjectionPrincipalEnvironment, gatewayControlPrincipalEnvironment,
		securityAgentAPIPrincipalEnvironment, securityAgentWorkerPrincipalEnvironment, securityAgentActionPrincipalEnvironment, redTeamWorkerPrincipalEnvironment, redTeamOutboxPrincipalEnvironment, redTeamAdapterPrincipalEnvironment, attackLabControllerPrincipalEnvironment, attackLabOutboxPrincipalEnvironment, attackLabProxyPrincipalEnvironment, recoveryWorkerPrincipalEnvironment, recoveryOutboxPrincipalEnvironment, policyDeploymentPrincipalEnvironment,
	} {
		name := fmt.Sprintf("global_cli_login_%02d", index)
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		environment = append(environment, key+"="+name)
	}
	run := func(command string, env []string, want string) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 40*time.Second)
		defer stop()
		process := exec.Command(binary, command)
		process.Env = env
		output, err := testprocess.Run(bounded, process)
		if bounded.Err() != nil {
			t.Fatal("CLI exceeded bound", bounded.Err())
		}
		if want == "refuse" {
			if err == nil || (!strings.Contains(string(output), "release migration failed") && !strings.Contains(string(output), "release migration database unavailable")) || strings.Contains(string(output), "postgres://") || strings.Contains(string(output), "SELECT") || strings.Contains(string(output), "receipt") || strings.Contains(string(output), `"enabled"`) {
				t.Fatalf("unsafe refusal: %v %s", err, output)
			}
		} else if err != nil || string(output) != want {
			t.Fatalf("%s wanted %q got %q error=%v", command, want, output, err)
		}
	}
	run("up-to-55", environment, "")
	if _, err := admin.Exec(ctx, `ALTER ROLE global_cli_migration NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	operator := connectMigrationPostgres(t, ctx, operatorDSN)
	defer operator.Close(context.Background())
	var valid bool
	if err := operator.QueryRow(ctx, `SELECT session_user='global_cli_migration' AND current_user=session_user AND NOT rolsuper AND NOT rolbypassrls AND oid<>10 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND NOT pg_has_role(session_user,'zasp_security_agent_global_operator','MEMBER') AND EXISTS(SELECT 1 FROM zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') FROM pg_roles WHERE rolname=session_user`).Scan(&valid); err != nil || !valid {
		t.Fatal("incorrect operator session", valid, err)
	}
	if err := operator.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_readiness($1,$2)`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&valid); err != nil || !valid {
		t.Fatal("registered55 unavailable", err)
	}
	// Operational commands receive no principal-registration or mutation env for read.
	base := []string{"ZASP_POSTGRES_DSN=" + operatorDSN, "ZASP_MIGRATION_TIMEOUT=30s"}
	mutation := func(enabled, version, request, correlation string) []string {
		return append(append([]string{}, base...), "ZASP_SECURITY_AGENT_GLOBAL_ENABLED="+enabled, "ZASP_SECURITY_AGENT_GLOBAL_EXPECTED_VERSION="+version, "ZASP_SECURITY_AGENT_GLOBAL_REQUEST_ID="+request, "ZASP_SECURITY_AGENT_GLOBAL_CORRELATION_ID="+correlation)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('control',(SELECT jsonb_agg(to_jsonb(c) ORDER BY organization_id,workspace_id,environment_id,action_key) FROM zasp_security_agent_kill_switches c),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY request_id) FROM zasp_security_agent_global_control_receipts r),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY organization_id,audit_id) FROM zasp_security_agent_audit a))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	unchanged := func(before string) {
		t.Helper()
		if snapshot() != before {
			t.Fatal("read/replay/refusal changed durable state")
		}
	}
	before := snapshot()
	run("security-agent-global-read", base, "{\"enabled\":true,\"version\":1,\"replayed\":false}\n")
	unchanged(before)
	const stopID = "pid_7f560001-0000-4000-8000-000000000001"
	const enableID = "pid_7f560001-0000-4000-8000-000000000002"
	stopEnv := mutation("false", "1", stopID, "global-stop-test")
	run("security-agent-global-set", stopEnv, "{\"enabled\":false,\"version\":2,\"replayed\":false}\n")
	assertDurable := func(enabled bool, version int64, count int) {
		t.Helper()
		if err := admin.QueryRow(ctx, `SELECT (SELECT execution_enabled=$1 AND version=$2 AND updated_by='global_cli_migration' FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*')) AND (SELECT count(*)=$3 FROM zasp_security_agent_global_control_receipts) AND (SELECT count(*)=$3 FROM zasp_security_agent_audit WHERE organization_id='*') AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_global_control_receipts r LEFT JOIN zasp_security_agent_audit a ON (a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=('*','*','*',r.request_id) WHERE a.audit_id IS NULL OR r.caller_session<>'global_cli_migration' OR a.actor_id<>r.caller_session OR a.correlation_id<>r.correlation_id OR a.created_at<>r.created_at OR a.run_id IS NOT NULL OR a.step_id IS NOT NULL OR a.approval_id IS NOT NULL OR a.event_kind<>'kill_switch_changed' OR a.body<>jsonb_build_object('request_id',r.request_id,'actor',r.caller_session,'enabled',r.enabled,'expected_version',r.expected_version,'correlation_id',r.correlation_id,'version',r.resulting_version,'action_key','*') OR a.event_digest<>digest(convert_to(a.body::text,'UTF8'),'sha256') OR r.result<>jsonb_build_object('enabled',r.enabled,'version',r.resulting_version,'replayed',false)) AND EXISTS(SELECT 1 FROM zasp_security_agent_global_control_receipts WHERE request_id=$4 AND NOT enabled AND expected_version=1 AND resulting_version=2 AND correlation_id='global-stop-test')`, enabled, version, count, stopID).Scan(&valid); err != nil || !valid {
			t.Fatal("durable control/receipt/audit intent mismatch", valid, err)
		}
	}
	assertDurable(false, 2, 1)
	before = snapshot()
	run("security-agent-global-read", base, "{\"enabled\":false,\"version\":2,\"replayed\":false}\n")
	unchanged(before)
	run("security-agent-global-set", stopEnv, "{\"enabled\":false,\"version\":2,\"replayed\":true}\n")
	unchanged(before)
	for _, env := range [][]string{mutation("true", "1", stopID, "global-stop-test"), mutation("false", "2", stopID, "global-stop-test"), mutation("false", "1", stopID, "conflict"), mutation("true", "1", enableID, "enable")} {
		run("security-agent-global-set", env, "refuse")
		unchanged(before)
	}
	// Wrong release identity reaches SQL but cannot mutate or reveal internals.
	for _, pin := range []struct{ key, value string }{{"production_security_agent_existing_tests_checksum", migrations.ProductionSecurityAgentExistingTests().Checksum()}, {"production_security_agent_existing_tests_fingerprint", migrations.SecurityAgentExistingTestsFingerprint()}} {
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key=$1`, pin.key); err != nil {
			t.Fatal(err)
		}
		run("security-agent-global-read", base, "refuse")
		run("security-agent-global-set", stopEnv, "refuse")
		unchanged(before)
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$2 WHERE key=$1`, pin.key, pin.value); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"security-agent-global-read", "security-agent-global-set"} {
		env := append([]string{}, stopEnv...)
		env[0] = fmt.Sprintf("ZASP_POSTGRES_DSN=postgres://global_cli_login_00@127.0.0.1:%d/postgres?sslmode=disable", admin.Config().Port)
		run(command, env, "refuse")
		unchanged(before)
		env = append([]string{}, stopEnv...)
		env[1] = "ZASP_MIGRATION_TIMEOUT=1ns"
		run(command, env, "refuse")
		unchanged(before)
	}
	run("security-agent-global-set", mutation("true", "2", enableID, "global-enable-test"), "{\"enabled\":true,\"version\":3,\"replayed\":false}\n")
	assertDurable(true, 3, 2)
	if err := admin.QueryRow(ctx, `SELECT enabled AND expected_version=2 AND resulting_version=3 AND correlation_id='global-enable-test' FROM zasp_security_agent_global_control_receipts WHERE request_id=$1`, enableID).Scan(&valid); err != nil || !valid {
		t.Fatal("re-enable receipt mismatch", err)
	}
	before = snapshot()
	run("security-agent-global-set", stopEnv, "{\"enabled\":false,\"version\":2,\"replayed\":true}\n")
	unchanged(before)
	run("security-agent-global-read", base, "{\"enabled\":true,\"version\":3,\"replayed\":false}\n")
	unchanged(before)
	t.Logf("actual CLI %s; owned data=%s port=%d operator=global_cli_migration NOSUPERUSER NOBYPASSRLS; read/stop/replay/conflict/stale/reenable, bad authority, expired context and release drift independently verified", binary, directory, admin.Config().Port)
}
