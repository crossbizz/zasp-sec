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

func TestAuditExportConfigurationBinaryPreflight(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if output, err := testprocess.Run(ctx, exec.Command("go", "build", "-race", "-o", binary, ".")); err != nil {
		t.Fatalf("build migration executable: %v %s", err, output)
	}
	for _, arguments := range [][]string{{"configure-audit-exports"}, {"configure-audit-exports", "extra"}, {"register-audit-export-workers"}, {"register-audit-export-workers", "extra"}, {"register-audit-export-api"}, {"register-audit-export-api", "extra"}} {
		command := exec.Command(binary, arguments...)
		command.Env = []string{"ZASP_MIGRATION_TIMEOUT=5s", "ZASP_POSTGRES_DSN=postgres://private-marker.invalid/unreachable", "ZASP_AUDIT_EXPORT_POLICY_ID=private-marker"}
		output, err := testprocess.Run(ctx, command)
		if err == nil || !strings.Contains(string(output), "release migration configuration rejected") || strings.Contains(string(output), "private-marker") {
			t.Fatalf("invalid export configuration reached database or leaked input: %v %s", err, output)
		}
	}
}

// This is executable CLI compatibility acceptance, not an export lifecycle test.
// It uses only an owned disposable PostgreSQL and a newly built race-enabled
// binary. Export tables/retained-evidence rollback controls are a later slice.
func TestAuditExportsReleaseBinaryPostgres(t *testing.T) {
	for _, schema := range []int64{52, 53, 54} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) { testAuditExportsReleaseBinaryPostgres(t, schema) })
	}
}

func testAuditExportsReleaseBinaryPostgres(t *testing.T, configurationSchema int64) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	admin := connectMigrationPostgres(t, ctx, dsn)
	defer admin.Close(context.Background())
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	build := exec.Command("go", "build", "-race", "-o", binary, ".")
	if output, err := testprocess.Run(ctx, build); err != nil {
		t.Fatalf("build migration executable: %v %s", err, output)
	}

	// A leaked ambient PostgreSQL option would make real migration writes fail.
	// Explicit test DSN and freshly created login identities are the only authority.
	t.Setenv("PGOPTIONS", "-c default_transaction_read_only=on")
	t.Setenv("ZASP_MIGRATION_DB_PRINCIPAL", "ambient_must_not_be_used")
	environment := []string{"ZASP_POSTGRES_DSN=" + dsn, "ZASP_MIGRATION_TIMEOUT=30s", "ZASP_MIGRATION_DB_PRINCIPAL=zasp_test"}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
			environment = append(environment, entry)
		}
	}
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
		name := fmt.Sprintf("zasp_cli52_login_%02d", index)
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
	// Registry, all metadata and both original principal-binding sets must stay
	// byte-identical on refusal/retry. Include exact public zasp function bodies
	// and ACLs so an unnoticed partial compatibility replacement cannot pass.
	snapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
		 'versions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY version) FROM zasp_schema_versions r),
		 'metadata',(SELECT jsonb_agg(to_jsonb(r) ORDER BY key) FROM zasp_schema_metadata r),
		 'runtime_bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY authority_role) FROM zasp_runtime_principal_bindings r),
		 'discovery_bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY authority_role) FROM zasp_discovery_principal_bindings r),
		 'functions',(SELECT md5(string_agg(pg_get_functiondef(p.oid)||p.proowner::text||COALESCE(p.proacl::text,''),E'\n' ORDER BY p.proname,pg_get_function_identity_arguments(p.oid))) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'zasp_%' AND p.prokind='f'))::text`).Scan(&value); err != nil {
			t.Fatal("read release snapshot", err)
		}
		return value
	}
	unchanged := func(before, message string) {
		t.Helper()
		if snapshot() != before {
			t.Fatal(message)
		}
	}
	ready51 := func() {
		t.Helper()
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2) AND zasp_runtime_principals_ready()`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("published51 readiness/registration", ready, err)
		}
	}
	ready52 := func() {
		t.Helper()
		var ready bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("compiled52 readiness", ready, err)
		}
		ready51()
	}

	// Default command still stops at49 on a genuinely empty database.
	run([]string{"up"}, environment, true)
	version(49)
	run([]string{"up-to-51"}, environment, true)
	version(51)
	ready51()
	prior51 := snapshot()

	missing := []string{}
	for _, entry := range environment {
		if !strings.HasPrefix(entry, runtimeCoordinatorPrincipalEnvironment+"=") {
			missing = append(missing, entry)
		}
	}
	run([]string{"up-to-52"}, missing, false)
	unchanged(prior51, "missing registration mutated51 before preflight refused")
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	drifted51 := snapshot()
	run([]string{"up-to-52"}, environment, false)
	unchanged(drifted51, "binary installed52 over drifted51")
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_precision_checksum'`, migrations.ProductionRuntimePrecision().Checksum()); err != nil {
		t.Fatal(err)
	}
	unchanged(prior51, "fixture did not restore exact predecessor")

	// Keep a registered application connection alive across the actual CLI upgrade.
	config := admin.Config().Copy()
	config.User = "zasp_cli52_login_04"
	config.RuntimeParams = map[string]string{} // no ambient PGOPTIONS in this fixture
	outbox, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close(context.Background())
	oldClientReady := func(want bool) {
		t.Helper()
		var ready bool
		if err := outbox.QueryRow(ctx, `SELECT zasp_discovery_principal_ready('zasp_outbox_worker') AND zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || ready != want {
			t.Fatal("existing registered51 client readiness", ready, want, err)
		}
	}
	oldClientReady(true)
	run([]string{"up-to-52"}, environment, true)
	version(52)
	ready52()
	oldClientReady(true)
	installed52 := snapshot()
	// Exercise the budget release through the executable, including principal
	// registration, compiled readiness, idempotence and exact empty rollback.
	run([]string{"up-to-53"}, missing, false)
	unchanged(installed52, "budget preflight changed predecessor")
	run([]string{"up-to-53"}, environment, true)
	version(53)
	var budgetReady bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_readiness($1,$2)`, migrations.ProductionSecurityAgentBudgets().Checksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&budgetReady); err != nil || !budgetReady {
		t.Fatal("compiled53 readiness", budgetReady, err)
	}
	installed53 := snapshot()
	if configurationSchema == 54 {
		run([]string{"up-to-54"}, missing, false)
		unchanged(installed53, "run context preflight changed predecessor")
		run([]string{"up-to-54"}, environment, true)
		version(54)
		var contextReady bool
		if err := admin.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_readiness($1,$2)`, migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint()).Scan(&contextReady); err != nil || !contextReady {
			t.Fatal("compiled54 readiness", contextReady, err)
		}
		installed54 := snapshot()
		run([]string{"up-to-54"}, environment, true)
		unchanged(installed54, "run context retry changed release identity")
		for _, command := range []string{"up", "up-to-53", "down-to-52"} {
			run([]string{command}, environment, false)
			unchanged(installed54, "historical command changed run context release")
		}
		run([]string{"down-to-53"}, environment, true)
		version(53)
		unchanged(installed53, "run context rollback did not restore exact53")
	}
	run([]string{"up-to-53"}, environment, true)
	unchanged(installed53, "budget retry changed release identity")
	for _, command := range []string{"up", "up-to-52", "down-to-51"} {
		run([]string{command}, environment, false)
		unchanged(installed53, "historical command changed budget release")
	}
	run([]string{"down-to-52"}, environment, true)
	version(52)
	ready52()
	unchanged(installed52, "budget rollback did not restore exact predecessor")
	run([]string{"down-to-52"}, environment, true)
	unchanged(installed52, "budget rollback retry changed predecessor")
	if configurationSchema >= 53 {
		run([]string{"up-to-53"}, environment, true)
	}
	if configurationSchema == 54 {
		run([]string{"up-to-54"}, environment, true)
	}
	configurationSnapshot := snapshot()
	apiSnapshot := func() string {
		t.Helper()
		var result string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY principal_name) FROM zasp_audit_export_api_bindings b),'grants',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member) FROM pg_auth_members m))::text`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	var grantsBefore, grantsAfter string
	if err := admin.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY roleid,member),'[]'::jsonb)::text FROM pg_auth_members m`).Scan(&grantsBefore); err != nil {
		t.Fatal(err)
	}
	run([]string{"register-audit-export-api"}, environment, true)
	var exactAPI bool
	if err := admin.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(principal_name='zasp_cli52_login_00' AND capability='audit-export-api-v1') FROM zasp_audit_export_api_bindings`).Scan(&exactAPI); err != nil || !exactAPI {
		t.Fatal("API registration did not bind the exact discovery login", err)
	}
	if err := admin.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY roleid,member),'[]'::jsonb)::text FROM pg_auth_members m`).Scan(&grantsAfter); err != nil || grantsBefore != grantsAfter {
		t.Fatal("API registration changed role grants", err)
	}
	registeredAPI := apiSnapshot()
	run([]string{"register-audit-export-api"}, environment, true)
	for _, target := range []string{"", "zasp_cli52_login_01", "zasp_test", "not_registered_login"} {
		invalid := []string{}
		for _, entry := range environment {
			if !strings.HasPrefix(entry, discoveryAPIPrincipalEnvironment+"=") {
				invalid = append(invalid, entry)
			}
		}
		invalid = append(invalid, discoveryAPIPrincipalEnvironment+"="+target)
		run([]string{"register-audit-export-api"}, invalid, false)
	}
	run([]string{"register-audit-export-api", "extra"}, environment, false)
	if apiSnapshot() != registeredAPI {
		t.Fatal("API replay/refusal changed bindings or grants")
	}
	unchanged(configurationSnapshot, "API registration changed release authority")
	for _, name := range []string{"zasp_cli_export_executor", "zasp_cli_export_outbox"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	workerEnvironment := append(append([]string{}, environment...), "ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL=zasp_cli_export_executor", "ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL=zasp_cli_export_outbox")
	run([]string{"register-audit-export-workers"}, workerEnvironment, true)
	workerSnapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY principal_name) FROM zasp_audit_export_worker_bindings b),'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member) FROM pg_auth_members m WHERE member IN(SELECT oid FROM pg_roles WHERE rolname IN('zasp_cli_export_executor','zasp_cli_export_outbox'))))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	var exactWorkers bool
	if err := admin.QueryRow(ctx, `SELECT count(*)=2 AND bool_and((principal_name='zasp_cli_export_executor' AND authority_role='zasp_audit_export_worker') OR (principal_name='zasp_cli_export_outbox' AND authority_role='zasp_audit_export_outbox')) FROM zasp_audit_export_worker_bindings`).Scan(&exactWorkers); err != nil || !exactWorkers {
		t.Fatal("CLI did not register exact worker authority", err)
	}
	registeredWorkers := workerSnapshot()
	run([]string{"register-audit-export-workers"}, workerEnvironment, true)
	if workerSnapshot() != registeredWorkers {
		t.Fatal("worker registration replay changed role bindings/grants")
	}
	run([]string{"register-audit-export-workers", "extra"}, workerEnvironment, false)
	run([]string{"register-audit-export-workers"}, environment, false)
	if workerSnapshot() != registeredWorkers {
		t.Fatal("invalid registration changed authority")
	}
	unchanged(configurationSnapshot, "worker registration changed legacy authority")
	policyEnvironment := append([]string{}, environment...)
	for key, value := range auditExportConfigurationEnvironment() {
		policyEnvironment = append(policyEnvironment, key+"="+value)
	}
	run([]string{"configure-audit-exports"}, policyEnvironment, true)
	var policyID, policyDigest string
	if err := admin.QueryRow(ctx, `SELECT p.policy_id,encode(p.policy_digest,'hex') FROM zasp_audit_export_current_policy c JOIN zasp_audit_export_policies p USING(policy_id)`).Scan(&policyID, &policyDigest); err != nil || policyID != "pid_75000001-0000-4000-8000-000000000001" || len(policyDigest) != 64 {
		t.Fatal("binary did not persist owner policy", err)
	}
	policySnapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY policy_id) FROM zasp_audit_export_policies p),'current',(SELECT to_jsonb(c) FROM zasp_audit_export_current_policy c))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	configured := policySnapshot()
	var exactPolicy bool
	if err := admin.QueryRow(ctx, `SELECT bucket='owned-cli-export-fixture' AND expected_bucket_owner='123456789012' AND maximum_export_bytes=1073741824 AND maximum_retained_bytes=10737418240 AND maximum_inflight=2 AND capture_timeout_seconds=120 FROM zasp_audit_export_policies WHERE policy_id=$1`, policyID).Scan(&exactPolicy); err != nil || !exactPolicy {
		t.Fatal("CLI defaults/pins not stored exactly", err)
	}
	run([]string{"configure-audit-exports"}, policyEnvironment, true)
	if policySnapshot() != configured {
		t.Fatal("policy replay changed durable configuration")
	}
	for _, args := range [][]string{{"configure-audit-exports", "extra"}, {"configure-audit-exports"}} {
		env := policyEnvironment
		if len(args) == 1 {
			env = environment
		}
		run(args, env, false)
		if policySnapshot() != configured {
			t.Fatal("rejected configuration changed policy")
		}
	}
	unchanged(configurationSnapshot, "configuration altered schema/functions/principal registration")
	rotationEnvironment := []string{}
	for _, entry := range policyEnvironment {
		if !strings.HasPrefix(entry, "ZASP_AUDIT_EXPORT_POLICY_ID=") {
			rotationEnvironment = append(rotationEnvironment, entry)
		}
	}
	rotationEnvironment = append(rotationEnvironment, "ZASP_AUDIT_EXPORT_POLICY_ID=pid_75000003-0000-4000-8000-000000000003", "ZASP_AUDIT_EXPORT_EXPECTED_CURRENT_POLICY_ID="+policyID)
	run([]string{"configure-audit-exports"}, rotationEnvironment, true)
	var retainedPolicies int
	var selectedPolicy string
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_policies),policy_id FROM zasp_audit_export_current_policy`).Scan(&retainedPolicies, &selectedPolicy); err != nil || retainedPolicies != 2 || selectedPolicy != "pid_75000003-0000-4000-8000-000000000003" {
		t.Fatal("CLI rotation did not retain/select exact revisions", err)
	}
	rotated := policySnapshot()
	run([]string{"configure-audit-exports"}, rotationEnvironment, true)
	run([]string{"configure-audit-exports"}, policyEnvironment, false)
	if policySnapshot() != rotated {
		t.Fatal("old CLI retry rewound or changed retained policy")
	}
	if configurationSchema == 54 {
		run([]string{"down-to-53"}, environment, true)
	}
	if configurationSchema >= 53 {
		run([]string{"down-to-52"}, environment, true)
	}
	run([]string{"up-to-52"}, environment, true)
	unchanged(installed52, "idempotent52 changed registry, definitions or bindings")
	for _, arguments := range [][]string{{"up"}, {"up-to-48"}, {"up-to-49"}, {"up-to-50"}, {"up-to-51"}, {"down"}, {"down-to-49"}, {"down-to-50"}, {"up-to-52", "extra"}, {"down-to-51", "extra"}} {
		run(arguments, environment, false)
		unchanged(installed52, "mixed/historical command changed52")
	}
	for _, key := range []string{"production_audit_exports_checksum", "production_audit_exports_fingerprint"} {
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key=$1`, key); err != nil {
			t.Fatal(err)
		}
		drifted := snapshot()
		oldClientReady(false)
		run([]string{"register-audit-export-workers"}, workerEnvironment, false)
		if workerSnapshot() != registeredWorkers {
			t.Fatal("registration under drift changed worker authority")
		}
		run([]string{"configure-audit-exports"}, rotationEnvironment, false)
		if policySnapshot() != rotated {
			t.Fatal("configuration under readiness drift changed policy")
		}
		run([]string{"up-to-52"}, environment, false)
		run([]string{"down-to-51"}, environment, false)
		unchanged(drifted, "rejected drift repaired or altered52")
		correct := migrations.ProductionAuditExports().Checksum()
		if key == "production_audit_exports_fingerprint" {
			correct = migrations.ProductionAuditExportsSemanticFingerprint()
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$2 WHERE key=$1`, key, correct); err != nil {
			t.Fatal(err)
		}
	}
	unchanged(installed52, "drift fixture restoration changed52")
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(53,'unsupported_future_release',repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	future := snapshot()
	oldClientReady(false)
	run([]string{"up-to-52"}, environment, false)
	run([]string{"down-to-51"}, environment, false)
	unchanged(future, "binary rewrote unknown53")
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_schema_versions WHERE version=53 AND name='unsupported_future_release'`); err != nil {
		t.Fatal(err)
	}
	ready52()
	run([]string{"down-to-51"}, environment, true)
	version(51)
	ready51()
	oldClientReady(true)
	unchanged(prior51, "52Down failed to restore original51 definitions or authority")
	run([]string{"down-to-51"}, environment, true)
	unchanged(prior51, "idempotent down-to51 changed restored51")
	run([]string{"up-to-52"}, environment, true)
	version(52)
	ready52()
	t.Logf("built CLI audit configuration schema%d verified; restored52 checksum=%s fingerprint=%s; default49, registered51 bridge, explicit upgrade/retry, preflight/drift/future/mixed refusal and exact rollback/reinstall; no export artifact or retained-export guard proof", configurationSchema, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint())
}
