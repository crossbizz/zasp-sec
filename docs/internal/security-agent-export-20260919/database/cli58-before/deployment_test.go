package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Opt in only inside the owned Linux PostgreSQL fixture, with the actual CLI
// pre-built offline and mounted at this path. Never consume an ambient DSN.
func TestComplianceDeploymentBinaryOwnedPostgres(t *testing.T) {
	exerciseComplianceDeploymentBinaryOwnedPostgres(t, false)
}

func TestAttackLabDeploymentBinaryOwnedPostgres(t *testing.T) {
	exerciseComplianceDeploymentBinaryOwnedPostgres(t, true)
}

func exerciseComplianceDeploymentBinaryOwnedPostgres(t *testing.T, attackLab bool) {
	if runtime.GOOS != "linux" || os.Getenv("ZASP_COMPLIANCE_DEPLOYMENT_BINARY") != "/compliance-migrate" {
		t.Skip("requires owned Linux PostgreSQL fixture and mounted migration CLI")
	}
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	owner := connectMigrationPostgres(t, ctx, dsn)
	defer owner.Close(context.Background())
	seed := func(statement string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, statement, args...); err != nil {
			t.Fatalf("owned fixture setup: %v", err)
		}
	}
	seed(`CREATE ROLE fixture_admin LOGIN SUPERUSER; CREATE ROLE compliance_migrator LOGIN INHERIT SUPERUSER; CREATE ROLE compliance_executor LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE compliance_cleanup LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE audit_executor LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE audit_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
	adminConfig := owner.Config().Copy()
	adminConfig.User = "fixture_admin"
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	base := []string{"ZASP_MIGRATION_TIMEOUT=45s"}
	forward := append([]string{}, base...)
	forward = append(forward, "ZASP_MIGRATION_DB_PRINCIPAL=compliance_migrator")
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
		name := fmt.Sprintf("compliance_prior_%02d", index)
		seed(`CREATE ROLE ` + pgx.Identifier{name}.Sanitize() + ` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)
		forward = append(forward, key+"="+name)
	}
	run := func(label string, args, environment []string, selectedDSN, want string) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 50*time.Second)
		defer stop()
		command := exec.Command("/compliance-migrate", args...)
		command.Env = append(append([]string{}, environment...), "ZASP_POSTGRES_DSN="+selectedDSN)
		output, err := testprocess.Run(bounded, command)
		if bounded.Err() != nil || (err == nil) != (want == "") || (want != "" && !strings.Contains(string(output), want)) || (want == "" && len(output) != 0) {
			t.Fatalf("%s: CLI result=%v output=%q", label, err, output)
		}
		for _, secret := range []string{selectedDSN, "compliance_executor", "compliance_cleanup", "compliance_other", "private_marker", "SQLSTATE"} {
			if strings.Contains(string(output), secret) {
				t.Fatalf("%s: public output disclosed private input", label)
			}
		}
		t.Log("actual CLI:", label)
	}
	dsn = strings.Replace(dsn, "zasp_test@", "compliance_migrator@", 1)
	owner = connectMigrationPostgres(t, ctx, dsn)
	defer owner.Close(context.Background())
	run("bootstrap exact56 through published migration command", []string{"up-to-56"}, forward, dsn, "")
	var count int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_compliance_worker_bindings`).Scan(&count); err != nil || count != 0 {
		t.Fatal("forward migration registered compliance workers implicitly", count, err)
	}
	// The registered migration login owns the release objects. Remove all
	// superuser/role-creation powers before any compliance registration attempt.
	if _, err := admin.Exec(ctx, `ALTER ROLE compliance_migrator NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatalf("fixture role demotion: %#v", err)
	}
	var authority bool
	if err := owner.QueryRow(ctx, `SELECT session_user='compliance_migrator' AND r.rolcanlogin AND r.rolinherit AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND EXISTS(SELECT 1 FROM zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') FROM pg_roles r WHERE r.rolname=session_user`).Scan(&authority); err != nil || !authority {
		t.Fatal("registration fixture is not registered non-superuser authority", err)
	}
	t.Log("registered migration session verified: LOGIN INHERIT, NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")

	settings := append(append([]string{}, forward...),
		"ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL=audit_executor", "ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL=audit_outbox",
		"ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL=compliance_executor", "ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL=compliance_cleanup")
	for key, value := range auditExportConfigurationEnvironment() {
		settings = append(settings, key+"="+value)
	}
	chainCommand := "/compliance-migrate up-to-56 && /compliance-migrate register-audit-export-api && /compliance-migrate register-audit-export-workers && /compliance-migrate configure-audit-exports && exec /compliance-migrate register-compliance-workers"
	runChain := func(wantSuccess bool) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 60*time.Second)
		defer stop()
		command := exec.Command("/bin/sh", "-ec", chainCommand)
		command.Env = append(append([]string{}, settings...), "ZASP_POSTGRES_DSN="+dsn)
		output, err := testprocess.Run(bounded, command)
		refused := strings.Contains(string(output), "release migration failed") || strings.Contains(string(output), "release principal registration or readiness failed")
		if bounded.Err() != nil || (err == nil) != wantSuccess || (wantSuccess && len(output) != 0) || (!wantSuccess && !refused) {
			t.Fatalf("connected CLI chain: err=%v output=%q", err, output)
		}
		t.Log("actual CLI chain:", chainCommand, "success:", wantSuccess)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
		'compliance',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY principal_name),'[]') FROM zasp_compliance_worker_bindings b),
		'audit_workers',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY principal_name),'[]') FROM zasp_audit_export_worker_bindings b),
		'audit_api',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY principal_name),'[]') FROM zasp_audit_export_api_bindings b),
		'policies',(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY policy_id),'[]') FROM zasp_audit_export_policies p),
		'current',(SELECT jsonb_agg(to_jsonb(p)) FROM zasp_audit_export_current_policy p),
		'grants',(SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor),'[]') FROM pg_auth_members m))::text`).Scan(&value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	unchanged := func(before string) {
		t.Helper()
		if snapshot() != before {
			t.Fatal("refused operation changed bindings, policy or role grants")
		}
	}
	// State and readiness refusal happens before any of the optional registries
	// exists, then repeats after all registries have been populated.
	for _, populated := range []bool{false, true} {
		if populated {
			runChain(true)
			var exact bool
			err := admin.QueryRow(ctx, `SELECT
			(SELECT count(*)=2 AND bool_and((principal_name='audit_executor' AND authority_role='zasp_audit_export_worker') OR (principal_name='audit_outbox' AND authority_role='zasp_audit_export_outbox')) FROM zasp_audit_export_worker_bindings)
			AND (SELECT count(*)=1 AND bool_and(principal_name='compliance_prior_00' AND capability='audit-export-api-v1') FROM zasp_audit_export_api_bindings)
			AND (SELECT count(*)=2 AND bool_and((principal_name='compliance_executor' AND authority_role='zasp_compliance_worker') OR (principal_name='compliance_cleanup' AND authority_role='zasp_compliance_cleanup')) FROM zasp_compliance_worker_bindings)
			AND (SELECT count(*)=1 AND bool_and(policy_id='pid_75000001-0000-4000-8000-000000000001' AND bucket='owned-cli-export-fixture') FROM zasp_audit_export_policies)
			AND (SELECT policy_id='pid_75000001-0000-4000-8000-000000000001' FROM zasp_audit_export_current_policy WHERE singleton)
			AND public.zasp_compliance_readiness($1,$2)`, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&exact)
			if err != nil || !exact {
				t.Fatal("connected authority/configuration/readiness mismatch", err)
			}
			t.Log("both systems have exact independent bindings; audit policy selected; compiled56 readiness true")
			before := snapshot()
			runChain(true)
			unchanged(before)
		}
		for _, drift := range []struct{ label, apply, restore string }{
			{"invalid56 checksum", `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=56`, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=56`},
			{"unavailable56 readiness", `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_compliance_checksum'`, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_compliance_checksum'`},
		} {
			if _, err := admin.Exec(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			before := snapshot()
			for _, operation := range []string{"register-audit-export-api", "register-audit-export-workers", "configure-audit-exports", "register-compliance-workers"} {
				run(drift.label+"/"+operation, []string{operation}, settings, dsn, "release migration failed")
				unchanged(before)
			}
			runChain(false)
			unchanged(before)
			if _, err := admin.Exec(ctx, drift.restore, migrations.ProductionCompliance().Checksum()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if attackLab {
		// Schema DDL uses the controlled fixture's bootstrap authority. Registration
		// and the replayed rendered command chain then run with it demoted again.
		if _, err := admin.Exec(ctx, `ALTER ROLE compliance_migrator SUPERUSER; CREATE ROLE attack_lab_settlement LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		run("explicit57 bootstrap after exact56 assertions", []string{"up-to-57"}, forward, dsn, "")
		if _, err := admin.Exec(ctx, `ALTER ROLE compliance_migrator NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		settings = append(settings, "ZASP_SECURITY_AGENT_ATTACK_LAB_RECONCILER_DB_PRINCIPAL=attack_lab_settlement")
		chainCommand = strings.ReplaceAll(strings.ReplaceAll(chainCommand, "up-to-56", "up-to-57"), "exec /compliance-migrate register-compliance-workers", "/compliance-migrate register-compliance-workers") + " && exec /compliance-migrate register-security-agent-attack-lab-reconciler"
		for _, operation := range []string{"up-to-57", "register-audit-export-api", "register-audit-export-workers", "configure-audit-exports", "register-compliance-workers", "register-security-agent-attack-lab-reconciler"} {
			run("57 boundary "+operation, []string{operation}, settings, dsn, "")
		}
		runChain(true)
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_attack_lab_readiness($1,$2) AND NOT (SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname=session_user) AND (SELECT principal_name='attack_lab_settlement' AND authority_role='zasp_security_agent_attack_lab_reconciler' FROM zasp_sa_attack_lab_principals)`, migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("registered57 CLI readiness: %v", err)
		}
		// Existing-test reconciliation uses the baseline registered agent worker
		// capability, not a separate operational registration command.
		testConfig := owner.Config().Copy()
		testConfig.User = ""
		for _, entry := range forward {
			if value, ok := strings.CutPrefix(entry, securityAgentWorkerPrincipalEnvironment+"="); ok {
				testConfig.User = value
			}
		}
		if testConfig.User == "" {
			t.Fatal("existing-test principal missing from actual forward registration")
		}
		testConnection, err := pgx.ConnectConfig(ctx, testConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer testConnection.Close(context.Background())
		var scopes string
		if err := testConnection.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_reconcile_scopes('','','','coexistence-test-reconciler',$1,$2)::text`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&scopes); err != nil || scopes != "[]" {
			t.Fatalf("actual registered existing-test scope capability at57: %s %v", scopes, err)
		}
		t.Log("existing-test registered worker scope authority remains usable at57 through actual CLI baseline binding")
		before := snapshot()
		runChain(true)
		unchanged(before)
		for _, command := range []string{"up-to-59", "up", "up-to-56"} {
			run("57 refuses unsupported or implicit downgrade "+command, []string{command}, settings, dsn, "release migration failed")
			unchanged(before)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_attack_lab_checksum'`); err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"register-audit-export-api", "register-audit-export-workers", "configure-audit-exports", "register-compliance-workers", "register-security-agent-attack-lab-reconciler"} {
			run("57 drift refuses "+operation, []string{operation}, settings, dsn, "release migration failed")
			unchanged(before)
		}
		t.Log("LOCAL actual57 CLI chain and existing56 checks complete; no provider or credential provisioning")
	}
}
