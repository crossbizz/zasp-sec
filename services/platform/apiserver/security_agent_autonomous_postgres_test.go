package apiserver

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionSecurityAgentAutonomousResponsePostgresInstallsExactAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	metadata := migrations.ProductionSecurityAgentAutonomousResponse()
	if err := runner.UpProductionSecurityAgentAutonomousResponse(ctx); err != nil {
		t.Fatalf("v21 up: %v", err)
	}
	var fingerprint string
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_autonomous_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionSecurityAgentAutonomousResponseSemanticFingerprint() {
		t.Fatalf("v21 fingerprint=%s", fingerprint)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_autonomous_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v21 readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE security_agent_autonomous_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE security_agent_autonomous_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_autonomous_api_login','security_agent_autonomous_worker_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("principal registration=%t err=%v", ready, err)
	}
	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		config, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		config.User = principal
		value, connectErr := pgx.ConnectConfig(ctx, config)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		return value
	}
	api := connectAs("security_agent_autonomous_api_login")
	defer api.Close(context.Background())
	worker := connectAs("security_agent_autonomous_worker_login")
	defer worker.Close(context.Background())
	workerDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	workerRepository, err := NewSecurityAgentWorkerRepository(workerDatabase)
	if err != nil {
		t.Fatalf("v21 worker repository: %v", err)
	}

	type tenantFixture struct {
		organization, workspace, environment, definition, finding, activation string
	}
	tenants := []tenantFixture{
		{"pid_7b000001-0000-4000-8000-000000000001", "pid_7b000002-0000-4000-8000-000000000002", "pid_7b000003-0000-4000-8000-000000000003", "pid_7b000004-0000-4000-8000-000000000004", "pid_7b000005-0000-4000-8000-000000000005", "supervised"},
		{"pid_7c000001-0000-4000-8000-000000000001", "pid_7c000002-0000-4000-8000-000000000002", "pid_7c000003-0000-4000-8000-000000000003", "pid_7c000004-0000-4000-8000-000000000004", "pid_7c000005-0000-4000-8000-000000000005", "autonomous"},
	}
	for index, tenant := range tenants {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,$2,$3)`, []any{tenant.organization, "Security tenant", "security-" + string(rune('a'+index)) + ".invalid"}},
			{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production')`, []any{tenant.workspace, tenant.organization}},
			{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, []any{tenant.environment, tenant.organization, tenant.workspace}},
		} {
			if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		body := json.RawMessage(`{"id":"` + tenant.definition + `","name":"Automatic credential response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + tenant.environment + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["update_finding_response"],"verification_kind":"finding_state","definition_version":1,"enabled":true}`)
		persistedActivation := tenant.activation
		if tenant.activation == "autonomous" {
			persistedActivation = "supervised"
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,$5,4,1,$6,'security-agent-actions-v1')`, tenant.organization, tenant.workspace, tenant.environment, tenant.definition, persistedActivation, body); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,'pid_7d000001-0000-4000-8000-000000000001'),($1,$2,$3,'update_finding_response',true,'pid_7d000001-0000-4000-8000-000000000001')`, tenant.organization, tenant.workspace, tenant.environment); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Discovered credential exposure','high','open')`, tenant.organization, tenant.workspace, tenant.environment, tenant.finding); err != nil {
			t.Fatal(err)
		}
	}
	var activationResult json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,'pid_7c000020-0000-4000-8000-000000000020','activate-autonomous-e2e-0001',4,'autonomous',transaction_timestamp()+interval '5 minutes','pid_7c000021-0000-4000-8000-000000000021','pid_7c000022-0000-4000-8000-000000000022','pid_7c000023-0000-4000-8000-000000000023')`, tenants[1].organization, tenants[1].workspace, tenants[1].environment, tenants[1].definition).Scan(&activationResult); err != nil {
		t.Fatalf("autonomous activation: %v", err)
	}
	var storedActivation, storedAutonomy string
	if err := connection.QueryRow(ctx, `SELECT activation,body->>'autonomy' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, tenants[1].organization, tenants[1].workspace, tenants[1].environment, tenants[1].definition).Scan(&storedActivation, &storedAutonomy); err != nil || storedActivation != "autonomous" || storedAutonomy != "autonomous" {
		t.Fatalf("stored activation=%s autonomy=%s err=%v result=%s", storedActivation, storedAutonomy, err, activationResult)
	}
	if created, err := workerRepository.ScheduleSecurityAgentTriggers(ctx, "security-agent-worker-e2e", 10); err != nil || created != 2 {
		t.Fatalf("automatic scheduling created=%d err=%v", created, err)
	}
	claims, err := workerRepository.ClaimSecurityAgentRuns(ctx, "security-agent-worker-e2e", "lease-token-autonomous-0001", 60, 10)
	if err != nil || len(claims) != 2 {
		t.Fatalf("initial claims=%#v err=%v", claims, err)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].OrganizationID < claims[j].OrganizationID })
	for index, claim := range claims {
		approvalID := []string{"pid_7b000010-0000-4000-8000-000000000010", "pid_7c000010-0000-4000-8000-000000000010"}[index]
		auditID := []string{"pid_7b000011-0000-4000-8000-000000000011", "pid_7c000011-0000-4000-8000-000000000011"}[index]
		correlationID := []string{"pid_7b000012-0000-4000-8000-000000000012", "pid_7c000012-0000-4000-8000-000000000012"}[index]
		expiresAt := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
		if !validSecurityAgentRunClaim(claim) || claim.Prepared || !validSecurityAgentWorkerIdentity("security-agent-worker-e2e", "lease-token-autonomous-0001") || !validProductID(approvalID) || !validProductID(auditID) || !validProductID(correlationID) || expiresAt.Location() != time.UTC {
			t.Fatalf("invalid prepare fixture claim=%#v approval=%t audit=%t correlation=%t", claim, validProductID(approvalID), validProductID(auditID), validProductID(correlationID))
		}
		result, prepareErr := workerRepository.PrepareSecurityAgentRun(ctx, claim, "security-agent-worker-e2e", "lease-token-autonomous-0001", approvalID, expiresAt, auditID, correlationID)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		if tenants[index].activation == "supervised" && (result.State != "waiting_approval" || result.ApprovalID != approvalID) {
			t.Fatalf("supervised prepare=%#v", result)
		}
		if tenants[index].activation == "autonomous" && (result.State != "queued" || result.ApprovalID != "") {
			t.Fatalf("autonomous prepare=%#v", result)
		}
	}

	autonomousClaims, err := workerRepository.ClaimSecurityAgentRuns(ctx, "security-agent-worker-e2e", "lease-token-autonomous-0002", 60, 10)
	if err != nil || len(autonomousClaims) != 1 || autonomousClaims[0].OrganizationID != tenants[1].organization || !autonomousClaims[0].Prepared {
		t.Fatalf("autonomous claims=%#v err=%v", autonomousClaims, err)
	}
	if _, err := workerRepository.ExecuteSecurityAgentRun(ctx, autonomousClaims[0], "security-agent-worker-e2e", "lease-token-autonomous-0002", "pid_7c000013-0000-4000-8000-000000000013", "pid_7c000014-0000-4000-8000-000000000014"); err != nil {
		t.Fatalf("autonomous execute: %v", err)
	}
	var supervisedApproval string
	if err := connection.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE organization_id=$1`, tenants[0].organization).Scan(&supervisedApproval); err != nil {
		t.Fatal(err)
	}
	var decision json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval($1,$2,$3,$4,'pid_7b000020-0000-4000-8000-000000000020','approve-automatic-run-0001',1,'approved',transaction_timestamp(),'pid_7b000021-0000-4000-8000-000000000021','pid_7b000022-0000-4000-8000-000000000022','pid_7b000023-0000-4000-8000-000000000023')`, tenants[0].organization, tenants[0].workspace, tenants[0].environment, supervisedApproval).Scan(&decision); err != nil {
		t.Fatalf("supervised approval: %v", err)
	}
	supervisedClaims, err := workerRepository.ClaimSecurityAgentRuns(ctx, "security-agent-worker-e2e", "lease-token-autonomous-0003", 60, 10)
	if err != nil || len(supervisedClaims) != 1 || supervisedClaims[0].OrganizationID != tenants[0].organization || !supervisedClaims[0].Prepared {
		t.Fatalf("supervised claims=%#v err=%v", supervisedClaims, err)
	}
	if _, err := workerRepository.ExecuteSecurityAgentRun(ctx, supervisedClaims[0], "security-agent-worker-e2e", "lease-token-autonomous-0003", "pid_7b000024-0000-4000-8000-000000000024", "pid_7b000025-0000-4000-8000-000000000025"); err != nil {
		t.Fatalf("supervised execute: %v", err)
	}
	for index, tenant := range tenants {
		var findingState, runState, authorization string
		var approvalCount, foreignEffectCount int
		if err := connection.QueryRow(ctx, `SELECT finding.status,run.state,step.authorization_result,(SELECT count(*) FROM zasp_security_agent_approvals approval WHERE approval.organization_id=$1),(SELECT count(*) FROM zasp_security_agent_effects effect WHERE effect.organization_id<>$1 AND effect.run_id=run.run_id) FROM zasp_risk_findings finding JOIN zasp_security_agent_runs run ON (run.organization_id,run.workspace_id,run.environment_id,run.trigger_id)=(finding.organization_id,finding.workspace_id,finding.environment_id,finding.id) JOIN zasp_security_agent_steps step ON (step.organization_id,step.workspace_id,step.environment_id,step.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id) WHERE (finding.organization_id,finding.id)=($1,$2)`, tenant.organization, tenant.finding).Scan(&findingState, &runState, &authorization, &approvalCount, &foreignEffectCount); err != nil {
			t.Fatal(err)
		}
		wantAuthorization := []string{"approval_required", "autonomous"}[index]
		wantApprovals := []int{1, 0}[index]
		if findingState != "under_review" || runState != "remediated" || authorization != wantAuthorization || approvalCount != wantApprovals || foreignEffectCount != 0 {
			t.Fatalf("tenant %d finding=%s run=%s authorization=%s approvals=%d foreign_effects=%d", index, findingState, runState, authorization, approvalCount, foreignEffectCount)
		}
	}
}

func TestProductionSecurityAgentAutonomousResponseFingerprintIsStableAcrossMigrationPrincipals(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bootstrap, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close(context.Background())
	if _, err := bootstrap.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "zasp_e2e"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []struct {
		name string
		run  func(context.Context) error
	}{{"v15", runner.UpProductionRuntimeDataPlane}, {"v16", runner.UpProductionRuntimeGatewayReconciliation}, {"v17", runner.UpProductionRuntimeIngestReconciliation}, {"v18", runner.UpProductionSecurityAgentExecution}, {"v19", runner.UpProductionIdentityAdministration}, {"v20", runner.UpProductionSecurityAgentControls}} {
		if err := apply.run(ctx); err != nil {
			t.Fatalf("%s: %v", apply.name, err)
		}
	}
	var controlsFingerprint, controlsACL string
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_controls_live_fingerprint(),concat_ws('|',(SELECT COALESCE(string_agg(procedure.proname||'='||COALESCE(procedure.proacl::text,''),',' ORDER BY procedure.proname),'') FROM pg_proc procedure WHERE procedure.proname=ANY(ARRAY['zasp_security_agent_set_kill_switch','zasp_security_agent_execution_control_detail','zasp_security_agent_mutate_execution_control','zasp_security_agent_controls_security_ready'])),(SELECT COALESCE(class.relacl::text,'') FROM pg_class class WHERE class.oid='public.zasp_environments'::regclass))`).Scan(&controlsFingerprint, &controlsACL); err != nil {
		t.Fatal(err)
	}
	if controlsFingerprint != migrations.ProductionSecurityAgentControlsSemanticFingerprint() {
		t.Fatalf("v20 migration principal fingerprint=%s expected=%s acl=%s", controlsFingerprint, migrations.ProductionSecurityAgentControlsSemanticFingerprint(), controlsACL)
	}
	if err := runner.UpProductionSecurityAgentAutonomousResponse(ctx); err != nil {
		t.Fatalf("v21: %v", err)
	}
	var fingerprint, acl string
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_autonomous_live_fingerprint(),COALESCE(proacl::text,'') FROM pg_proc WHERE oid='public.zasp_security_agent_sync_autonomy_v21()'::regprocedure`).Scan(&fingerprint, &acl); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionSecurityAgentAutonomousResponseSemanticFingerprint() {
		t.Fatalf("migration principal fingerprint=%s expected=%s acl=%s", fingerprint, migrations.ProductionSecurityAgentAutonomousResponseSemanticFingerprint(), acl)
	}
}
