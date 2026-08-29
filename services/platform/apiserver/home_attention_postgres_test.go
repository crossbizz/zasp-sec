package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionHomeAttentionPostgresInstallsExactTenantSummary(t *testing.T) {
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{
		runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution,
		runner.UpProductionRecovery, runner.UpProductionPolicyDeployment,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	metadata := migrations.ProductionHomeAttention()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v29 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_home_attention_live_fingerprint()`).Scan(&fingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionHomeAttentionSemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v29 candidate fingerprint=%s", fingerprint)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 up: %v", err)
	}
	scope := inventoryScope(t)
	foreignOrganization := integrationProductID(t, "pid_72000001-0000-4000-8000-000000000001")
	foreignScope, err := domain.NewScope(foreignOrganization, scope.WorkspaceID(), scope.EnvironmentID())
	if err != nil {
		t.Fatal(err)
	}
	seedScope := func(scopeValue domain.Scope) {
		t.Helper()
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,backfilled_at,equivalent_at,cutover_at) VALUES($1,$2,$3,'cutover','44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30',decode(repeat('aa',32),'hex'),decode(repeat('aa',32),'hex'),transaction_timestamp(),transaction_timestamp(),transaction_timestamp())`, scopeValue.OrganizationID().String(), scopeValue.WorkspaceID().String(), scopeValue.EnvironmentID().String()); err != nil {
			t.Fatal(err)
		}
	}
	seedScope(scope)
	seedScope(foreignScope)
	insertRun := func(scopeValue domain.Scope, id, state string, age string) {
		t.Helper()
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at,updated_at) VALUES($1,$2,$3,$4,'pid_73000001-0000-4000-8000-000000000001',1,'pid_73000002-0000-4000-8000-000000000002','pid_73000003-0000-4000-8000-000000000003',$5,transaction_timestamp()-$6::interval,transaction_timestamp()-$6::interval)`, scopeValue.OrganizationID().String(), scopeValue.WorkspaceID().String(), scopeValue.EnvironmentID().String(), id, state, age); err != nil {
			t.Fatal(err)
		}
	}
	insertRun(scope, "pid_74000001-0000-4000-8000-000000000001", "needs_human", "5 minutes")
	insertRun(scope, "pid_74000002-0000-4000-8000-000000000002", "failed", "4 minutes")
	insertRun(scope, "pid_74000003-0000-4000-8000-000000000003", "inconclusive", "3 minutes")
	insertRun(scope, "pid_74000004-0000-4000-8000-000000000004", "contained", "2 hours")
	insertRun(scope, "pid_74000005-0000-4000-8000-000000000005", "remediated", "1 hour")
	insertRun(scope, "pid_74000006-0000-4000-8000-000000000006", "contained", "25 hours")
	insertRun(foreignScope, "pid_74000007-0000-4000-8000-000000000007", "needs_human", "1 minute")
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at,created_at) VALUES($1,$2,$3,'pid_75000001-0000-4000-8000-000000000001','pid_74000001-0000-4000-8000-000000000001','pid_75000002-0000-4000-8000-000000000002',decode(repeat('bb',32),'hex'),'pending','pid_73000003-0000-4000-8000-000000000003',transaction_timestamp()+interval '5 minutes',transaction_timestamp()-interval '10 minutes')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresInventoryRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := repository.GetHomeSummary(ctx, scope)
	if err != nil || summary.PendingApprovals != 1 || summary.OldestApprovalAgeSeconds < 599 || summary.OldestApprovalAgeSeconds > 601 || summary.NeedsHumanRuns != 1 || summary.FailedRuns != 1 || summary.InconclusiveRuns != 1 || summary.RecentContained != 1 || summary.RecentRemediated != 1 || summary.Healthy || !summary.AttentionRequired {
		t.Fatalf("tenant summary=%#v err=%v", summary, err)
	}
	foreign, err := repository.GetHomeSummary(ctx, foreignScope)
	if err != nil || foreign.PendingApprovals != 0 || foreign.NeedsHumanRuns != 1 || foreign.FailedRuns != 0 || foreign.RecentContained != 0 {
		t.Fatalf("foreign summary=%#v err=%v", foreign, err)
	}
	if err := runner.DownProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 down: %v", err)
	}
	if err := runner.UpProductionHomeAttention(ctx); err != nil {
		t.Fatalf("v29 re-up: %v", err)
	}
	replayed, err := repository.GetHomeSummary(ctx, scope)
	if err != nil || replayed.PendingApprovals != 1 || replayed.NeedsHumanRuns != 1 || replayed.RecentContained != 1 {
		t.Fatalf("reapplied summary=%#v err=%v", replayed, err)
	}
}
