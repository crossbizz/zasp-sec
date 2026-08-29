package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionApprovalNotificationPostgresDeduplicatesAndIsolatesMinimalPayload(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `
CREATE ROLE approval_notification_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_discovery_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_discovery_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_ingest LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE approval_notification_gateway LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	for _, apply := range []func(context.Context) error{
		runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse,
		runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation,
		runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	metadata := migrations.ProductionApprovalNotification()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v30 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_approval_notification_live_fingerprint()`).Scan(&fingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionApprovalNotificationSemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v30 candidate fingerprint=%s", fingerprint)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 up: %v", err)
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals(session_user,'approval_notification_discovery_api','approval_notification_discovery_worker','approval_notification_ingest','approval_notification_runtime','approval_notification_outbox','approval_notification_gateway')`).Scan(&registered); err != nil || !registered {
		t.Fatalf("discovery register=%t err=%v", registered, err)
	}
	registered = false
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'approval_notification_api_login','approval_notification_worker_login')`).Scan(&registered); err != nil || !registered {
		t.Fatalf("register=%t err=%v", registered, err)
	}

	identity := fixtureRequestIdentity(t)
	organization := identity.Scope.OrganizationID().String()
	workspace := identity.Scope.WorkspaceID().String()
	environment := identity.Scope.EnvironmentID().String()
	foreignOrganization := "pid_76ffffff-ffff-4fff-8fff-ffffffffffff"
	integration := "pid_76000010-0000-4000-8000-000000000010"
	foreignIntegration := "pid_76000011-0000-4000-8000-000000000011"
	run := "pid_76000012-0000-4000-8000-000000000012"
	foreignRun := "pid_76000013-0000-4000-8000-000000000013"
	approval := "pid_76000014-0000-4000-8000-000000000014"
	foreignApproval := "pid_76000015-0000-4000-8000-000000000015"
	invalidRun := "pid_76000016-0000-4000-8000-000000000016"
	invalidApproval := "pid_76000017-0000-4000-8000-000000000017"
	webhookBody := func(id string) string {
		return `{"id":"` + id + `","connector_key":"generic-webhook","name":"Approval webhook","configuration":{"destination_url":"https://hooks.example.test/zasp","signing_secret_reference":"secret_ref_approval_prod"},"status":"configured","created_at":"2026-08-28T00:00:00Z","updated_at":"2026-08-28T00:00:00Z"}`
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,$5::jsonb),($6,$2,$3,'integration',$7,$8::jsonb)`, organization, workspace, environment, integration, webhookBody(integration), foreignOrganization, foreignIntegration, webhookBody(foreignIntegration)); err != nil {
		t.Fatal(err)
	}
	insertRun := func(org, id string) {
		t.Helper()
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES($1,$2,$3,$4,'pid_76000020-0000-4000-8000-000000000020',1,'pid_76000021-0000-4000-8000-000000000021','pid_76000022-0000-4000-8000-000000000022','waiting_approval')`, org, workspace, environment, id); err != nil {
			t.Fatal(err)
		}
	}
	insertRun(organization, run)
	insertRun(foreignOrganization, foreignRun)
	insertApproval := func(org, approvalID, runID string) {
		t.Helper()
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) VALUES($1,$2,$3,$4,$5,'pid_76000023-0000-4000-8000-000000000023',decode(repeat('aa',32),'hex'),'pending','pid_76000022-0000-4000-8000-000000000022',transaction_timestamp()+interval '10 minutes') ON CONFLICT DO NOTHING`, org, workspace, environment, approvalID, runID); err != nil {
			t.Fatal(err)
		}
	}
	insertApproval(organization, approval, run)
	insertApproval(organization, approval, run)
	insertApproval(foreignOrganization, foreignApproval, foreignRun)
	var localCount, foreignCount int
	var payload json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT count(*),(jsonb_agg(payload ORDER BY delivery_id)->0) FROM zasp_security_agent_approval_notifications WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, organization, workspace, environment).Scan(&localCount, &payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_approval_notifications WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, foreignOrganization, workspace, environment).Scan(&foreignCount); err != nil {
		t.Fatal(err)
	}
	if localCount != 1 || foreignCount != 1 || !strings.Contains(string(payload), `"event": "security_agent.approval_required"`) || !strings.Contains(string(payload), approval) || strings.Contains(string(payload), "evidence") || strings.Contains(string(payload), "secret") || strings.Contains(string(payload), "credential") {
		t.Fatalf("counts=%d/%d payload=%s", localCount, foreignCount, payload)
	}

	configuration, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.User = "approval_notification_api_login"
	api, err := pgx.ConnectConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	leaseToken := strings.Repeat("b", 64)
	apiDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewApprovalNotificationPostgresRepository(apiDatabase)
	if err != nil {
		t.Fatal(err)
	}
	secrets := &findingTicketSecretResolverStub{material: []byte(strings.Repeat("s", 32))}
	webhook := &approvalNotificationWebhookStub{}
	reconciler, err := NewApprovalNotificationReconciler(ApprovalNotificationReconcilerConfig{
		Repository: authority, Secrets: secrets, Webhook: webhook, Owner: "agentsec-api:test", LeaseSeconds: 30,
		NewLeaseToken: func() (string, error) { return leaseToken, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !reconciler.Ready() || secrets.calls != 1 || webhook.calls != 1 || webhook.payload != string(payload) || strings.Contains(webhook.payload, "evidence") || strings.Contains(webhook.payload, "secret") {
		t.Fatalf("reconciler ready=%t secret/webhook=%d/%d payload=%s", reconciler.Ready(), secrets.calls, webhook.calls, webhook.payload)
	}
	var localState, foreignState string
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_security_agent_approval_notifications WHERE (organization_id,workspace_id,environment_id,approval_id)=($1,$2,$3,$4)`, organization, workspace, environment, approval).Scan(&localState); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_security_agent_approval_notifications WHERE (organization_id,workspace_id,environment_id,approval_id)=($1,$2,$3,$4)`, foreignOrganization, workspace, environment, foreignApproval).Scan(&foreignState); err != nil {
		t.Fatal(err)
	}
	if localState != "delivered" || foreignState != "pending" {
		t.Fatalf("notification states local/foreign=%s/%s", localState, foreignState)
	}

	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{configuration,destination_url}','"https://127.0.0.1"'::jsonb) WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organization, workspace, environment, integration); err != nil {
		t.Fatal(err)
	}
	insertRun(organization, invalidRun)
	insertApproval(organization, invalidApproval, invalidRun)
	var invalidCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_approval_notifications WHERE (organization_id,workspace_id,environment_id,approval_id)=($1,$2,$3,$4)`, organization, workspace, environment, invalidApproval).Scan(&invalidCount); err != nil {
		t.Fatal(err)
	}
	if invalidCount != 0 {
		t.Fatalf("invalid destination enqueued %d poisoned notification rows", invalidCount)
	}

	for _, cleanup := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM zasp_security_agent_approval_notifications`, nil},
		{`DELETE FROM zasp_security_agent_approvals WHERE approval_id IN($1,$2,$3)`, []any{approval, foreignApproval, invalidApproval}},
		{`DELETE FROM zasp_security_agent_runs WHERE run_id IN($1,$2,$3)`, []any{run, foreignRun, invalidRun}},
		{`DELETE FROM zasp_workflow_records WHERE id IN($1,$2)`, []any{integration, foreignIntegration}},
	} {
		if _, err := connection.Exec(ctx, cleanup.query, cleanup.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := runner.DownProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 down: %v", err)
	}
	if err := runner.UpProductionApprovalNotification(ctx); err != nil {
		t.Fatalf("v30 re-up: %v", err)
	}
}
