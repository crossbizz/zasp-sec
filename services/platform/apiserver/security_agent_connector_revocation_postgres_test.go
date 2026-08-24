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

func TestProductionSecurityAgentConnectorRevocationPostgresInstallsExactAuthority(t *testing.T) {
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())

	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{
		runner.UpProductionRuntimeDataPlane,
		runner.UpProductionRuntimeGatewayReconciliation,
		runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution,
		runner.UpProductionIdentityAdministration,
		runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse,
		runner.UpProductionSecurityAgentTemporaryPolicy,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}

	metadata := migrations.ProductionSecurityAgentConnectorRevocation()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v23 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatalf("v23 SQL: %v", err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_security_agent_connector_revocation_live_fingerprint()`).Scan(&fingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionSecurityAgentConnectorRevocationSemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v23 candidate fingerprint=%s", fingerprint)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionSecurityAgentConnectorRevocation(ctx); err != nil {
		t.Fatalf("v23 up: %v", err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_connector_revocation_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v23 readiness=%t err=%v", ready, err)
	}
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{name: "column", apply: `ALTER TABLE zasp_security_agent_connector_revocations ADD COLUMN review_drift text`, restore: `ALTER TABLE zasp_security_agent_connector_revocations DROP COLUMN review_drift`},
		{name: "index", apply: `CREATE INDEX review_connector_revocation_drift_idx ON zasp_security_agent_connector_revocations(environment_id)`, restore: `DROP INDEX review_connector_revocation_drift_idx`},
		{name: "policy", apply: `CREATE POLICY review_connector_revocation_drift_policy ON zasp_security_agent_connector_revocations FOR SELECT TO zasp_security_agent_action_worker USING(true)`, restore: `DROP POLICY review_connector_revocation_drift_policy ON zasp_security_agent_connector_revocations`},
	} {
		if _, err := connection.Exec(ctx, drift.apply); err != nil {
			t.Fatalf("apply %s drift: %v", drift.name, err)
		}
		if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_connector_revocation_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || ready {
			t.Fatalf("v23 %s drift readiness=%t err=%v", drift.name, ready, err)
		}
		if _, err := connection.Exec(ctx, drift.restore); err != nil {
			t.Fatalf("restore %s drift: %v", drift.name, err)
		}
		if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_connector_revocation_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
			t.Fatalf("v23 restored %s readiness=%t err=%v", drift.name, ready, err)
		}
	}
	if _, err := connection.Exec(ctx, `
CREATE ROLE security_agent_v23_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v23_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v23_action_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v23_connector_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT zasp_discovery_worker TO security_agent_v23_connector_login`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_v23_api_login','security_agent_v23_worker_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("planner principals ready=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_action_principal(session_user,'security_agent_v23_action_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("action principal ready=%t err=%v", ready, err)
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
	plannerConnection := connectAs("security_agent_v23_worker_login")
	defer plannerConnection.Close(context.Background())
	actionConnection := connectAs("security_agent_v23_action_login")
	defer actionConnection.Close(context.Background())
	apiConnection := connectAs("security_agent_v23_api_login")
	defer apiConnection.Close(context.Background())
	connectorConnection := connectAs("security_agent_v23_connector_login")
	defer connectorConnection.Close(context.Background())
	plannerDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: plannerConnection})
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewSecurityAgentWorkerRepository(plannerDatabase)
	if err != nil {
		t.Fatal(err)
	}
	actionDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: actionConnection})
	if err != nil {
		t.Fatal(err)
	}
	actionRepository, err := NewSecurityAgentActionRepository(actionDatabase)
	if err != nil {
		t.Fatal(err)
	}

	organizationID := "pid_7f000001-0000-4000-8000-000000000001"
	workspaceID := "pid_7f000002-0000-4000-8000-000000000002"
	environmentID := "pid_7f000003-0000-4000-8000-000000000003"
	integrationID := "pid_7f000004-0000-4000-8000-000000000004"
	connectionID := "pid_7f000005-0000-4000-8000-000000000005"
	credentialID := "pid_7f000006-0000-4000-8000-000000000006"
	syncID := "pid_7f000007-0000-4000-8000-000000000007"
	snapshotID := "pid_7f000008-0000-4000-8000-000000000008"
	findingID := "pid_7f000009-0000-4000-8000-000000000009"
	evidenceID := "pid_7f000010-0000-4000-8000-000000000010"
	entityID := "pid_7f000023-0000-4000-8000-000000000023"
	definitionID := "pid_7f000011-0000-4000-8000-000000000011"
	actorID := "pid_7f000012-0000-4000-8000-000000000012"
	connectionReference := "ref:github/installation/123456"
	definition := json.RawMessage(`{"id":"` + definitionID + `","name":"Revoke exposed integration","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["revoke_integration_connection"],"verification_kind":"connection_state","definition_version":1,"enabled":true}`)
	workflow := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Production GitHub","configuration":{},"status":"active","updated_at":"2026-08-21T00:00:00Z"}`)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'V23 tenant','v23.invalid')`, []any{organizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production')`, []any{workspaceID, organizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, []any{environmentID, organizationID, workspaceID}},
		{`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,credential_reference,state) VALUES($1,$2,$3,$4,'github','collector-v1','Production GitHub','{}',$5,'active')`, []any{organizationID, workspaceID, environmentID, integrationID, connectionReference}},
		{`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'integration',$4,1,$5)`, []any{organizationID, workspaceID, environmentID, integrationID, workflow}},
		{`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,$5,'github',$6,'verified',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, integrationID, connectionID, connectionReference}},
		{`INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES($1,$2,$3,$4,$5,'github','github_installation_reference',$6,1,'{"installation_id":"123456"}')`, []any{organizationID, workspaceID, environmentID, credentialID, integrationID, connectionReference}},
		{`INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'security-agent-v23-sync-0001',decode(repeat('01',32),'hex'),'manual',$6,'queued','parser-v1','tool-v1')`, []any{organizationID, workspaceID, environmentID, syncID, integrationID, actorID}},
		{`INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'github','s3://zasp-evidence/v23/manifest.json',decode(repeat('02',32),'hex'),'complete',decode(repeat('03',32),'hex'),'{}',true,true,transaction_timestamp(),transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, snapshotID, integrationID, syncID}},
		{`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Exposed integration credential','critical','open')`, []any{organizationID, workspaceID, environmentID, findingID}},
		{`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$4,'repository','Production repository','active',transaction_timestamp(),transaction_timestamp(),'asset')`, []any{organizationID, workspaceID, environmentID, entityID}},
		{`INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,NULL,'s3://zasp-evidence/v23/finding.json',decode(repeat('04',32),'hex'),'application/json','1','parser-v1',transaction_timestamp(),'github',1,'s3://zasp-evidence/v23/finding.json','v23/finding.json','version-v23-0001',128,'tool-v1')`, []any{organizationID, workspaceID, environmentID, evidenceID, integrationID, snapshotID, entityID}},
		{`INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, []any{organizationID, workspaceID, environmentID, findingID, evidenceID}},
		{`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,$5,'security-agent-actions-v1')`, []any{organizationID, workspaceID, environmentID, definitionID, definition}},
		{`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,$4),($1,$2,$3,'revoke_integration_connection',true,$4)`, []any{organizationID, workspaceID, environmentID, actorID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", statement.sql, err)
		}
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{status}','"configured"'::jsonb) WHERE kind='integration' AND id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("non-actionable schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{status}','"active"'::jsonb) WHERE kind='integration' AND id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{connector_key}','"okta"'::jsonb) WHERE kind='integration' AND id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("workflow-provider mismatch schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{connector_key}','"github"'::jsonb) WHERE kind='integration' AND id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET kind='okta' WHERE id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("typed-provider mismatch schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET kind='github' WHERE id=$1`, integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integration_connections SET connection_reference='ref:github/installation/not-a-number' WHERE id=$1`, connectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_credentials SET credential_reference='ref:github/installation/not-a-number' WHERE id=$1`, credentialID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("unactionable reference schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integration_connections SET connection_reference=$2 WHERE id=$1`, connectionID, connectionReference); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_credentials SET credential_reference=$2 WHERE id=$1`, credentialID, connectionReference); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integration_connections SET provider='nango:test' WHERE id=$1`, connectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_credentials SET provider='nango:test',credential_class='nango_connection_reference' WHERE id=$1`, credentialID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("unsupported provider schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integration_connections SET provider='github' WHERE id=$1`, connectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_credentials SET provider='github',credential_class='github_app_reference' WHERE id=$1`, credentialID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("unsupported credential class schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_credentials SET credential_class='github_installation_reference' WHERE id=$1`, credentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,'pid_7f000021-0000-4000-8000-000000000021','okta','ref:okta/oauth/654321','verified',transaction_timestamp())`, organizationID, workspaceID, environmentID, integrationID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("ambiguous connection schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_integration_connections WHERE id='pid_7f000021-0000-4000-8000-000000000021'`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES($1,$2,$3,'pid_7f000022-0000-4000-8000-000000000022',$4,'github','github_app_reference',$5,1,'{"installation_id":"123456"}')`, organizationID, workspaceID, environmentID, integrationID, connectionReference); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 0 {
		t.Fatalf("ambiguous credential schedule=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_connector_credentials WHERE id='pid_7f000022-0000-4000-8000-000000000022'`); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-planner", 10); err != nil || created != 1 {
		t.Fatalf("schedule=%d err=%v", created, err)
	}
	claims, err := planner.ClaimSecurityAgentRuns(ctx, "security-agent-v23-planner", "planner-lease-token-v23-0001", 60, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	approvalID := "pid_7f000013-0000-4000-8000-000000000013"
	prepared, err := planner.PrepareSecurityAgentRun(ctx, claims[0], "security-agent-v23-planner", "planner-lease-token-v23-0001", approvalID, time.Now().UTC().Add(15*time.Minute).Truncate(time.Microsecond), "pid_7f000014-0000-4000-8000-000000000014", "pid_7f000015-0000-4000-8000-000000000015")
	if err != nil || prepared.State != "waiting_approval" {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	if _, err := planner.ClaimSecurityAgentRuns(ctx, "security-agent-v23-planner", "planner-lease-token-v23-denied", 60, 10); err != nil {
		t.Fatal(err)
	}
	var approvalPayload json.RawMessage
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_approval_detail_v23($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, approvalID).Scan(&approvalPayload); err != nil || !strings.Contains(string(approvalPayload), `"reversible": false`) || !strings.Contains(string(approvalPayload), `"expected_effect": "Revoke integration connection"`) {
		t.Fatalf("approval=%s err=%v", approvalPayload, err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval_v23($1,$2,$3,$4,$5,'security-agent-v23-approval-denied',1,'approved',transaction_timestamp(),$6,$7,$8)`, organizationID, workspaceID, environmentID, approvalID, actorID, "pid_7f000016-0000-4000-8000-000000000116", "pid_7f000017-0000-4000-8000-000000000117", "pid_7f000018-0000-4000-8000-000000000118").Scan(&approvalPayload); err == nil {
		t.Fatal("non-admin actor approved irreversible connector revocation")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-v23','member-v23','security_admin',true)`, actorID, organizationID); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval_v23($1,$2,$3,$4,$5,'security-agent-v23-approval-0001',1,'approved',transaction_timestamp(),$6,$7,$8)`, organizationID, workspaceID, environmentID, approvalID, actorID, "pid_7f000016-0000-4000-8000-000000000016", "pid_7f000017-0000-4000-8000-000000000017", "pid_7f000018-0000-4000-8000-000000000018").Scan(&approvalPayload); err != nil {
		t.Fatalf("approve: %v", err)
	}
	claims, err = planner.ClaimSecurityAgentRuns(ctx, "security-agent-v23-planner", "planner-lease-token-v23-0002", 60, 10)
	if err != nil || len(claims) != 1 || !claims[0].Prepared {
		t.Fatalf("approved claims=%#v err=%v", claims, err)
	}
	authorizationTx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizationTx.QueryRow(ctx, `SELECT true FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4) FOR UPDATE`, organizationID, workspaceID, environmentID, integrationID).Scan(&ready); err != nil {
		_ = authorizationTx.Rollback(ctx)
		t.Fatal(err)
	}
	dispatchDone := make(chan error, 1)
	go func() {
		_, dispatchErr := planner.ExecuteSecurityAgentRun(ctx, claims[0], "security-agent-v23-planner", "planner-lease-token-v23-0002", "pid_7f000019-0000-4000-8000-000000000319", "pid_7f000020-0000-4000-8000-000000000320")
		dispatchDone <- dispatchErr
	}()
	select {
	case dispatchErr := <-dispatchDone:
		_ = authorizationTx.Rollback(ctx)
		t.Fatalf("dispatch bypassed workflow serialization: %v", dispatchErr)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := authorizationTx.Exec(ctx, `INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,'pid_7f000024-0000-4000-8000-000000000024','okta','ref:okta/oauth/999999','verified',transaction_timestamp())`, organizationID, workspaceID, environmentID, integrationID); err != nil {
		_ = authorizationTx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := authorizationTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case dispatchErr := <-dispatchDone:
		if dispatchErr == nil {
			t.Fatal("authorization race dispatched an ambiguous connector")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authorization-race dispatch did not finish")
	}
	var prematureEffects int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_effects WHERE integration_id=$1 AND operation='revoke'`, integrationID).Scan(&prematureEffects); err != nil || prematureEffects != 0 {
		t.Fatalf("authorization race effects=%d err=%v", prematureEffects, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_integration_connections WHERE id='pid_7f000024-0000-4000-8000-000000000024'`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_findings SET status='resolved' WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.ExecuteSecurityAgentRun(ctx, claims[0], "security-agent-v23-planner", "planner-lease-token-v23-0002", "pid_7f000019-0000-4000-8000-000000000119", "pid_7f000020-0000-4000-8000-000000000120"); err == nil {
		t.Fatal("closed finding dispatched irreversible connector revocation")
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_effects WHERE integration_id=$1 AND operation='revoke'`, integrationID).Scan(&prematureEffects); err != nil || prematureEffects != 0 {
		t.Fatalf("closed finding effects=%d err=%v", prematureEffects, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_findings SET status='open',version=version+1 WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.ExecuteSecurityAgentRun(ctx, claims[0], "security-agent-v23-planner", "planner-lease-token-v23-0002", "pid_7f000019-0000-4000-8000-000000000219", "pid_7f000020-0000-4000-8000-000000000220"); err == nil {
		t.Fatal("version-drifted finding dispatched irreversible connector revocation")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_findings SET version=version-1 WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	dispatched, err := planner.ExecuteSecurityAgentRun(ctx, claims[0], "security-agent-v23-planner", "planner-lease-token-v23-0002", "pid_7f000019-0000-4000-8000-000000000019", "pid_7f000020-0000-4000-8000-000000000020")
	if err != nil || dispatched.State != "running" || dispatched.EffectState != "pending" {
		t.Fatalf("dispatch=%#v err=%v", dispatched, err)
	}
	if reconciled, err := actionRepository.ReconcileConnectorRevocations(ctx, "security-agent-v23-action", 10); err != nil || reconciled != 0 {
		t.Fatalf("premature reconciliation=%d err=%v", reconciled, err)
	}
	var claimed json.RawMessage
	if err := connectorConnection.QueryRow(ctx, `SELECT zasp_connector_claim_reconciliation('connector-v23-worker',60,10)`).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	var connectorClaims struct {
		Items []struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
			ID             string `json:"id"`
			LeaseOwner     string `json:"lease_owner"`
			LeaseToken     string `json:"lease_token"`
			Operation      string `json:"operation"`
		} `json:"items"`
	}
	if err := json.Unmarshal(claimed, &connectorClaims); err != nil || len(connectorClaims.Items) != 1 || connectorClaims.Items[0].Operation != "revoke" {
		t.Fatalf("connector claims=%s decoded=%#v err=%v", claimed, connectorClaims, err)
	}
	connectorClaim := connectorClaims.Items[0]
	var connectorCompletion json.RawMessage
	if err := connectorConnection.QueryRow(ctx, `SELECT zasp_connector_complete_revocation($1,$2,$3,$4,$5,$6)`, connectorClaim.OrganizationID, connectorClaim.WorkspaceID, connectorClaim.EnvironmentID, connectorClaim.ID, connectorClaim.LeaseOwner, connectorClaim.LeaseToken).Scan(&connectorCompletion); err != nil || !strings.Contains(string(connectorCompletion), `"status": "reconciled"`) {
		t.Fatalf("connector completion=%s err=%v", connectorCompletion, err)
	}
	if reconciled, err := actionRepository.ReconcileConnectorRevocations(ctx, "security-agent-v23-action", 10); err != nil || reconciled != 1 {
		t.Fatalf("verified reconciliation=%d err=%v", reconciled, err)
	}
	var runState, effectState, linkState, connectionState, credentialState, integrationState, workflowStatus, workflowUpdatedAt string
	var integrationCredential *string
	if err := connection.QueryRow(ctx, `SELECT run.state,effect.state,link.state,connection.state,credential.status,integration.state,integration.credential_reference,workflow.body->>'status',workflow.body->>'updated_at' FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_connector_revocations link USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.id)=(link.organization_id,link.workspace_id,link.environment_id,link.connection_id) JOIN zasp_connector_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.id)=(link.organization_id,link.workspace_id,link.environment_id,link.credential_id) JOIN zasp_integrations integration ON (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(link.organization_id,link.workspace_id,link.environment_id,link.integration_id) JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.kind,workflow.id)=(link.organization_id,link.workspace_id,link.environment_id,'integration',link.integration_id) WHERE run.run_id=$1`, dispatched.RunID).Scan(&runState, &effectState, &linkState, &connectionState, &credentialState, &integrationState, &integrationCredential, &workflowStatus, &workflowUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if runState != "remediated" || effectState != "verified" || linkState != "verified" || connectionState != "revoked" || credentialState != "revoked" || integrationState != "pending" || integrationCredential != nil || workflowStatus != "pending_authorization" {
		t.Fatalf("final states run=%s effect=%s link=%s connection=%s credential=%s integration=%s reference=%v workflow=%s", runState, effectState, linkState, connectionState, credentialState, integrationState, integrationCredential, workflowStatus)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, workflowUpdatedAt); err != nil || !strings.HasSuffix(workflowUpdatedAt, "Z") || parsed.Location() != time.UTC {
		t.Fatalf("workflow updated_at=%q parsed=%v err=%v, want canonical UTC Z", workflowUpdatedAt, parsed, err)
	}
	assertConnectorRevocationSchedulerFairness(t, ctx, connection, planner, organizationID, workspaceID, environmentID, actorID, entityID)
	if err := runner.DownProductionSecurityAgentConnectorRevocation(ctx); err == nil {
		t.Fatal("v23 down accepted durable connector-revocation authority")
	}
}

func assertConnectorRevocationSchedulerFairness(t *testing.T, ctx context.Context, connection *pgx.Conn, planner *SecurityAgentWorkerRepository, organizationID, workspaceID, environmentID, actorID, entityID string) {
	t.Helper()
	integrationID := "pid_7f000030-0000-4000-8000-000000000030"
	connectionID := "pid_7f000031-0000-4000-8000-000000000031"
	credentialID := "pid_7f000032-0000-4000-8000-000000000032"
	syncID := "pid_7f000033-0000-4000-8000-000000000033"
	snapshotID := "pid_7f000034-0000-4000-8000-000000000034"
	evidenceID := "pid_7f000035-0000-4000-8000-000000000035"
	definitionA := "pid_7f000036-0000-4000-8000-000000000036"
	definitionB := "pid_7f000037-0000-4000-8000-000000000037"
	findingA1 := "pid_7f000038-0000-4000-8000-000000000038"
	findingA2 := "pid_7f000039-0000-4000-8000-000000000039"
	findingB := "pid_7f000040-0000-4000-8000-000000000040"
	connectionReference := "ref:github/installation/777777"
	workflow := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Fairness GitHub","configuration":{},"status":"active","updated_at":"2026-08-21T00:00:00Z"}`)
	definition := func(id, source string) json.RawMessage {
		return json.RawMessage(`{"id":"` + id + `","name":"Fair ` + source + `","trigger_kind":"finding","trigger_source":"` + source + `","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["revoke_integration_connection"],"verification_kind":"connection_state","definition_version":1,"enabled":true}`)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,credential_reference,state) VALUES($1,$2,$3,$4,'github','collector-v1','Fairness GitHub','{}',$5,'active')`, []any{organizationID, workspaceID, environmentID, integrationID, connectionReference}},
		{`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'integration',$4,1,$5)`, []any{organizationID, workspaceID, environmentID, integrationID, workflow}},
		{`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,$5,'github',$6,'verified',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, integrationID, connectionID, connectionReference}},
		{`INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES($1,$2,$3,$4,$5,'github','github_installation_reference',$6,1,'{"installation_id":"777777"}')`, []any{organizationID, workspaceID, environmentID, credentialID, integrationID, connectionReference}},
		{`INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'security-agent-v23-fairness-sync',decode(repeat('11',32),'hex'),'manual',$6,'queued','parser-v1','tool-v1')`, []any{organizationID, workspaceID, environmentID, syncID, integrationID, actorID}},
		{`INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'github','s3://zasp-evidence/v23/fairness-manifest.json',decode(repeat('12',32),'hex'),'complete',decode(repeat('13',32),'hex'),'{}',true,true,transaction_timestamp(),transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, snapshotID, integrationID, syncID}},
		{`INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,NULL,'s3://zasp-evidence/v23/fairness.json',decode(repeat('14',32),'hex'),'application/json','1','parser-v1',transaction_timestamp(),'github',1,'s3://zasp-evidence/v23/fairness.json','v23/fairness.json','version-v23-fairness',128,'tool-v1')`, []any{organizationID, workspaceID, environmentID, evidenceID, integrationID, snapshotID, entityID}},
		{`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,$5,'security-agent-actions-v1'),($1,$2,$3,$6,'supervised',1,1,$7,'security-agent-actions-v1')`, []any{organizationID, workspaceID, environmentID, definitionA, definition(definitionA, "starvation-a"), definitionB, definition(definitionB, "starvation-b")}},
		{`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','starvation-a','A1','high','open'),($1,$2,$3,$5,'posture','starvation-a','A2','high','open'),($1,$2,$3,$6,'posture','starvation-b','B','high','open')`, []any{organizationID, workspaceID, environmentID, findingA1, findingA2, findingB}},
		{`INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$7),($1,$2,$3,$5,1,$7),($1,$2,$3,$6,1,$7)`, []any{organizationID, workspaceID, environmentID, findingA1, findingA2, findingB, evidenceID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("fairness seed %s: %v", statement.sql, err)
		}
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v23-fairness", 6); err != nil || created != 2 {
		t.Fatalf("fair scheduler=%d err=%v", created, err)
	}
	var scheduledA, scheduledB int
	if err := connection.QueryRow(ctx, `SELECT count(*) FILTER(WHERE definition_id=$1),count(*) FILTER(WHERE definition_id=$2) FROM zasp_security_agent_trigger_receipts`, definitionA, definitionB).Scan(&scheduledA, &scheduledB); err != nil || scheduledA != 1 || scheduledB != 1 {
		t.Fatalf("fair definitions A=%d B=%d err=%v", scheduledA, scheduledB, err)
	}
}
