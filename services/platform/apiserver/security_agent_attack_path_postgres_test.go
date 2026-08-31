package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionSecurityAgentAttackPathPostgresSchedulesOnceAndBindsPlannerToVerifiedPath(t *testing.T) {
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
		runner.UpProductionRuntimeDataPlane,
		runner.UpProductionRuntimeGatewayReconciliation,
		runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution,
		runner.UpProductionIdentityAdministration,
		runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse,
		runner.UpProductionSecurityAgentTemporaryPolicy,
		runner.UpProductionSecurityAgentConnectorRevocation,
		runner.UpProductionSecurityAgentSessionIsolation,
		runner.UpProductionRedTeamExecution,
		runner.UpProductionAttackLabExecution,
		runner.UpProductionRecovery,
		runner.UpProductionPolicyDeployment,
		runner.UpProductionHomeAttention,
		runner.UpProductionApprovalNotification,
		runner.UpProductionWorkflowCompatibility,
		runner.UpProductionSecurityAgentPlanner,
		runner.UpProductionSecurityAgentAttackPath,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if version, err := runner.Version(ctx); err != nil || version != 33 {
		t.Fatalf("v33 migration state version=%d err=%v", version, err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE security_agent_v33_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_discovery_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_discovery_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_ingest_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_runtime_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_outbox_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v33_gateway_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals(session_user,'security_agent_v33_discovery_api_login','security_agent_v33_discovery_worker_login','security_agent_v33_ingest_login','security_agent_v33_runtime_login','security_agent_v33_outbox_login','security_agent_v33_gateway_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("discovery principal registration ready=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_v33_api_login','security_agent_v33_worker_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("principal registration ready=%t err=%v", ready, err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "security_agent_v33_worker_login"
	workerConnection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer workerConnection.Close(context.Background())
	var releaseReady, principalReady bool
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_readiness($1,$2),zasp_security_agent_principal_ready('zasp_security_agent_worker')`, migrations.ProductionSecurityAgentAttackPath().Checksum(), migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&releaseReady, &principalReady); err != nil || !releaseReady || !principalReady {
		t.Fatalf("v33 worker readiness release=%t principal=%t err=%v", releaseReady, principalReady, err)
	}
	if _, err := connection.Exec(ctx, `ALTER FUNCTION zasp_security_agent_planner_context(text,text,text,text,text,text) SET search_path TO public`); err != nil {
		t.Fatal(err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_readiness($1,$2)`, migrations.ProductionSecurityAgentAttackPath().Checksum(), migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&releaseReady); err != nil || releaseReady {
		t.Fatalf("v33 inherited planner drift readiness=%t err=%v", releaseReady, err)
	}
	if _, err := connection.Exec(ctx, `ALTER FUNCTION zasp_security_agent_planner_context(text,text,text,text,text,text) SET search_path TO pg_catalog, public`); err != nil {
		t.Fatal(err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_readiness($1,$2)`, migrations.ProductionSecurityAgentAttackPath().Checksum(), migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&releaseReady); err != nil || !releaseReady {
		t.Fatalf("v33 restored inherited planner readiness=%t err=%v", releaseReady, err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: workerConnection})
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewSecurityAgentWorkerRepository(database)
	if err != nil {
		t.Fatal(err)
	}

	organizationID := "pid_6a000001-0000-4000-8000-000000000001"
	workspaceID := "pid_6a000002-0000-4000-8000-000000000002"
	environmentID := "pid_6a000003-0000-4000-8000-000000000003"
	definitionID := "pid_6a000004-0000-4000-8000-000000000004"
	pathID := "pid_6a000005-0000-4000-8000-000000000005"
	entryID := "pid_6a000006-0000-4000-8000-000000000006"
	sinkID := "pid_6a000007-0000-4000-8000-000000000007"
	evidenceID := "pid_6a000008-0000-4000-8000-000000000008"
	actorID := "pid_6a000009-0000-4000-8000-000000000009"
	foreignOrganizationID := "pid_9a000001-0000-4000-8000-000000000001"
	foreignWorkspaceID := "pid_9a000002-0000-4000-8000-000000000002"
	foreignEnvironmentID := "pid_9a000003-0000-4000-8000-000000000003"
	body := json.RawMessage(`{"id":"` + definitionID + `","name":"Contain verified attack path","trigger_kind":"attack_path","trigger_source":"verified","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["create_temporary_policy"],"verification_kind":"policy_state","definition_version":1,"enabled":true}`)
	foreignBody := json.RawMessage(`{"id":"` + definitionID + `","name":"Contain foreign verified attack path","trigger_kind":"attack_path","trigger_source":"verified","environment_ids":["` + foreignEnvironmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["create_temporary_policy"],"verification_kind":"policy_state","definition_version":1,"enabled":true}`)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Attack path tenant','attack-path.invalid')`, []any{organizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production')`, []any{workspaceID, organizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, []any{environmentID, organizationID, workspaceID}},
		{`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,$5,'security-agent-actions-v1')`, []any{organizationID, workspaceID, environmentID, definitionID, body}},
		{`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,$4),($1,$2,$3,'create_temporary_policy',true,$4)`, []any{organizationID, workspaceID, environmentID, actorID}},
		{`INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES($1,$2,$3,$4,$5,$6,'potential')`, []any{organizationID, workspaceID, environmentID, pathID, entryID, sinkID}},
		{`INSERT INTO zasp_risk_attack_path_nodes(organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES($1,$2,$3,$4,1,$5),($1,$2,$3,$4,2,$6)`, []any{organizationID, workspaceID, environmentID, pathID, entryID, sinkID}},
		{`INSERT INTO zasp_risk_attack_path_evidence(organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, []any{organizationID, workspaceID, environmentID, pathID, evidenceID}},
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Foreign attack path tenant','foreign-attack-path.invalid')`, []any{foreignOrganizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Foreign production')`, []any{foreignWorkspaceID, foreignOrganizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Foreign production','production')`, []any{foreignEnvironmentID, foreignOrganizationID, foreignWorkspaceID}},
		{`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,$5,'security-agent-actions-v1')`, []any{foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, definitionID, foreignBody}},
		{`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,$4),($1,$2,$3,'create_temporary_policy',true,$4)`, []any{foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, actorID}},
		{`INSERT INTO zasp_risk_attack_paths(organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES($1,$2,$3,$4,$5,$6,'potential')`, []any{foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, pathID, entryID, sinkID}},
		{`INSERT INTO zasp_risk_attack_path_nodes(organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES($1,$2,$3,$4,1,$5),($1,$2,$3,$4,2,$6)`, []any{foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, pathID, entryID, sinkID}},
		{`INSERT INTO zasp_risk_attack_path_evidence(organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, []any{foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, pathID, evidenceID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", statement.sql, err)
		}
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v33-worker", 10); err != nil || created != 0 {
		t.Fatalf("potential path scheduled=%d err=%v", created, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, pathID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v33-worker", 10); err != nil || created != 1 {
		t.Fatalf("verified path scheduled=%d err=%v", created, err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v33-worker", 10); err != nil || created != 0 {
		t.Fatalf("duplicate path scheduled=%d err=%v", created, err)
	}
	claims, err := planner.ClaimSecurityAgentRuns(ctx, "security-agent-v33-worker", "attack-path-lease-token-0001", 60, 10)
	if err != nil || len(claims) != 1 || claims[0].OrganizationID != organizationID || claims[0].TriggerID != pathID || claims[0].DefinitionID != definitionID {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	contextValue, err := planner.LoadSecurityAgentPlannerContext(ctx, claims[0], "security-agent-v33-worker", "attack-path-lease-token-0001")
	if err != nil || len(contextValue.Evidence) != 1 || contextValue.Evidence[0].Kind != "attack_path" || contextValue.Evidence[0].ID != pathID || contextValue.Evidence[0].Version != 2 || len(contextValue.AllowedActions) != 1 || contextValue.AllowedActions[0] != "create_temporary_policy" || len(contextValue.AllowedTargets) != 1 || contextValue.AllowedTargets[0] != environmentID {
		var raw json.RawMessage
		directErr := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_planner_context_v33($1,$2,$3,$4,$5,$6)`, organizationID, workspaceID, environmentID, claims[0].RunID, "security-agent-v33-worker", "attack-path-lease-token-0001").Scan(&raw)
		t.Fatalf("context=%#v err=%v direct=%s directErr=%v", contextValue, err, raw, directErr)
	}
	prepared, err := planner.AcceptSecurityAgentPlannerCandidate(ctx, claims[0], "security-agent-v33-worker", "attack-path-lease-token-0001", SecurityAgentPlannerSubmission{
		InputDigest: contextValue.InputDigest, OutputDigest: "sha256:" + strings.Repeat("b", 64), Model: "openai/gpt-5-mini", PolicyVersion: "security-agent-planner-v1", Summary: "Contain only the verified path scope", Action: "create_temporary_policy", TargetID: environmentID,
	}, "pid_6a000010-0000-4000-8000-000000000010", time.Now().UTC().Add(15*time.Minute).Truncate(time.Microsecond), "pid_6a000011-0000-4000-8000-000000000011", "pid_6a000012-0000-4000-8000-000000000012")
	if err != nil || prepared.State != "waiting_approval" || prepared.RunID != claims[0].RunID {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, pathID); err != nil {
		t.Fatal(err)
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v33-worker", 10); err != nil || created != 1 {
		t.Fatalf("foreign verified path scheduled=%d err=%v", created, err)
	}
	var receipts, runs, approvals int
	var foreignReceipts, foreignRuns int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE organization_id=$1 AND trigger_kind='attack_path' AND trigger_id=$2 AND trigger_version=2),(SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$1 AND trigger_id=$2),(SELECT count(*) FROM zasp_security_agent_approvals WHERE organization_id=$1 AND run_id=$3),(SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE organization_id=$4 AND trigger_kind='attack_path' AND trigger_id=$2 AND trigger_version=2),(SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$4 AND trigger_id=$2)`, organizationID, pathID, claims[0].RunID, foreignOrganizationID).Scan(&receipts, &runs, &approvals, &foreignReceipts, &foreignRuns); err != nil || receipts != 1 || runs != 1 || approvals != 1 || foreignReceipts != 1 || foreignRuns != 1 {
		t.Fatalf("receipts=%d runs=%d approvals=%d foreign_receipts=%d foreign_runs=%d err=%v", receipts, runs, approvals, foreignReceipts, foreignRuns, err)
	}
}
