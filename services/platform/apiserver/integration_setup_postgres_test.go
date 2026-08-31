package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionIntegrationSetupPostgresReturnsOnlyExactTenantScopeAndFailsClosedOnAuthorityDrift(t *testing.T) {
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
		runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification,
		runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `
CREATE ROLE integration_setup_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE integration_setup_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE integration_setup_ingest_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE integration_setup_runtime_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE integration_setup_outbox_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE integration_setup_gateway_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals(session_user,'integration_setup_api_login','integration_setup_worker_login','integration_setup_ingest_login','integration_setup_runtime_login','integration_setup_outbox_login','integration_setup_gateway_login')`).Scan(&registered); err != nil || !registered {
		t.Fatalf("principal registration ready=%t err=%v", registered, err)
	}
	organizationA := "pid_8c000001-0000-4000-8000-000000000001"
	workspaceA := "pid_8c000002-0000-4000-8000-000000000002"
	environmentA := "pid_8c000003-0000-4000-8000-000000000003"
	organizationB := "pid_8d000001-0000-4000-8000-000000000001"
	workspaceB := "pid_8d000002-0000-4000-8000-000000000002"
	environmentB := "pid_8d000003-0000-4000-8000-000000000003"
	integrationID := "pid_8c000004-0000-4000-8000-000000000004"
	connectionID := "pid_8c000005-0000-4000-8000-000000000005"
	credentialID := "pid_8c000006-0000-4000-8000-000000000006"
	for _, seed := range []struct{ organization, workspace, environment, installation, login string }{
		{organizationA, workspaceA, environmentA, "123456", "acme-a"},
		{organizationB, workspaceB, environmentB, "654321", "acme-b"},
	} {
		allArgs := []any{seed.organization, seed.workspace, seed.environment, integrationID, connectionID, seed.installation, credentialID, seed.login}
		for _, query := range []struct {
			statement string
			args      []any
		}{
			{`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES($1,$2,$3,$4,'github','collector-v1','GitHub','{"authorization_mode":"github_app"}'::jsonb,'active')`, allArgs[:4]},
			{`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,$5,'github','ref:github/installation/'||$6,'verified',transaction_timestamp())`, allArgs[:6]},
			{`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT $1,$2,$3,$4,$5,'github','github_installation',$6,connection.version,digest(convert_to(integration.configuration::text,'UTF8'),'sha256'),'oauth' FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,$5) WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=($1,$2,$3,$4)`, allArgs[:6]},
			{`INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES($1,$2,$3,$4,$5,'github','github_installation_reference','ref:github/installation/'||$6::text,1,jsonb_build_object('installation_id',$6::text,'account_type','Organization','account_login',$7::text,'repository_selection','selected','permissions',jsonb_build_object('actions','read','contents','read','metadata','read')))`, []any{seed.organization, seed.workspace, seed.environment, credentialID, integrationID, seed.installation, seed.login}},
		} {
			if _, err := connection.Exec(ctx, query.statement, query.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	kubernetesID := "pid_8c000007-0000-4000-8000-000000000007"
	kubernetesConnection := "pid_8c000008-0000-4000-8000-000000000008"
	sensorID := "pid_8c000009-0000-4000-8000-000000000009"
	kubernetesArgs := []any{organizationA, workspaceA, environmentA, kubernetesID, kubernetesConnection, sensorID}
	for _, query := range []struct {
		statement string
		args      []any
	}{
		{`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES($1,$2,$3,$4,'kubernetes','collector-v1','Production cluster','{"connection_reference":"ref:kubernetes/connection/production-0001"}'::jsonb,'active')`, kubernetesArgs[:4]},
		{`INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES($1,$2,$3,$4,$5,'kubernetes','ref:kubernetes/connection/production-0001','verified',transaction_timestamp())`, kubernetesArgs[:5]},
		{`INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source) SELECT $1,$2,$3,$4,$5,'kubernetes','kubernetes_cluster','production-us-west',connection.version,digest(convert_to(integration.configuration::text,'UTF8'),'sha256'),'reference' FROM zasp_integrations integration JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.id)=(integration.organization_id,integration.workspace_id,integration.environment_id,integration.id,$5) WHERE (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=($1,$2,$3,$4)`, kubernetesArgs[:5]},
		{`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Runtime sensor','tetragon','active')`, []any{organizationA, workspaceA, environmentA, sensorID}},
		{`INSERT INTO zasp_sensor_heartbeats(organization_id,workspace_id,environment_id,sensor_id,sequence,request_digest,status,metadata) VALUES($1,$2,$3,$4,1,digest('heartbeat','sha256'),'healthy','{"btf":true}'::jsonb)`, []any{organizationA, workspaceA, environmentA, sensorID}},
	} {
		if _, err := connection.Exec(ctx, query.statement, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "integration_setup_api_login"
	apiConnection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer apiConnection.Close(context.Background())
	read := func(organization, workspace, environment, id string) IntegrationSetupStatus {
		t.Helper()
		var payload json.RawMessage
		if err := apiConnection.QueryRow(ctx, postgresExecutionPublicIntegrationSetupStatusSQL, organization, workspace, environment, id, migrations.ProductionIntegrationSetup().Checksum(), migrations.ProductionIntegrationSetupSemanticFingerprint()).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var status IntegrationSetupStatus
		if err := decodeStrictDiscovery(payload, &status); err != nil || !exactJSONFields(payload, "authorization", "connector_key", "integration_id", "runtime_coverage", "updated_at") || !validPublicIntegrationSetupStatus(status, id) {
			t.Fatalf("status=%s err=%v", payload, err)
		}
		return status
	}
	statusA := read(organizationA, workspaceA, environmentA, integrationID)
	statusB := read(organizationB, workspaceB, environmentB, integrationID)
	if statusA.Authorization.ScopeLabel == nil || *statusA.Authorization.ScopeLabel != "acme-a" || statusB.Authorization.ScopeLabel == nil || *statusB.Authorization.ScopeLabel != "acme-b" {
		t.Fatalf("tenant status A=%#v B=%#v", statusA, statusB)
	}
	kubernetes := read(organizationA, workspaceA, environmentA, kubernetesID)
	if kubernetes.RuntimeCoverage.State != "healthy" || kubernetes.RuntimeCoverage.SensorCount != 1 || kubernetes.RuntimeCoverage.HealthySensorCount != 1 {
		t.Fatalf("Kubernetes coverage=%#v", kubernetes)
	}
	if _, err := apiConnection.Exec(ctx, `SELECT credential_reference FROM zasp_connector_credentials LIMIT 1`); err == nil {
		t.Fatal("API login read connector credentials directly")
	}
	if _, err := connection.Exec(ctx, `GRANT SELECT ON zasp_connector_credentials TO zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_production_integration_setup_readiness($1,$2)`, migrations.ProductionIntegrationSetup().Checksum(), migrations.ProductionIntegrationSetupSemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("ACL drift readiness=%t err=%v", ready, err)
	}
	var rejected json.RawMessage
	if err := apiConnection.QueryRow(ctx, postgresExecutionPublicIntegrationSetupStatusSQL, organizationA, workspaceA, environmentA, integrationID, migrations.ProductionIntegrationSetup().Checksum(), migrations.ProductionIntegrationSetupSemanticFingerprint()).Scan(&rejected); err == nil {
		t.Fatal("setup status accepted drifted v34 authority")
	}
}
