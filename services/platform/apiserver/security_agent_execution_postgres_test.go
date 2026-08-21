package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionSecurityAgentExecutionPostgresQuarantinesActivatesAndClaimsByExactTenant(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatal(err)
	}

	scope := fixtureRequestIdentity(t).Scope
	organizationID := scope.OrganizationID().String()
	workspaceID := scope.WorkspaceID().String()
	environmentID := scope.EnvironmentID().String()
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	legacyBody := json.RawMessage(`{"id":"pid_78000001-0000-4000-8000-000000000001","name":"Contain risky runtime","trigger_kind":"runtime_decision","trigger_source":"block","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":3,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["create_temporary_policy"],"verification_kind":"policy_state","definition_version":1,"enabled":true}`)
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'security_agent',$4,$5)`, organizationID, workspaceID, environmentID, definitionID, legacyBody); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionSecurityAgentExecution(ctx); err != nil {
		t.Fatalf("v18 up: %v", err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE security_agent_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE security_agent_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_api_login','security_agent_worker_login')`).Scan(&registered); err != nil || !registered {
		t.Fatalf("register security agent principals=%t err=%v", registered, err)
	}
	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		configuration, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		configuration.User = principal
		principalConnection, connectErr := pgx.ConnectConfig(ctx, configuration)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		return principalConnection
	}
	apiConnection := connectAs("security_agent_api_login")
	defer apiConnection.Close(context.Background())
	workerConnection := connectAs("security_agent_worker_login")
	defer workerConnection.Close(context.Background())
	var apiReady, workerReady, apiCanClaim bool
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_principal_ready('zasp_security_agent_api'),zasp_security_agent_principal_ready('zasp_security_agent_worker'),has_function_privilege(session_user,'zasp_security_agent_claim_runs(text,text,integer,integer)','EXECUTE')`).Scan(&apiReady, &workerReady, &apiCanClaim); err != nil || !apiReady || workerReady || apiCanClaim {
		t.Fatalf("api authority ready=%t worker=%t claim=%t err=%v", apiReady, workerReady, apiCanClaim, err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_principal_ready('zasp_security_agent_worker')`).Scan(&workerReady); err != nil || !workerReady {
		t.Fatalf("worker authority ready=%t err=%v", workerReady, err)
	}
	actorID := "pid_78000002-0000-4000-8000-000000000002"
	var detail json.RawMessage
	createdDefinitionID := "pid_78000012-0000-4000-8000-000000000012"
	createdBody := json.RawMessage(`{"id":"pid_78000012-0000-4000-8000-000000000012","name":"New discovery response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":3,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["create_temporary_policy"],"verification_kind":"policy_state","definition_version":1,"enabled":false}`)
	createdIntent := json.RawMessage(`{"scope":{"organization_id":"` + organizationID + `","workspace_id":"` + workspaceID + `","environment_id":"` + environmentID + `"},"resource_id":"","expected_version":0,"body":` + string(createdBody) + `}`)
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_mutate_definition('create',$1,$2,$3,$4,$5,'createSecurityAgent','security-agent-create-0001',0,$6,$7,'audit-created','corr-created','')`, createdDefinitionID, organizationID, workspaceID, environmentID, actorID, createdIntent, createdBody).Scan(&detail); err != nil {
		t.Fatalf("create generic security agent: %v", err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'security_agent','pid_78000013-0000-4000-8000-000000000013',$4)`, organizationID, workspaceID, environmentID, createdBody); err == nil {
		t.Fatal("legacy database authority bypassed v18 definition guard")
	}
	var mirroredActivation string
	var mirroredEnabled bool
	if err := connection.QueryRow(ctx, `SELECT activation,(body->>'enabled')::boolean FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, createdDefinitionID).Scan(&mirroredActivation, &mirroredEnabled); err != nil || mirroredActivation != "draft" || mirroredEnabled {
		t.Fatalf("mirrored definition activation=%q enabled=%t err=%v", mirroredActivation, mirroredEnabled, err)
	}
	metadata := migrations.ProductionSecurityAgentExecution()
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionSecurityAgentExecutionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("readiness=%t err=%v", ready, err)
	}

	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_definition_detail($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, definitionID).Scan(&detail); err != nil {
		t.Fatalf("definition detail: %v", err)
	}
	var decoded struct {
		Activation string          `json:"activation"`
		Version    int64           `json:"version"`
		Body       json.RawMessage `json:"body"`
	}
	if json.Unmarshal(detail, &decoded) != nil || decoded.Activation != "draft" || decoded.Version != 1 || string(decoded.Body) == "" {
		t.Fatalf("quarantined definition=%s", detail)
	}
	var quarantinedEnabled bool
	if err := connection.QueryRow(ctx, `SELECT (body->>'enabled')::boolean FROM zasp_security_agent_definitions WHERE organization_id=$1 AND definition_id=$2`, organizationID, definitionID).Scan(&quarantinedEnabled); err != nil || quarantinedEnabled {
		t.Fatalf("legacy enabled=%t err=%v", quarantinedEnabled, err)
	}

	var activated json.RawMessage
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,1,'validated',$5,transaction_timestamp(),'audit-validated','corr-validated')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&activated); err != nil {
		t.Fatalf("validate definition: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,2,'supervised',$5,transaction_timestamp(),'audit-supervised-blocked','corr-supervised-blocked')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&activated); err == nil {
		t.Fatal("supervised activation passed with global execution disabled")
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_set_kill_switch('*','*','*','*',true,1,$1,'audit-global','corr-global')`, actorID).Scan(&activated); err != nil {
		t.Fatalf("enable global execution: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_set_kill_switch($1,$2,$3,'*',true,0,$4,'audit-tenant','corr-tenant')`, organizationID, workspaceID, environmentID, actorID).Scan(&activated); err != nil {
		t.Fatalf("enable tenant execution: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_set_kill_switch($1,$2,$3,'create_temporary_policy',true,0,$4,'audit-action','corr-action')`, organizationID, workspaceID, environmentID, actorID).Scan(&activated); err != nil {
		t.Fatalf("enable action execution: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,2,'supervised',$5,transaction_timestamp(),'audit-supervised','corr-supervised')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&activated); err != nil {
		t.Fatalf("supervised activation: %v", err)
	}

	foreignOrganization := "pid_78000011-0000-4000-8000-000000000011"
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_definition_detail($1,$2,$3,$4)`, foreignOrganization, workspaceID, environmentID, definitionID).Scan(&detail); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign detail error=%v body=%s", err, detail)
	}

	triggerDigest := sha256.Sum256([]byte("runtime-decision-v1"))
	runID := "pid_78000003-0000-4000-8000-000000000003"
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_create_run($1,$2,$3,$4,3,$5,'runtime_decision',1,$6,$7,$8,$9)`, organizationID, workspaceID, environmentID, definitionID, runID, triggerDigest[:], actorID, "audit-run", "corr-run").Scan(&detail); err != nil {
		t.Fatalf("create run: %v", err)
	}
	var claimed json.RawMessage
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_claim_runs('worker-a','lease-token-000000000001',60,10)`).Scan(&claimed); err != nil {
		t.Fatalf("claim run: %v", err)
	}
	var claimItems struct {
		Items []struct {
			RunID          string `json:"run_id"`
			OrganizationID string `json:"organization_id"`
		} `json:"items"`
	}
	if json.Unmarshal(claimed, &claimItems) != nil || len(claimItems.Items) != 1 || claimItems.Items[0].RunID != runID || claimItems.Items[0].OrganizationID != organizationID {
		t.Fatalf("claim=%s", claimed)
	}

	var postgresError *pgconn.PgError
	err = apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_create_run($1,$2,$3,$4,3,'pid_78000004-0000-4000-8000-000000000004','runtime_decision',1,$5,$6,'audit-run-foreign','corr-run-foreign')`, foreignOrganization, workspaceID, environmentID, definitionID, triggerDigest[:], actorID).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "22023" {
		t.Fatalf("foreign create error=%v", err)
	}
}
