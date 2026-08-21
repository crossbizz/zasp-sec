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
	legacyBody := json.RawMessage(`{"id":"pid_78000001-0000-4000-8000-000000000001","name":"Review exposed credential","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["update_finding_response"],"verification_kind":"finding_state","definition_version":1,"enabled":true}`)
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
	var apiReady, workerReady, apiCanClaim, apiCanLegacyCreate, apiCanRun bool
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_principal_ready('zasp_security_agent_api'),zasp_security_agent_principal_ready('zasp_security_agent_worker'),has_function_privilege(session_user,'zasp_security_agent_claim_runs(text,text,integer,integer)','EXECUTE'),has_function_privilege(session_user,'zasp_security_agent_create_run(text,text,text,text,bigint,text,text,bigint,bytea,text,text,text)','EXECUTE'),has_function_privilege(session_user,'zasp_security_agent_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text)','EXECUTE')`).Scan(&apiReady, &workerReady, &apiCanClaim, &apiCanLegacyCreate, &apiCanRun); err != nil || !apiReady || workerReady || apiCanClaim || apiCanLegacyCreate || !apiCanRun {
		t.Fatalf("api authority ready=%t worker=%t claim=%t legacy_create=%t run=%t err=%v", apiReady, workerReady, apiCanClaim, apiCanLegacyCreate, apiCanRun, err)
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
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,'activate-validated-0001',1,'validated',transaction_timestamp()+interval '4 minutes','audit-validated','corr-validated','receipt-validated')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&activated); err != nil {
		t.Fatalf("validate definition: %v", err)
	}
	evidenceID := "pid_78000020-0000-4000-8000-000000000020"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','exposed_credential','Exposed credential','high','open')`, organizationID, workspaceID, environmentID, evidenceID); err != nil {
		t.Fatalf("seed simulation evidence: %v", err)
	}
	simulationRunID := "pid_78000021-0000-4000-8000-000000000021"
	simulationAuditID := "pid_78000022-0000-4000-8000-000000000022"
	simulationCorrelationID := "pid_78000023-0000-4000-8000-000000000023"
	simulationReceiptID := "pid_78000024-0000-4000-8000-000000000024"
	simulationExpiresAt := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond)
	var simulation json.RawMessage
	var replayed json.RawMessage
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_simulate($1,$2,$3,$4,$5,'simulate-agent-idem-0001',2,$6,'Review exposed credential',jsonb_build_array($7::text),$8,$9,$10,$11)`, organizationID, workspaceID, environmentID, definitionID, actorID, simulationRunID, evidenceID, simulationExpiresAt, simulationAuditID, simulationCorrelationID, simulationReceiptID).Scan(&simulation); err != nil {
		t.Fatalf("simulate definition: %v", err)
	}
	var simulated struct {
		RunID       string `json:"run_id"`
		PlanHash    string `json:"plan_hash"`
		SideEffects int    `json:"side_effects"`
		Replayed    bool   `json:"replayed"`
	}
	if json.Unmarshal(simulation, &simulated) != nil || simulated.RunID != simulationRunID || !strings.HasPrefix(simulated.PlanHash, "sha256:") || len(simulated.PlanHash) != 71 || simulated.SideEffects != 0 || simulated.Replayed {
		t.Fatalf("simulation=%s", simulation)
	}
	var simulationState string
	var planMatches bool
	var effectCount int
	if err := connection.QueryRow(ctx, `SELECT run.state,run.plan_hash=plan.plan_hash,(SELECT count(*) FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=($1,$2,$3,$4)) FROM zasp_security_agent_runs run JOIN zasp_security_agent_plans plan USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, simulationRunID).Scan(&simulationState, &planMatches, &effectCount); err != nil || simulationState != "simulated" || !planMatches || effectCount != 0 {
		t.Fatalf("simulation state=%q plan=%t effects=%d err=%v", simulationState, planMatches, effectCount, err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_simulate($1,$2,$3,$4,$5,'simulate-agent-idem-0001',2,'pid_78000025-0000-4000-8000-000000000025','Review exposed credential',jsonb_build_array($6::text),$7,'pid_78000026-0000-4000-8000-000000000026','pid_78000027-0000-4000-8000-000000000027','pid_78000028-0000-4000-8000-000000000028')`, organizationID, workspaceID, environmentID, definitionID, actorID, evidenceID, simulationExpiresAt).Scan(&replayed); err != nil || !strings.Contains(string(replayed), `"replayed": true`) || !strings.Contains(string(replayed), `"run_id": "`+simulationRunID+`"`) {
		t.Fatalf("simulation replay=%s err=%v", replayed, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_findings SET status='resolved',updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, evidenceID); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_simulate($1,$2,$3,$4,$5,'simulate-agent-idem-0001',2,$6,'Review exposed credential',jsonb_build_array($7::text),$8,$9,$10,$11)`, organizationID, workspaceID, environmentID, definitionID, actorID, simulationRunID, evidenceID, simulationExpiresAt, simulationAuditID, simulationCorrelationID, simulationReceiptID).Scan(&detail); err == nil {
		t.Fatal("simulation replay ignored evidence authorization loss")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_findings SET status='open',updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, evidenceID); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_simulate($1,$2,$3,$4,$5,'simulate-agent-idem-0002',2,'pid_78000029-0000-4000-8000-000000000029','Review unknown evidence',jsonb_build_array('pid_78000030-0000-4000-8000-000000000030'::text),$6,'pid_78000031-0000-4000-8000-000000000031','pid_78000032-0000-4000-8000-000000000032','pid_78000033-0000-4000-8000-000000000033')`, organizationID, workspaceID, environmentID, definitionID, actorID, simulationExpiresAt).Scan(&detail); err == nil {
		t.Fatal("simulation accepted unauthorized evidence")
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,'activate-supervised-0001',2,'supervised',transaction_timestamp()+interval '4 minutes','audit-supervised-blocked','corr-supervised-blocked','receipt-supervised-blocked')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&activated); err == nil {
		t.Fatal("supervised activation passed with global execution disabled")
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_set_kill_switch('*','*','*','*',true,1,$1,'audit-global','corr-global')`, actorID).Scan(&activated); err != nil {
		t.Fatalf("enable global execution: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_set_kill_switch($1,$2,$3,'*',true,0,$4,'audit-tenant','corr-tenant')`, organizationID, workspaceID, environmentID, actorID).Scan(&activated); err != nil {
		t.Fatalf("enable tenant execution: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_set_kill_switch($1,$2,$3,'update_finding_response',true,0,$4,'audit-action','corr-action')`, organizationID, workspaceID, environmentID, actorID).Scan(&activated); err != nil {
		t.Fatalf("enable action execution: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,'activate-supervised-0001',2,'supervised',transaction_timestamp()+interval '4 minutes','audit-supervised','corr-supervised','receipt-supervised')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&activated); err != nil {
		t.Fatalf("supervised activation: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,'activate-supervised-0001',2,'supervised',transaction_timestamp()+interval '4 minutes','new-audit-must-not-win','new-correlation-must-not-win','new-receipt-must-not-win')`, organizationID, workspaceID, environmentID, definitionID, actorID).Scan(&replayed); err != nil || !strings.Contains(string(replayed), `"replayed": true`) || !strings.Contains(string(replayed), `"receipt_id": "receipt-supervised"`) {
		t.Fatalf("activation replay=%s err=%v", replayed, err)
	}

	foreignOrganization := "pid_78000011-0000-4000-8000-000000000011"
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_definition_detail($1,$2,$3,$4)`, foreignOrganization, workspaceID, environmentID, definitionID).Scan(&detail); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign detail error=%v body=%s", err, detail)
	}

	runID := "pid_78000003-0000-4000-8000-000000000003"
	runAuditID := "pid_78000036-0000-4000-8000-000000000036"
	runCorrelationID := "pid_78000037-0000-4000-8000-000000000037"
	runReceiptID := "pid_78000038-0000-4000-8000-000000000038"
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_run($1,$2,$3,$4,$5,'security-agent-run-idem-0001',3,$6,'finding',$7,$8,$9,$10)`, organizationID, workspaceID, environmentID, definitionID, actorID, runID, evidenceID, runAuditID, runCorrelationID, runReceiptID).Scan(&detail); err != nil {
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
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_heartbeat_run($1,$2,$3,$4,'worker-a','lease-token-000000000001',60)`, organizationID, workspaceID, environmentID, runID).Scan(&detail); err != nil {
		t.Fatalf("heartbeat run: %v", err)
	}
	approvalID := "pid_78000034-0000-4000-8000-000000000034"
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_prepare_run($1,$2,$3,$4,'worker-a','lease-token-000000000001',$5,transaction_timestamp()+interval '15 minutes','pid_78000039-0000-4000-8000-000000000039','pid_78000040-0000-4000-8000-000000000040')`, organizationID, workspaceID, environmentID, runID, approvalID).Scan(&detail); err != nil || !strings.Contains(string(detail), `"state": "waiting_approval"`) {
		t.Fatalf("prepare run=%s err=%v", detail, err)
	}
	var effectCountBeforeApproval int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&effectCountBeforeApproval); err != nil || effectCountBeforeApproval != 0 {
		t.Fatalf("effects before approval=%d err=%v", effectCountBeforeApproval, err)
	}
	var postgresError *pgconn.PgError
	err = apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval($1,$2,$3,$4,$5,'security-agent-self-approve-0001',1,'approved',transaction_timestamp(),'pid_78000046-0000-4000-8000-000000000046','pid_78000047-0000-4000-8000-000000000047','pid_78000048-0000-4000-8000-000000000048')`, organizationID, workspaceID, environmentID, approvalID, actorID).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "40001" {
		t.Fatalf("self approval error=%v", err)
	}
	approverID := "pid_78000035-0000-4000-8000-000000000035"
	postgresError = nil
	err = apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval($1,$2,$3,$4,$5,'security-agent-stale-auth-0001',1,'approved',transaction_timestamp()-interval '6 minutes','pid_78000049-0000-4000-8000-000000000049','pid_78000050-0000-4000-8000-000000000050','pid_78000051-0000-4000-8000-000000000051')`, organizationID, workspaceID, environmentID, approvalID, approverID).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "22023" {
		t.Fatalf("stale authentication error=%v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval($1,$2,$3,$4,$5,'security-agent-approve-idem-0001',1,'approved',transaction_timestamp(),'pid_78000041-0000-4000-8000-000000000041','pid_78000042-0000-4000-8000-000000000042','pid_78000043-0000-4000-8000-000000000043')`, organizationID, workspaceID, environmentID, approvalID, approverID).Scan(&detail); err != nil || !strings.Contains(string(detail), `"state": "approved"`) {
		t.Fatalf("approve run=%s err=%v", detail, err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_claim_runs('worker-b','lease-token-000000000002',60,10)`).Scan(&claimed); err != nil || !strings.Contains(string(claimed), `"run_id": "`+runID+`"`) {
		t.Fatalf("reclaim approved run=%s err=%v", claimed, err)
	}
	postgresError = nil
	err = workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_execute_run($1,$2,$3,$4,'worker-a','lease-token-000000000001','pid_78000052-0000-4000-8000-000000000052','pid_78000053-0000-4000-8000-000000000053')`, organizationID, workspaceID, environmentID, runID).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "40001" {
		t.Fatalf("stale worker execution error=%v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, runID).Scan(&effectCountBeforeApproval); err != nil || effectCountBeforeApproval != 0 {
		t.Fatalf("effects after stale worker=%d err=%v", effectCountBeforeApproval, err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_execute_run($1,$2,$3,$4,'worker-b','lease-token-000000000002','pid_78000044-0000-4000-8000-000000000044','pid_78000045-0000-4000-8000-000000000045')`, organizationID, workspaceID, environmentID, runID).Scan(&detail); err != nil || !strings.Contains(string(detail), `"state": "remediated"`) {
		t.Fatalf("execute run=%s err=%v", detail, err)
	}
	var findingStatus, effectState, runState string
	var findingVersion int64
	if err := connection.QueryRow(ctx, `SELECT finding.status,finding.version,effect.state,run.state FROM zasp_risk_findings finding JOIN zasp_security_agent_runs run ON (run.organization_id,run.workspace_id,run.environment_id,run.trigger_id)=(finding.organization_id,finding.workspace_id,finding.environment_id,finding.id) JOIN zasp_security_agent_effects effect ON (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id) WHERE run.run_id=$1`, runID).Scan(&findingStatus, &findingVersion, &effectState, &runState); err != nil || findingStatus != "under_review" || findingVersion != 2 || effectState != "verified" || runState != "remediated" {
		t.Fatalf("finding=%s v%d effect=%s run=%s err=%v", findingStatus, findingVersion, effectState, runState, err)
	}

	changedEvidenceID := "pid_78000054-0000-4000-8000-000000000054"
	changedRunID := "pid_78000055-0000-4000-8000-000000000055"
	changedApprovalID := "pid_78000056-0000-4000-8000-000000000056"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','exposed_credential','Rotating credential','high','open')`, organizationID, workspaceID, environmentID, changedEvidenceID); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_run($1,$2,$3,$4,$5,'security-agent-run-idem-0002',3,$6,'finding',$7,'pid_78000057-0000-4000-8000-000000000057','pid_78000058-0000-4000-8000-000000000058','pid_78000059-0000-4000-8000-000000000059')`, organizationID, workspaceID, environmentID, definitionID, actorID, changedRunID, changedEvidenceID).Scan(&detail); err != nil {
		t.Fatalf("create changed-evidence run: %v", err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_claim_runs('worker-c','lease-token-000000000003',60,10)`).Scan(&claimed); err != nil || !strings.Contains(string(claimed), `"run_id": "`+changedRunID+`"`) {
		t.Fatalf("claim changed-evidence run=%s err=%v", claimed, err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_prepare_run($1,$2,$3,$4,'worker-c','lease-token-000000000003',$5,transaction_timestamp()+interval '15 minutes','pid_78000060-0000-4000-8000-000000000060','pid_78000061-0000-4000-8000-000000000061')`, organizationID, workspaceID, environmentID, changedRunID, changedApprovalID).Scan(&detail); err != nil {
		t.Fatalf("prepare changed-evidence run: %v", err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval($1,$2,$3,$4,$5,'security-agent-approve-idem-0002',1,'approved',transaction_timestamp(),'pid_78000062-0000-4000-8000-000000000062','pid_78000063-0000-4000-8000-000000000063','pid_78000064-0000-4000-8000-000000000064')`, organizationID, workspaceID, environmentID, changedApprovalID, approverID).Scan(&detail); err != nil {
		t.Fatalf("approve changed-evidence run: %v", err)
	}
	if err := workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_claim_runs('worker-d','lease-token-000000000004',60,10)`).Scan(&claimed); err != nil || !strings.Contains(string(claimed), `"run_id": "`+changedRunID+`"`) {
		t.Fatalf("reclaim changed-evidence run=%s err=%v", claimed, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_risk_findings SET title='Credential rotated concurrently',version=version+1,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, changedEvidenceID); err != nil {
		t.Fatal(err)
	}
	postgresError = nil
	err = workerConnection.QueryRow(ctx, `SELECT zasp_security_agent_execute_run($1,$2,$3,$4,'worker-d','lease-token-000000000004','pid_78000065-0000-4000-8000-000000000065','pid_78000066-0000-4000-8000-000000000066')`, organizationID, workspaceID, environmentID, changedRunID).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "40001" {
		t.Fatalf("changed evidence execution error=%v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT finding.status,finding.version,run.state,(SELECT count(*) FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)) FROM zasp_risk_findings finding JOIN zasp_security_agent_runs run ON (run.organization_id,run.workspace_id,run.environment_id,run.trigger_id)=(finding.organization_id,finding.workspace_id,finding.environment_id,finding.id) WHERE run.run_id=$1`, changedRunID).Scan(&findingStatus, &findingVersion, &runState, &effectCountBeforeApproval); err != nil || findingStatus != "open" || findingVersion != 2 || runState != "planning" || effectCountBeforeApproval != 0 {
		t.Fatalf("changed finding=%s v%d run=%s effects=%d err=%v", findingStatus, findingVersion, runState, effectCountBeforeApproval, err)
	}

	err = apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_run($1,$2,$3,$4,$5,'security-agent-run-idem-foreign',3,'pid_78000004-0000-4000-8000-000000000004','finding',$6,'audit-run-foreign','corr-run-foreign','receipt-run-foreign')`, foreignOrganization, workspaceID, environmentID, definitionID, actorID, evidenceID).Scan(&detail)
	if !errors.As(err, &postgresError) || postgresError.Code != "22023" {
		t.Fatalf("foreign create error=%v", err)
	}
}
