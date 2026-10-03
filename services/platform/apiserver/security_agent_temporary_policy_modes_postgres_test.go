// Source-component fixture only. It never admits a native packet, registers81,
// or asserts deployed/provider acceptance. Baseline uses unchanged22 functions.
package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestTemporaryPolicyMonitorPostgresSourceLifecycle(t *testing.T) {
	observation := &disposablePostgresCleanupObservation{}
	t.Cleanup(func() {
		got := observation.snapshot()
		if !got.Available || !got.PGCtlStopped || !got.CommandWaitJoined || !got.NormalExit || got.SurvivingResources != 0 {
			t.Errorf("Monitor source fixture cleanup unresolved: %#v", got)
		}
	})
	registerDisposablePostgresCleanupObservation(t, observation)
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var serverVersion int
	var postmasterStarted time.Time
	var postmasterPID string
	if err := connection.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer,pg_postmaster_start_time(),split_part(pg_read_file('postmaster.pid'),E'\n',1)`).Scan(&serverVersion, &postmasterStarted, &postmasterPID); err != nil || serverVersion != 180003 || postmasterPID == "" {
		t.Fatalf("private PG18.3 profile version=%d pid=%q err=%v", serverVersion, postmasterPID, err)
	}
	t.Logf("source-only owned PG18.3 pid=%s started=%s production=false native=false", postmasterPID, postmasterStarted.UTC().Format(time.RFC3339Nano))
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{
		runner.UpProductionRuntimeDataPlane,
		runner.UpProductionRuntimeGatewayReconciliation,
		runner.UpProductionRuntimeIngestReconciliation,
		runner.UpProductionSecurityAgentExecution,
		runner.UpProductionIdentityAdministration,
		runner.UpProductionSecurityAgentControls,
		runner.UpProductionSecurityAgentAutonomousResponse,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	metadata := migrations.ProductionSecurityAgentTemporaryPolicy()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v22 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatalf("v22 SQL: %v", err)
	}
	var probeFingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_security_agent_temporary_policy_live_fingerprint()`).Scan(&probeFingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if probeFingerprint != migrations.ProductionSecurityAgentTemporaryPolicySemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v22 candidate fingerprint=%s", probeFingerprint)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(22,'security_agent_temporary_policy',$1)`, metadata.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var probeSecurity, probeReady bool
	if err := probe.QueryRow(ctx, `SELECT zasp_security_agent_temporary_policy_security_ready(),zasp_security_agent_temporary_policy_readiness($1,$2)`, metadata.Checksum(), probeFingerprint).Scan(&probeSecurity, &probeReady); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if !probeSecurity || !probeReady {
		_ = probe.Rollback(ctx)
		t.Fatalf("v22 candidate security=%t readiness=%t", probeSecurity, probeReady)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionSecurityAgentTemporaryPolicy(ctx); err != nil {
		t.Fatalf("v22 up: %v", err)
	}
	var fingerprint string
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_temporary_policy_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionSecurityAgentTemporaryPolicySemanticFingerprint() {
		t.Fatalf("v22 fingerprint=%s", fingerprint)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_temporary_policy_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v22 readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE security_agent_temporary_discovery_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT zasp_discovery_api TO security_agent_temporary_discovery_api_login`); err != nil {
		t.Fatal(err)
	}
	discoveryAPIConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	discoveryAPIConfig.User = "security_agent_temporary_discovery_api_login"
	discoveryAPI, err := pgx.ConnectConfig(ctx, discoveryAPIConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer discoveryAPI.Close(context.Background())
	if err := discoveryAPI.QueryRow(ctx, `SELECT zasp_security_agent_temporary_policy_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v22 discovery API readiness=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE security_agent_action_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE security_agent_temporary_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE security_agent_temporary_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE temporary_runtime_coordinator LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE temporary_runtime_archive LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE temporary_runtime_index LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE temporary_runtime_correlation LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE temporary_runtime_projection LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE temporary_runtime_gateway LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_temporary_api_login','security_agent_temporary_worker_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("planner registration=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_action_principal(session_user,'security_agent_action_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("action principal registration=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_register_principals(session_user,'temporary_runtime_coordinator','temporary_runtime_archive','temporary_runtime_index','temporary_runtime_correlation','temporary_runtime_projection','temporary_runtime_gateway')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("runtime principal registration=%t err=%v", ready, err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "security_agent_action_login"
	actionWorker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer actionWorker.Close(context.Background())
	if err := actionWorker.QueryRow(ctx, `SELECT zasp_security_agent_action_principal_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("action principal ready=%t err=%v", ready, err)
	}
	var canGatewayControl, canPlanner, canClaim bool
	if err := connection.QueryRow(ctx, `SELECT pg_has_role('security_agent_action_login','zasp_gateway_control','MEMBER'),pg_has_role('security_agent_action_login','zasp_security_agent_worker','MEMBER'),has_function_privilege('security_agent_action_login','public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)','EXECUTE')`).Scan(&canGatewayControl, &canPlanner, &canClaim); err != nil {
		t.Fatal(err)
	}
	if canGatewayControl || canPlanner || !canClaim {
		t.Fatalf("action authority gateway=%t planner=%t claim=%t", canGatewayControl, canPlanner, canClaim)
	}

	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		principalConfig, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		principalConfig.User = principal
		value, connectErr := pgx.ConnectConfig(ctx, principalConfig)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		return value
	}
	plannerConnection := connectAs("security_agent_temporary_worker_login")
	defer plannerConnection.Close(context.Background())
	apiConnection := connectAs("security_agent_temporary_api_login")
	defer apiConnection.Close(context.Background())
	gatewayConnection := connectAs("temporary_runtime_gateway")
	defer gatewayConnection.Close(context.Background())
	plannerDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: plannerConnection})
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewSecurityAgentWorkerRepository(plannerDatabase)
	if err != nil {
		t.Fatal(err)
	}
	actionDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: actionWorker})
	if err != nil {
		t.Fatal(err)
	}
	actionRepository, err := NewSecurityAgentActionRepository(actionDatabase)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit owned source fixture grants only, never production registration.
	if _, err := connection.Exec(ctx, migrations.TemporaryPolicyModesSourceSQL()); err != nil {
		t.Fatalf("source81 SQL: %v", err)
	}
	if _, err := connection.Exec(ctx, `GRANT USAGE ON SCHEMA zasp_sa_temporary81 TO zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
 GRANT EXECUTE ON FUNCTION zasp_sa_temporary81.prepare_run(text,text,text,text,text,text,text,timestamptz,text,text),zasp_sa_temporary81.dispatch_run(text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;
 GRANT EXECUTE ON FUNCTION zasp_sa_temporary81.approval_detail(text,text,text,text),zasp_sa_temporary81.decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
 GRANT EXECUTE ON FUNCTION zasp_sa_temporary81.claim_effects(text,text,integer,integer),zasp_sa_temporary81.heartbeat_effect(text,text,text,text,text,text,text,integer),zasp_sa_temporary81.store_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea),zasp_sa_temporary81.read_target(text,text,text,text,text,text,text),zasp_sa_temporary81.finish_effect(text,text,text,text,text,text,text,text,bytea,text,text) TO zasp_security_agent_action_worker`); err != nil {
		t.Fatal(err)
	}
	var publicReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_sa_temporary81.ready($1,$1)`, migrations.TemporaryPolicyModesSourceChecksum()).Scan(&publicReady); err != nil || publicReady {
		t.Fatalf("unadmitted source81 publicly ready=%v err=%v", publicReady, err)
	}
	if admitted, err := NewSecurityAgentTemporaryPolicyModesRepository(actionDatabase); admitted != nil || err != ErrRepositoryConfiguration {
		t.Fatalf("source81 production constructor admitted=%v err=%v", admitted, err)
	}
	planner.prepareSQL = `SELECT zasp_sa_temporary81.prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	planner.executeSQL = `SELECT zasp_sa_temporary81.dispatch_run($1,$2,$3,$4,$5,$6,$7,$8)`
	actionRepository = temporaryPolicyModesSourceRepository(actionDatabase)
	organizationID := "pid_7e000001-0000-4000-8000-000000000001"
	workspaceID := "pid_7e000002-0000-4000-8000-000000000002"
	environmentID := "pid_7e000003-0000-4000-8000-000000000003"
	definitionID := "pid_7e000004-0000-4000-8000-000000000004"
	findingID := "pid_7e000005-0000-4000-8000-000000000005"
	deviceID := "pid_7e000006-0000-4000-8000-000000000006"
	enrollmentID := "pid_7e000007-0000-4000-8000-000000000007"
	credentialID := "pid_7e000008-0000-4000-8000-000000000008"
	rotatedEnrollmentID := "pid_7e000009-0000-4000-8000-000000000009"
	rotatedCredentialID := "pid_7e000019-0000-4000-8000-000000000019"
	body := json.RawMessage(`{"id":"` + definitionID + `","name":"Contain exposed credentials","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"temporary_policy_mode":"monitor","ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["create_temporary_policy"],"verification_kind":"policy_state","definition_version":1,"enabled":true}`)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Temporary policy tenant','temporary-policy.invalid')`, []any{organizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production')`, []any{workspaceID, organizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, []any{environmentID, organizationID, workspaceID}},
		{`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,$5,'security-agent-actions-v1')`, []any{organizationID, workspaceID, environmentID, definitionID, body}},
		{`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,'pid_7e000020-0000-4000-8000-000000000020'),($1,$2,$3,'create_temporary_policy',true,'pid_7e000020-0000-4000-8000-000000000020')`, []any{organizationID, workspaceID, environmentID}},
		{`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Discovered credential exposure','high','open')`, []any{organizationID, workspaceID, environmentID, findingID}},
		{`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Production gateway','active')`, []any{organizationID, workspaceID, environmentID, deviceID}},
		{`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',repeat(E'\\001',16)::bytea,repeat(E'\\002',32)::bytea,transaction_timestamp()+interval '1 hour')`, []any{organizationID, workspaceID, environmentID, enrollmentID, deviceID}},
		{`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,$6,repeat(E'\\003',32)::bytea,'runtime-gateway','ref:gateway/public/gateway-device-key-01',repeat(E'\\004',32)::bytea,transaction_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, credentialID, deviceID, enrollmentID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) VALUES($1,$2,$3,$4,1,'supervised',$5,digest(convert_to(($5::jsonb)::text,'UTF8'),'sha256'),'source-fixture-operator')`, organizationID, workspaceID, environmentID, definitionID, body); err != nil {
		t.Fatal(err)
	}
	compatibilityPolicy := json.RawMessage(`{"id":"policy-v22-compatibility","name":"V22 PAT compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	compatibilityIntent := json.RawMessage(`{"body":` + string(compatibilityPolicy) + `,"expected_version":0,"resource_id":""}`)
	var compatibilityResult json.RawMessage
	if err := discoveryAPI.QueryRow(ctx, `SELECT zasp_workflow_mutate('create','policy','policy-v22-compatibility',$1,$2,$3,'pid_7e000020-0000-4000-8000-000000000020','createPolicy','temporary-policy-pat-0001',0,$4::jsonb,$5::jsonb,'pid_7e000021-0000-4000-8000-000000000021','pid_7e000022-0000-4000-8000-000000000022','')`, organizationID, workspaceID, environmentID, compatibilityIntent, compatibilityPolicy).Scan(&compatibilityResult); err != nil || !strings.Contains(string(compatibilityResult), `"version": 1`) {
		t.Fatalf("v22 PAT workflow mutation=%s err=%v", compatibilityResult, err)
	}
	var controls struct {
		Actions []SecurityAgentExecutionControl `json:"actions"`
	}
	var controlsPayload json.RawMessage
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_execution_control_detail($1,$2,$3)`, organizationID, workspaceID, environmentID).Scan(&controlsPayload); err != nil || json.Unmarshal(controlsPayload, &controls) != nil || len(controls.Actions) != 2 || controls.Actions[0].ActionKey != "create_temporary_policy" || controls.Actions[1].ActionKey != "update_finding_response" {
		t.Fatalf("controls=%s decoded=%#v err=%v", controlsPayload, controls, err)
	}
	idempotencyValues := []string{"temporary-policy-control-0001", "temporary-policy-control-0002"}
	auditValues := []string{"pid_7e000021-0000-4000-8000-000000000021", "pid_7e000025-0000-4000-8000-000000000025"}
	correlationValues := []string{"pid_7e000022-0000-4000-8000-000000000022", "pid_7e000026-0000-4000-8000-000000000026"}
	receiptValues := []string{"pid_7e000023-0000-4000-8000-000000000023", "pid_7e000027-0000-4000-8000-000000000027"}
	for index, enabled := range []bool{false, true} {
		var mutation struct {
			ActionKey string `json:"action_key"`
			Enabled   bool   `json:"enabled"`
			Version   int64  `json:"version"`
		}
		if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,$5,'action','create_temporary_policy',$6,$7,transaction_timestamp()+interval '4 minutes',$8,$9,$10)`, organizationID, workspaceID, environmentID, "pid_7e000020-0000-4000-8000-000000000020", idempotencyValues[index], enabled, int64(index+1), auditValues[index], correlationValues[index], receiptValues[index]).Scan(&controlsPayload); err != nil || json.Unmarshal(controlsPayload, &mutation) != nil || mutation.ActionKey != "create_temporary_policy" || mutation.Enabled != enabled || mutation.Version != int64(index+2) {
			t.Fatalf("control mutation=%s decoded=%#v err=%v", controlsPayload, mutation, err)
		}
	}
	autonomousDefinitionID := "pid_7e000024-0000-4000-8000-000000000024"
	autonomousBody := json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(string(body), definitionID, autonomousDefinitionID), `"autonomy":"supervised"`, `"autonomy":"autonomous"`))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'autonomous',1,1,$5,'security-agent-actions-v1')`, organizationID, workspaceID, environmentID, autonomousDefinitionID, autonomousBody); err == nil {
		t.Fatal("accepted autonomous temporary policy definition")
	} else {
		var provider *pgconn.PgError
		if !errors.As(err, &provider) || provider.Code != "23514" {
			t.Fatalf("autonomous temporary policy err=%v", err)
		}
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-planner-e2e", 10); err != nil || created != 1 {
		t.Fatalf("schedule=%d err=%v", created, err)
	}
	claims, err := planner.ClaimSecurityAgentRuns(ctx, "security-agent-planner-e2e", "planner-lease-token-000001", 60, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	approvalID := "pid_7e000010-0000-4000-8000-000000000010"
	prepared, err := planner.PrepareSecurityAgentRun(ctx, claims[0], "security-agent-planner-e2e", "planner-lease-token-000001", approvalID, time.Now().UTC().Add(15*time.Minute).Truncate(time.Microsecond), "pid_7e000011-0000-4000-8000-000000000011", "pid_7e000012-0000-4000-8000-000000000012")
	if err != nil || prepared.State != "waiting_approval" {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	var plannedMode string
	if err := connection.QueryRow(ctx, `SELECT plan->'steps'->0->>'mode' FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, claims[0].RunID).Scan(&plannedMode); err != nil || plannedMode != "monitor" {
		t.Fatalf("saved Monitor planner emitted=%q err=%v", plannedMode, err)
	}
	var approvalDetail SecurityAgentApproval
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_sa_temporary81.approval_detail($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, approvalID).Scan(&controlsPayload); err != nil || json.Unmarshal(controlsPayload, &approvalDetail) != nil || approvalDetail.ExpectedEffect != "Apply temporary monitoring policy" || approvalDetail.TTLSeconds != 600 || !approvalDetail.Reversible {
		t.Fatalf("approval detail=%s decoded=%#v err=%v", controlsPayload, approvalDetail, err)
	}
	var approval json.RawMessage
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_sa_temporary81.decide_approval($1,$2,$3,$4,'pid_7e000013-0000-4000-8000-000000000013','temporary-policy-approval-0001',1,'approved',transaction_timestamp(),'pid_7e000014-0000-4000-8000-000000000014','pid_7e000015-0000-4000-8000-000000000015','pid_7e000016-0000-4000-8000-000000000016')`, organizationID, workspaceID, environmentID, approvalID).Scan(&approval); err != nil || !strings.Contains(string(approval), `"expected_effect": "Apply temporary monitoring policy"`) || !strings.Contains(string(approval), `"ttl_seconds": 600`) {
		t.Fatalf("approval=%s err=%v", approval, err)
	}
	claims, err = planner.ClaimSecurityAgentRuns(ctx, "security-agent-planner-e2e", "planner-lease-token-000002", 60, 10)
	if err != nil || len(claims) != 1 || !claims[0].Prepared {
		t.Fatalf("approved claims=%#v err=%v", claims, err)
	}
	dispatched, err := planner.ExecuteSecurityAgentRun(ctx, claims[0], "security-agent-planner-e2e", "planner-lease-token-000002", "pid_7e000017-0000-4000-8000-000000000017", "pid_7e000018-0000-4000-8000-000000000018")
	if err != nil || dispatched.State != "running" || dispatched.EffectState != "pending" {
		t.Fatalf("dispatched=%#v err=%v", dispatched, err)
	}
	effects, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "security-agent-action-e2e", "action-lease-token-000001", 60, 10)
	if err != nil || len(effects) != 1 || effects[0].OrganizationID != organizationID || len(effects[0].Targets) != 1 || effects[0].Targets[0].CredentialID != credentialID {
		t.Fatalf("effects=%#v err=%v", effects, err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	applyPolicies := postgresTemporaryContainmentPolicies(t)
	for i := range applyPolicies {
		input := policy.Policy{ID: strings.Replace(applyPolicies[i].ID, "containment", "monitor", 1), Trigger: applyPolicies[i].Trigger, Conditions: applyPolicies[i].Conditions, Action: policy.ActionMonitor}
		compiled, err := policy.Compile(input)
		if err != nil {
			t.Fatal(err)
		}
		applyPolicies[i] = compiled
	}
	applyEnvelope := postgresTemporaryPolicyEnvelope(t, effects[0], effects[0].Targets[0], "gateway-key-01", privateKey, now, now.Add(time.Duration(effects[0].TTLSeconds)*time.Second), applyPolicies)
	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false,version=version+1 WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'create_temporary_policy')`, organizationID, workspaceID, environmentID); err != nil {
		t.Fatal(err)
	}
	if err := actionRepository.StoreTemporaryPolicyTarget(ctx, effects[0], "security-agent-action-e2e", "action-lease-token-000001", applyEnvelope); err == nil {
		t.Fatal("stored apply while action kill switch was disabled")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true,version=version+1 WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'create_temporary_policy')`, organizationID, workspaceID, environmentID); err != nil {
		t.Fatal(err)
	}
	if err := actionRepository.StoreTemporaryPolicyTarget(ctx, effects[0], "security-agent-action-e2e", "action-lease-token-000001", applyEnvelope); err != nil {
		t.Fatalf("store apply: %v", err)
	}
	applyReadback, err := actionRepository.ReadTemporaryPolicyTarget(ctx, effects[0], effects[0].Targets[0])
	if err != nil || applyReadback.EnvelopeDigest != applyEnvelope.EnvelopeDigest {
		t.Fatalf("apply readback=%#v err=%v", applyReadback, err)
	}
	// Neither tenant, workspace nor environment aliases can read this signed target.
	for dimension := 0; dimension < 3; dimension++ {
		foreign := effects[0]
		other := "pid_81000099-0000-4000-8000-000000000099"
		switch dimension {
		case 0:
			foreign.OrganizationID = other
		case 1:
			foreign.WorkspaceID = other
		case 2:
			foreign.EnvironmentID = other
		}
		if _, err := actionRepository.ReadTemporaryPolicyTarget(ctx, foreign, effects[0].Targets[0]); err == nil {
			t.Fatalf("cross-scope Monitor read accepted dimension=%d", dimension)
		}
	}
	applyResultDigest := postgresTemporaryResultDigest(t, effects[0].InputDigest, applyEnvelope.EnvelopeDigest)
	if _, err := actionRepository.FinishTemporaryPolicyEffect(ctx, effects[0], "security-agent-action-e2e", "action-lease-token-000001", "sha256:"+strings.Repeat("0", sha256.Size*2), "pid_7e000034-0000-4000-8000-000000000034", "pid_7e000035-0000-4000-8000-000000000035"); err == nil {
		t.Fatal("accepted unbound result digest")
	}
	for _, rotation := range []struct {
		query string
		args  []any
	}{
		{`UPDATE zasp_gateway_credentials SET revoked_at=transaction_timestamp() WHERE id=$1`, []any{credentialID}},
		{`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at,consumed_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',decode(repeat('05',16),'hex'),decode(repeat('06',32),'hex'),transaction_timestamp()+interval '1 hour',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, rotatedEnrollmentID, deviceID}},
		{`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('07',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-02',decode(repeat('08',32),'hex'),transaction_timestamp()+interval '1 hour',1,2,'gateway-device-key-02','Ed25519',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, rotatedCredentialID, deviceID, rotatedEnrollmentID}},
	} {
		if _, err := connection.Exec(ctx, rotation.query, rotation.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := actionRepository.FinishTemporaryPolicyEffect(ctx, effects[0], "security-agent-action-e2e", "action-lease-token-000001", applyResultDigest, "pid_7e000036-0000-4000-8000-000000000036", "pid_7e000037-0000-4000-8000-000000000037"); err == nil {
		t.Fatal("accepted rotated credential before durable finish")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=($1,$2,$3,$4,$5,'create_temporary_policy')`, organizationID, workspaceID, environmentID, effects[0].RunID, effects[0].StepID); err != nil {
		t.Fatal(err)
	}
	recoveredEffects, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "security-agent-action-e2e", "action-lease-token-000002", 60, 10)
	if err != nil || len(recoveredEffects) != 1 || recoveredEffects[0].Phase != "apply" || len(recoveredEffects[0].Targets) != 1 || recoveredEffects[0].Targets[0].CredentialID != rotatedCredentialID || recoveredEffects[0].Targets[0].Sequence != effects[0].Targets[0].Sequence+1 {
		t.Fatalf("recovered effects=%#v err=%v", recoveredEffects, err)
	}
	effects = recoveredEffects
	now = now.Add(time.Second)
	applyEnvelope = postgresTemporaryPolicyEnvelope(t, effects[0], effects[0].Targets[0], "gateway-key-01", privateKey, now, now.Add(time.Duration(effects[0].TTLSeconds)*time.Second), applyPolicies)
	if err := actionRepository.StoreTemporaryPolicyTarget(ctx, effects[0], "security-agent-action-e2e", "action-lease-token-000002", applyEnvelope); err != nil {
		t.Fatalf("store recovered apply: %v", err)
	}
	applyResultDigest = postgresTemporaryResultDigest(t, effects[0].InputDigest, applyEnvelope.EnvelopeDigest)
	finished, err := actionRepository.FinishTemporaryPolicyEffect(ctx, effects[0], "security-agent-action-e2e", "action-lease-token-000002", applyResultDigest, "pid_7e000030-0000-4000-8000-000000000030", "pid_7e000031-0000-4000-8000-000000000031")
	if err != nil || finished.EffectState != "cleanup_pending" {
		t.Fatalf("finish apply=%#v err=%v", finished, err)
	}
	verifyPostgresTemporaryPolicyBundle(t, ctx, gatewayConnection, rotatedCredentialID, 0, effects[0], publicKey, now, 2)
	if premature, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "monitor-future-probe", "monitor-future-lease-0001", 60, 10); err != nil || len(premature) != 0 {
		t.Fatalf("future Monitor expiry was changed: %#v err=%v", premature, err)
	}
	for _, edited := range []bool{false, true} {
		name := "revoked_target_missing_verification"
		if edited {
			name = "immutable_definition_cleanup_continuity"
		}
		t.Run(name, func(t *testing.T) {
			probe, err := connection.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Rollback(context.Background())
			if edited {
				if _, err := probe.Exec(ctx, `UPDATE zasp_security_agent_definitions SET version=2,body=jsonb_set(body,'{temporary_policy_mode}','"block"'::jsonb) WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, definitionID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := probe.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, rotatedCredentialID); err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Exec(ctx, `UPDATE zasp_security_agent_effects SET updated_at=transaction_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, organizationID, workspaceID, environmentID, effects[0].RunID, effects[0].StepID); err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION security_agent_action_login`); err != nil {
				t.Fatal(err)
			}
			var revokedClaim json.RawMessage
			if err := probe.QueryRow(ctx, `SELECT zasp_sa_temporary81.claim_effects('source-revoked-target-cleanup','source-revoked-lease-0001',60,10)`).Scan(&revokedClaim); err != nil || !strings.Contains(string(revokedClaim), `"items": []`) {
				t.Fatalf("revoked target cleanup edited=%v result=%s err=%v", edited, revokedClaim, err)
			}
			if _, err := probe.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION DEFAULT`); err != nil {
				t.Fatal(err)
			}
			var revokedState, revokedEffect string
			var truthfulAudit bool
			if err := probe.QueryRow(ctx, `SELECT run.state,effect.state,EXISTS(SELECT 1 FROM zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id)=($1,$2,$3,$4,$5) AND a.event_kind='cleanup_failed' AND a.body->>'reason'='no_active_gateway_target' AND a.body->>'mode'='monitor') FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,effect.step_id)=($1,$2,$3,$4,$5)`, organizationID, workspaceID, environmentID, effects[0].RunID, effects[0].StepID).Scan(&revokedState, &revokedEffect, &truthfulAudit); err != nil || revokedState != "needs_human" || revokedEffect != "cleanup_failed" || !truthfulAudit {
				t.Fatalf("unverified cleanup state=%s effect=%s audit=%v err=%v", revokedState, revokedEffect, truthfulAudit, err)
			}
		})
	}

	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_effects SET updated_at=transaction_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=($1,$2,$3,$4,$5,'create_temporary_policy')`, organizationID, workspaceID, environmentID, effects[0].RunID, effects[0].StepID); err != nil {
		t.Fatal(err)
	}
	cleanupEffects, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "security-agent-action-e2e", "action-lease-token-000003", 60, 10)
	if err != nil || len(cleanupEffects) != 1 || cleanupEffects[0].Phase != "cleanup" || len(cleanupEffects[0].Targets) != 1 || cleanupEffects[0].Targets[0].Sequence != effects[0].Targets[0].Sequence+1 {
		t.Fatalf("cleanup effects=%#v err=%v", cleanupEffects, err)
	}
	cleanupEnvelope := postgresTemporaryPolicyEnvelope(t, cleanupEffects[0], cleanupEffects[0].Targets[0], "gateway-key-01", privateKey, now.Add(time.Second), now.Add(5*time.Minute+time.Second), nil)
	if err := actionRepository.StoreTemporaryPolicyTarget(ctx, cleanupEffects[0], "security-agent-action-e2e", "action-lease-token-000003", cleanupEnvelope); err != nil {
		t.Fatalf("store cleanup: %v", err)
	}
	cleanupResultDigest := postgresTemporaryResultDigest(t, cleanupEffects[0].InputDigest, cleanupEnvelope.EnvelopeDigest)
	finished, err = actionRepository.FinishTemporaryPolicyEffect(ctx, cleanupEffects[0], "security-agent-action-e2e", "action-lease-token-000003", cleanupResultDigest, "pid_7e000032-0000-4000-8000-000000000032", "pid_7e000033-0000-4000-8000-000000000033")
	if err != nil || finished.EffectState != "cleaned" {
		t.Fatalf("finish cleanup=%#v err=%v", finished, err)
	}
	verifyPostgresTemporaryPolicyBundle(t, ctx, gatewayConnection, rotatedCredentialID, effects[0].Targets[0].Sequence, cleanupEffects[0], publicKey, now.Add(time.Second), 0)
	if repeated, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "monitor-complete-probe", "monitor-complete-lease-0001", 60, 10); err != nil || len(repeated) != 0 {
		t.Fatalf("completed Monitor cleanup was claimed again: %#v err=%v", repeated, err)
	}
	var runState string
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, effects[0].RunID).Scan(&runState); err != nil || runState != "needs_human" {
		t.Fatalf("run state=%q err=%v", runState, err)
	}
}
