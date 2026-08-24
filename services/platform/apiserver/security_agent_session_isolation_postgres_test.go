package apiserver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestProductionSecurityAgentSessionIsolationPostgresInstallsExactAuthority(t *testing.T) {
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
		runner.UpProductionSecurityAgentConnectorRevocation,
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}

	metadata := migrations.ProductionSecurityAgentSessionIsolation()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v24 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatalf("v24 SQL: %v", err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_security_agent_session_isolation_live_fingerprint()`).Scan(&fingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionSecurityAgentSessionIsolationSemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v24 candidate fingerprint=%s", fingerprint)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionSecurityAgentSessionIsolation(ctx); err != nil {
		t.Fatalf("v24 up: %v", err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_session_isolation_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v24 readiness=%t err=%v", ready, err)
	}
	assertProductionSecurityAgentSessionIsolationLifecycle(t, ctx, dsn, connection, runner)
}

func assertProductionSecurityAgentSessionIsolationLifecycle(t *testing.T, ctx context.Context, dsn string, connection *pgx.Conn, runner *migrations.Runner) {
	t.Helper()
	if _, err := connection.Exec(ctx, `
CREATE ROLE security_agent_v24_api_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v24_worker_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE security_agent_v24_action_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_principals(session_user,'security_agent_v24_api_login','security_agent_v24_worker_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("planner principals ready=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_security_agent_register_action_principal(session_user,'security_agent_v24_action_login')`).Scan(&ready); err != nil || !ready {
		t.Fatalf("action principal ready=%t err=%v", ready, err)
	}
	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = principal
		value, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	plannerConnection := connectAs("security_agent_v24_worker_login")
	defer plannerConnection.Close(context.Background())
	actionConnection := connectAs("security_agent_v24_action_login")
	defer actionConnection.Close(context.Background())
	apiConnection := connectAs("security_agent_v24_api_login")
	defer apiConnection.Close(context.Background())
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

	organizationID := "pid_7d000001-0000-4000-8000-000000000001"
	workspaceID := "pid_7d000002-0000-4000-8000-000000000002"
	environmentID := "pid_7d000003-0000-4000-8000-000000000003"
	definitionID := "pid_7d000004-0000-4000-8000-000000000004"
	deviceID := "pid_7d000005-0000-4000-8000-000000000005"
	enrollmentID := "pid_7d000006-0000-4000-8000-000000000006"
	credentialID := "pid_7d000007-0000-4000-8000-000000000007"
	sessionID := "pid_7d000008-0000-4000-8000-000000000008"
	otherSessionID := "pid_7d000009-0000-4000-8000-000000000009"
	actorID := "pid_7d000010-0000-4000-8000-000000000010"
	foreignOrganizationID := "pid_7c000001-0000-4000-8000-000000000001"
	foreignWorkspaceID := "pid_7c000002-0000-4000-8000-000000000002"
	foreignEnvironmentID := "pid_7c000003-0000-4000-8000-000000000003"
	foreignDeviceID := "pid_7c000005-0000-4000-8000-000000000005"
	foreignEnrollmentID := "pid_7c000006-0000-4000-8000-000000000006"
	foreignCredentialID := "pid_7c000007-0000-4000-8000-000000000007"
	definition := json.RawMessage(`{"id":"` + definitionID + `","name":"Isolate compromised session","trigger_kind":"runtime_decision","trigger_source":"gateway","environment_ids":["` + environmentID + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":900,"temporary_policy_seconds":600,"ai_token_budget":4000,"concurrency_limit":1,"allowed_actions":["isolate_session"],"verification_kind":"gateway_decision","definition_version":1,"enabled":true}`)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Session tenant','session.invalid'),($2,'Foreign tenant','foreign-session.invalid')`, []any{organizationID, foreignOrganizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production'),($3,$4,'Production')`, []any{workspaceID, organizationID, foreignWorkspaceID, foreignOrganizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production'),($4,$5,$6,'Production','production')`, []any{environmentID, organizationID, workspaceID, foreignEnvironmentID, foreignOrganizationID, foreignWorkspaceID}},
		{`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,1,$5,'security-agent-actions-v1')`, []any{organizationID, workspaceID, environmentID, definitionID, definition}},
		{`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,$4),($1,$2,$3,'isolate_session',true,$4)`, []any{organizationID, workspaceID, environmentID, actorID}},
		{`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-v24','member-v24','security_admin',true)`, []any{actorID, organizationID}},
		{`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Production gateway','active'),($5,$6,$7,$8,'Foreign gateway','active')`, []any{organizationID, workspaceID, environmentID, deviceID, foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, foreignDeviceID}},
		{`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',decode(repeat('11',16),'hex'),decode(repeat('12',32),'hex'),transaction_timestamp()+interval '1 hour'),($6,$7,$8,$9,$10,'runtime-gateway-enroll',decode(repeat('13',16),'hex'),decode(repeat('14',32),'hex'),transaction_timestamp()+interval '1 hour')`, []any{organizationID, workspaceID, environmentID, enrollmentID, deviceID, foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, foreignEnrollmentID, foreignDeviceID}},
		{`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('15',32),'hex'),'runtime-gateway','ref:gateway/public/session-key',decode(repeat('16',32),'hex'),transaction_timestamp()+interval '1 hour',1,1,'session-gateway-key','Ed25519',transaction_timestamp()),($7,$8,$9,$10,$11,$12,decode(repeat('17',32),'hex'),'runtime-gateway','ref:gateway/public/foreign-key',decode(repeat('18',32),'hex'),transaction_timestamp()+interval '1 hour',1,1,'foreign-gateway-key','Ed25519',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, credentialID, deviceID, enrollmentID, foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, foreignCredentialID, foreignDeviceID, foreignEnrollmentID}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", statement.sql, err)
		}
	}
	for index, event := range []struct {
		organizationID, workspaceID, environmentID, deviceID, credentialID, eventID, sessionID string
	}{
		{organizationID, workspaceID, environmentID, deviceID, credentialID, "pid_7d000020-0000-4000-8000-000000000020", sessionID},
		{organizationID, workspaceID, environmentID, deviceID, credentialID, "pid_7d000021-0000-4000-8000-000000000021", sessionID},
		{organizationID, workspaceID, environmentID, deviceID, credentialID, "pid_7d000022-0000-4000-8000-000000000022", sessionID},
		{organizationID, workspaceID, environmentID, deviceID, credentialID, "pid_7d000023-0000-4000-8000-000000000023", otherSessionID},
		{foreignOrganizationID, foreignWorkspaceID, foreignEnvironmentID, foreignDeviceID, foreignCredentialID, "pid_7c000020-0000-4000-8000-000000000020", sessionID},
	} {
		classification := json.RawMessage(`{"category":"security","route_class":"runtime","resource_class":"session","outcome":"gateway","session_id":"` + event.sessionID + `"}`)
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,digest(convert_to($6||($8::jsonb)::text,'UTF8'),'sha256'),1,'block','http',$8::jsonb,transaction_timestamp()-make_interval(secs=>$9))`, event.organizationID, event.workspaceID, event.environmentID, event.deviceID, event.credentialID, event.eventID, index+1, classification, index); err != nil {
			t.Fatalf("event %d: %v", index, err)
		}
	}
	if created, err := planner.ScheduleSecurityAgentTriggers(ctx, "security-agent-v24-planner", 10); err != nil || created != 1 {
		t.Fatalf("schedule=%d err=%v", created, err)
	}
	claims, err := planner.ClaimSecurityAgentRuns(ctx, "security-agent-v24-planner", "planner-lease-token-v24-0001", 60, 10)
	if err != nil || len(claims) != 1 || claims[0].OrganizationID != organizationID || claims[0].TriggerID != sessionID {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	approvalID := "pid_7d000030-0000-4000-8000-000000000030"
	prepared, err := planner.PrepareSecurityAgentRun(ctx, claims[0], "security-agent-v24-planner", "planner-lease-token-v24-0001", approvalID, time.Now().UTC().Add(15*time.Minute).Truncate(time.Microsecond), "pid_7d000031-0000-4000-8000-000000000031", "pid_7d000032-0000-4000-8000-000000000032")
	if err != nil || prepared.State != "waiting_approval" {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	var approval SecurityAgentApproval
	var approvalPayload json.RawMessage
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_approval_detail_v24($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, approvalID).Scan(&approvalPayload); err != nil || json.Unmarshal(approvalPayload, &approval) != nil || approval.ExpectedEffect != "Isolate runtime session" || approval.TTLSeconds != 600 || !approval.Reversible {
		t.Fatalf("approval=%s decoded=%#v err=%v", approvalPayload, approval, err)
	}
	if err := apiConnection.QueryRow(ctx, `SELECT zasp_security_agent_decide_approval_v24($1,$2,$3,$4,$5,'session-isolation-approval-0001',1,'approved',transaction_timestamp(),$6,$7,$8)`, organizationID, workspaceID, environmentID, approvalID, actorID, "pid_7d000033-0000-4000-8000-000000000033", "pid_7d000034-0000-4000-8000-000000000034", "pid_7d000035-0000-4000-8000-000000000035").Scan(&approvalPayload); err != nil {
		t.Fatalf("approve: %v", err)
	}
	claims, err = planner.ClaimSecurityAgentRuns(ctx, "security-agent-v24-planner", "planner-lease-token-v24-0002", 60, 10)
	if err != nil || len(claims) != 1 || !claims[0].Prepared {
		t.Fatalf("approved claims=%#v err=%v", claims, err)
	}
	dispatched, err := planner.ExecuteSecurityAgentRun(ctx, claims[0], "security-agent-v24-planner", "planner-lease-token-v24-0002", "pid_7d000036-0000-4000-8000-000000000036", "pid_7d000037-0000-4000-8000-000000000037")
	if err != nil || dispatched.State != "running" || dispatched.EffectState != "pending" {
		t.Fatalf("dispatched=%#v err=%v", dispatched, err)
	}
	effects, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "security-agent-v24-action", "action-lease-token-v24-0001", 60, 10)
	if err != nil || len(effects) != 1 || effects[0].OrganizationID != organizationID || effects[0].ActionKey != "isolate_session" || effects[0].SessionID != sessionID || len(effects[0].Targets) != 1 || effects[0].Targets[0].DeviceID != deviceID || effects[0].Targets[0].CredentialID != credentialID {
		t.Fatalf("effects=%#v err=%v", effects, err)
	}
	var foreignTargets int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE organization_id=$1 OR device_id=$2`, foreignOrganizationID, foreignDeviceID).Scan(&foreignTargets); err != nil || foreignTargets != 0 {
		t.Fatalf("foreign targets=%d err=%v", foreignTargets, err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	applyPolicies := postgresSessionIsolationPolicies(t, sessionID)
	applyEnvelope := postgresTemporaryPolicyEnvelope(t, effects[0], effects[0].Targets[0], "gateway-key-v24", privateKey, now, now.Add(time.Duration(effects[0].TTLSeconds)*time.Second), applyPolicies)
	if err := actionRepository.StoreTemporaryPolicyTarget(ctx, effects[0], "security-agent-v24-action", "action-lease-token-v24-0001", applyEnvelope); err != nil {
		t.Fatalf("store apply: %v", err)
	}
	applyReadback, err := actionRepository.ReadTemporaryPolicyTarget(ctx, effects[0], effects[0].Targets[0])
	if err != nil || applyReadback.EnvelopeDigest != applyEnvelope.EnvelopeDigest {
		t.Fatalf("apply readback=%#v err=%v", applyReadback, err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-v24": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := policy.VerifyGatewayPolicyEnvelope(gatewayPolicyEnvelopeFromTemporary(t, effects[0], applyReadback, applyPolicies), keys, policy.GatewayPolicyBinding{OrganizationID: organizationID, WorkspaceID: workspaceID, EnvironmentID: environmentID, DeviceID: deviceID}, now)
	if err != nil || len(verified.Policies) != 2 {
		t.Fatalf("verify policies=%#v err=%v", verified, err)
	}
	for _, compiled := range verified.Policies {
		input := map[string]string{"session_id": sessionID}
		if compiled.Trigger == "tool_call" {
			input["tool.name"] = "shell"
		} else {
			input["http.method"] = "POST"
		}
		blocked, blockedErr := policy.Evaluate(ctx, compiled, input)
		input["session_id"] = otherSessionID
		allowed, allowedErr := policy.Evaluate(ctx, compiled, input)
		if blockedErr != nil || !blocked.Matched || blocked.Action != policy.ActionBlock || allowedErr != nil || allowed.Matched {
			t.Fatalf("session policy=%#v blocked=%#v blocked_err=%v allowed=%#v allowed_err=%v", compiled, blocked, blockedErr, allowed, allowedErr)
		}
	}
	applyResultDigest := postgresTemporaryResultDigest(t, effects[0].InputDigest, applyEnvelope.EnvelopeDigest)
	finished, err := actionRepository.FinishTemporaryPolicyEffect(ctx, effects[0], "security-agent-v24-action", "action-lease-token-v24-0001", applyResultDigest, "pid_7d000038-0000-4000-8000-000000000038", "pid_7d000039-0000-4000-8000-000000000039")
	if err != nil || finished.EffectState != "cleanup_pending" {
		t.Fatalf("finish apply=%#v err=%v", finished, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_security_agent_effects SET updated_at=transaction_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=($1,$2,$3,$4,$5,'isolate_session')`, organizationID, workspaceID, environmentID, effects[0].RunID, effects[0].StepID); err != nil {
		t.Fatal(err)
	}
	cleanupEffects, err := actionRepository.ClaimTemporaryPolicyEffects(ctx, "security-agent-v24-action", "action-lease-token-v24-0002", 60, 10)
	if err != nil || len(cleanupEffects) != 1 || cleanupEffects[0].Phase != "cleanup" || cleanupEffects[0].SessionID != sessionID || len(cleanupEffects[0].Targets) != 1 {
		t.Fatalf("cleanup effects=%#v err=%v", cleanupEffects, err)
	}
	cleanupEnvelope := postgresTemporaryPolicyEnvelope(t, cleanupEffects[0], cleanupEffects[0].Targets[0], "gateway-key-v24", privateKey, now.Add(time.Second), now.Add(5*time.Minute+time.Second), nil)
	if err := actionRepository.StoreTemporaryPolicyTarget(ctx, cleanupEffects[0], "security-agent-v24-action", "action-lease-token-v24-0002", cleanupEnvelope); err != nil {
		t.Fatalf("store cleanup: %v", err)
	}
	cleanupResultDigest := postgresTemporaryResultDigest(t, cleanupEffects[0].InputDigest, cleanupEnvelope.EnvelopeDigest)
	finished, err = actionRepository.FinishTemporaryPolicyEffect(ctx, cleanupEffects[0], "security-agent-v24-action", "action-lease-token-v24-0002", cleanupResultDigest, "pid_7d000040-0000-4000-8000-000000000040", "pid_7d000041-0000-4000-8000-000000000041")
	if err != nil || finished.EffectState != "cleaned" {
		t.Fatalf("finish cleanup=%#v err=%v", finished, err)
	}
	var runState string
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, effects[0].RunID).Scan(&runState); err != nil || runState != "remediated" {
		t.Fatalf("run state=%q err=%v", runState, err)
	}
	if err := runner.DownProductionSecurityAgentSessionIsolation(ctx); err == nil {
		t.Fatal("v24 down accepted durable session-isolation authority")
	}
}

func postgresSessionIsolationPolicies(t *testing.T, sessionID string) []policy.CompiledPolicy {
	t.Helper()
	definitions := []policy.Policy{
		{ID: "session-isolation-http-v1", Trigger: "http_request", Conditions: []policy.Condition{{Field: "http.method", Operator: "present"}, {Field: "session_id", Operator: "equals", Value: sessionID}}, Action: policy.ActionBlock},
		{ID: "session-isolation-mcp-v1", Trigger: "tool_call", Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}, {Field: "session_id", Operator: "equals", Value: sessionID}}, Action: policy.ActionBlock},
	}
	compiled := make([]policy.CompiledPolicy, len(definitions))
	for index, definition := range definitions {
		value, err := policy.Compile(definition)
		if err != nil {
			t.Fatal(err)
		}
		compiled[index] = value
	}
	return compiled
}

func gatewayPolicyEnvelopeFromTemporary(t *testing.T, claim TemporaryPolicyEffectClaim, envelope TemporaryPolicyTargetEnvelope, policies []policy.CompiledPolicy) policy.GatewayPolicyEnvelope {
	t.Helper()
	return policy.GatewayPolicyEnvelope{
		ContractVersion: 1, KeyID: envelope.KeyID, Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: envelope.Target.DeviceID,
		Sequence: uint64(envelope.Target.Sequence), PolicyVersion: uint64(envelope.Target.PolicyVersion), IssuedAt: envelope.IssuedAt, ExpiresAt: envelope.ExpiresAt, FailureMode: envelope.FailureMode,
		Policies: policies, PayloadDigest: envelope.PayloadDigest[len("sha256:"):], Signature: base64.RawURLEncoding.EncodeToString(envelope.Signature),
	}
}
