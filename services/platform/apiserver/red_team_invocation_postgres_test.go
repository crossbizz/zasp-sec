package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const invocationTarget = "pid_95000001-0000-4000-8000-000000000001"
const invocationDefinition = "pid_95000002-0000-4000-8000-000000000002"
const invocationRun = "pid_95000003-0000-4000-8000-000000000003"
const invocationIntegration = "pid_95000004-0000-4000-8000-000000000004"
const invocationSnapshot = "pid_95000005-0000-4000-8000-000000000005"
const invocationEvidence = "pid_95000006-0000-4000-8000-000000000006"

func TestRedTeamLegacyTargetLookupCannotBypassRunLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	connection, runner, adapter, worker := redTeamInvocationFixture(t, ctx)
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, migrations.ProductionRedTeamInvocation().UpSQL()); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_production_red_team_invocation_live_fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionRedTeamInvocationSemanticFingerprint() {
		t.Fatalf("candidate v38 fingerprint=%s", fingerprint)
	}
	if err := runner.UpProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	var body json.RawMessage
	if err := adapter.QueryRow(ctx, `SELECT zasp_red_team_resolve_target($1,$2,$3,$4,'agent_endpoint')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), invocationTarget).Scan(&body); err == nil {
		t.Fatal("legacy target lookup returned credentials without any run or lease authority")
	}
	arguments := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), invocationTarget, "agent_endpoint", invocationRun, strings.Repeat("a", 32), "prompt_injection"}
	const resolveSQL = `SELECT zasp_red_team_resolve_invocation($1,$2,$3,$4,$5,$6,$7,$8)`
	resolve := func() {
		t.Helper()
		if err := adapter.QueryRow(ctx, resolveSQL, arguments...).Scan(&body); err != nil || !bytes.Contains(body, []byte(`"target_id": "`+invocationTarget+`"`)) {
			t.Fatalf("authorized resolve=%s err=%v", body, err)
		}
	}
	resolve()
	var ready bool
	if err := adapter.QueryRow(ctx, `SELECT zasp_red_team_invocation_readiness($1,$2)`, migrations.ProductionRedTeamInvocation().Checksum(), migrations.ProductionRedTeamInvocationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("adapter readiness=%t err=%v", ready, err)
	}
	if err := worker.QueryRow(ctx, resolveSQL, arguments...).Scan(&body); err == nil {
		t.Fatal("worker principal resolved target credentials")
	}
	if err := adapter.QueryRow(ctx, `SELECT zasp_red_team_resolve_target_v37($1,$2,$3,$4,$5)`, arguments[:5]...).Scan(&body); err == nil {
		t.Fatal("private legacy resolver remained executable")
	}
	for index, value := range []string{"pid_95ffffff-0000-4000-8000-000000000001", "pid_95ffffff-0000-4000-8000-000000000002", "pid_95ffffff-0000-4000-8000-000000000003", "pid_95ffffff-0000-4000-8000-000000000004", "coding_agent", "pid_95ffffff-0000-4000-8000-000000000005", strings.Repeat("b", 32), "tool_abuse"} {
		wrong := append([]any(nil), arguments...)
		wrong[index] = value
		if err := adapter.QueryRow(ctx, resolveSQL, wrong...).Scan(&body); err == nil {
			t.Fatalf("request authority mismatch accepted at index %d", index)
		}
	}
	for _, test := range []struct{ name, mutate, restore string }{
		{"cancelled", `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id=$1`, `UPDATE zasp_red_team_runs SET cancel_requested=false WHERE run_id=$1`},
		{"expired lease", `UPDATE zasp_red_team_runs SET lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE run_id=$1`, `UPDATE zasp_red_team_runs SET lease_expires_at=transaction_timestamp()+interval '1 hour' WHERE run_id=$1`},
		{"new owner", `UPDATE zasp_red_team_runs SET lease_token=convert_to(repeat('b',32),'UTF8') WHERE run_id=$1`, `UPDATE zasp_red_team_runs SET lease_token=convert_to(repeat('a',32),'UTF8') WHERE run_id=$1`},
		{"definition version", `UPDATE zasp_red_team_definitions SET version=2 WHERE definition_id=$2`, `UPDATE zasp_red_team_definitions SET version=1 WHERE definition_id=$2`},
		{"disabled", `UPDATE zasp_red_team_definitions SET enabled=false WHERE definition_id=$2`, `UPDATE zasp_red_team_definitions SET enabled=true WHERE definition_id=$2`},
		{"production", `UPDATE zasp_environments SET environment_class='production' WHERE id=$3`, `UPDATE zasp_environments SET environment_class='staging' WHERE id=$3`},
		{"revoked credential", `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE environment_id=$3`, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE environment_id=$3`},
		{"source no longer current", `UPDATE zasp_discovery_snapshots SET is_last_good=false WHERE id=$4`, `UPDATE zasp_discovery_snapshots SET is_last_good=true WHERE id=$4`},
	} {
		t.Run(test.name, func(t *testing.T) {
			for index, sql := range []string{test.mutate, test.restore} {
				if _, err := connection.Exec(ctx, `WITH scope AS(SELECT $1::text,$2::text,$3::text,$4::text) `+sql, invocationRun, invocationDefinition, scope.EnvironmentID().String(), invocationSnapshot); err != nil {
					t.Fatal(err)
				}
				if index == 0 {
					if err := adapter.QueryRow(ctx, resolveSQL, arguments...).Scan(&body); err == nil {
						t.Fatal("invalidated authority returned target binding")
					}
				}
			}
			resolve()
		})
	}
	if err := runner.DownProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_production_red_team_safety_live_fingerprint()`).Scan(&fingerprint); err != nil || fingerprint != migrations.ProductionRedTeamSafetySemanticFingerprint() {
		t.Fatalf("rollback fingerprint=%s err=%v", fingerprint, err)
	}
	if err := adapter.QueryRow(ctx, `SELECT zasp_red_team_resolve_target($1,$2,$3,$4,$5)`, arguments[:5]...).Scan(&body); err != nil {
		t.Fatal("rollback did not restore exact legacy API")
	}
	if err := runner.UpProductionRedTeamInvocation(ctx); err != nil {
		t.Fatal(err)
	}
	resolve()
	for _, drift := range []struct{ name, apply, restore string }{
		{"public invocation execute", `GRANT EXECUTE ON FUNCTION zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION zasp_red_team_resolve_invocation(text,text,text,text,text,text,text,text) FROM PUBLIC`},
		{"private resolver execute", `GRANT EXECUTE ON FUNCTION zasp_red_team_resolve_target_v37(text,text,text,text,text) TO zasp_red_team_adapter`, `REVOKE EXECUTE ON FUNCTION zasp_red_team_resolve_target_v37(text,text,text,text,text) FROM zasp_red_team_adapter`},
		{"future schema", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(39,'unknown',repeat('a',64))`, `DELETE FROM zasp_schema_versions WHERE version=39`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := connection.Exec(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := adapter.QueryRow(ctx, `SELECT zasp_red_team_invocation_readiness($1,$2)`, migrations.ProductionRedTeamInvocation().Checksum(), migrations.ProductionRedTeamInvocationSemanticFingerprint()).Scan(&ready); err == nil && ready {
				t.Fatal("drift passed readiness")
			}
			if _, err := connection.Exec(ctx, drift.restore); err != nil {
				t.Fatal(err)
			}
			if err := adapter.QueryRow(ctx, `SELECT zasp_red_team_invocation_readiness($1,$2)`, migrations.ProductionRedTeamInvocation().Checksum(), migrations.ProductionRedTeamInvocationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
				t.Fatalf("restored readiness=%t err=%v", ready, err)
			}
		})
	}
}

func TestRedTeamReclaimedTerminalRunClearsLease(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancelled", false: "exhausted"}[cancelled], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			connection, runner, _, worker := redTeamInvocationFixture(t, ctx)
			if err := runner.UpProductionRedTeamInvocation(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=$1,attempt=5,lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE run_id=$2`, cancelled, invocationRun); err != nil {
				t.Fatal(err)
			}
			scope := fixtureRequestIdentity(t).Scope
			var result json.RawMessage
			if err := worker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'invocation-reclaimer',$5,60)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), invocationRun, []byte(strings.Repeat("b", 32))).Scan(&result); err != nil || !bytes.Contains(result, []byte(`"ack_terminal"`)) {
				t.Fatalf("terminal reclaim=%s err=%v", result, err)
			}
			var state string
			var cleared bool
			if err := connection.QueryRow(ctx, `SELECT state,worker_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL FROM zasp_red_team_runs WHERE run_id=$1`, invocationRun).Scan(&state, &cleared); err != nil || !cleared || state != map[bool]string{true: "cancelled", false: "failed"}[cancelled] {
				t.Fatalf("terminal state=%s cleared=%t err=%v", state, cleared, err)
			}
		})
	}
}

func redTeamInvocationFixture(t *testing.T, ctx context.Context) (*pgx.Conn, *migrations.Runner, *pgx.Conn, *pgx.Conn) {
	t.Helper()
	connection, err := pgx.Connect(ctx, startDisposablePostgresAs(t, "zasp_e2e"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(context.Background()) })
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discovery.CreateIntegration(ctx, identity, IntegrationCreate{ID: invocationIntegration, Kind: "kubernetes", ConnectorVersion: "1.0.0", DisplayName: "Invocation provenance", Configuration: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := discovery.TransitionIntegration(ctx, scope, IntegrationTransition{ID: invocationIntegration, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	const syncID = "pid_95000007-0000-4000-8000-000000000007"
	observed := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'invocation-proof-sync',decode(repeat('ab',32),'hex'),'manual',$6,'parser_v1','tool_v1')`, org, workspace, environment, syncID, invocationIntegration, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'kubernetes','s3://zasp-evidence/invocation/manifest.json',decode(repeat('ab',32),'hex'),'complete',decode(repeat('ab',32),'hex'),'{}',true,true,$7,$7)`, org, workspace, environment, invocationSnapshot, invocationIntegration, syncID, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,version,product_kind,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,observed_at,fresh_until,projection_version,winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection,winning_attributes)
 VALUES($1,$2,$3,$4,'agent','Invocation target','{}','active',$5,$5,1,'agent',9500,$6,$7,1,$5,$5::timestamptz+interval '1 hour',1,$8,'kubernetes','kubernetes','invocation-agent',1,1,'{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/invocation_target_0001","target_kinds":["agent_endpoint"]}}')`, org, workspace, environment, invocationTarget, observed, invocationEvidence, invocationSnapshot, invocationIntegration); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/invocation/page.json',decode(repeat('ab',32),'hex'),'application/json','raw_v1','parser_v1',$8,'kubernetes',1,'pid_95000008-0000-4000-8000-000000000008','invocation/page.json','version-1',128,'tool_v1')`, org, workspace, environment, invocationEvidence, invocationIntegration, invocationSnapshot, invocationTarget, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,$4,'kubernetes',$5,'invocation-agent',$6,'present','{}',$7,$7,'kubernetes','kubernetes_agent','Invocation target','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),$8,9500,$7,$7::timestamptz+interval '1 hour',1,80,1)`, org, workspace, environment, invocationIntegration, invocationTarget, invocationSnapshot, observed, invocationEvidence); err != nil {
		t.Fatal(err)
	}
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook, runner.UpProductionRuntimeQueueReplay, runner.UpProductionRedTeamSafety} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Invocation tenant','invocation-proof.invalid') ON CONFLICT(id) DO NOTHING`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Invocation workspace') ON CONFLICT(organization_id,id) DO NOTHING`, workspace, org); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Invocation staging','staging') ON CONFLICT(organization_id,workspace_id,id) DO UPDATE SET environment_class='staging'`, org, workspace, environment); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,'pid_95000009-0000-4000-8000-000000000009',$4,'ref:red-team/invocation_target_0001','read_only',1,$5,transaction_timestamp()+interval '1 hour')`, org, workspace, environment, invocationTarget, bytes.Repeat([]byte{0xab}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Invocation proof',$5,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$6)`, org, workspace, environment, invocationDefinition, invocationTarget, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,worker_id,lease_token,lease_expires_at,input_digest) VALUES($1,$2,$3,$4,$5,1,$6,'leased',1,'invocation-worker',convert_to(repeat('a',32),'UTF8'),transaction_timestamp()+interval '1 hour',decode(repeat('ab',32),'hex'))`, org, workspace, environment, invocationRun, invocationDefinition, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE invocation_worker LOGIN INHERIT; CREATE ROLE invocation_outbox LOGIN INHERIT; CREATE ROLE invocation_adapter LOGIN INHERIT; SELECT zasp_red_team_register_principals('zasp_e2e','invocation_worker','invocation_outbox','invocation_adapter')`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"invocation_discovery_api", "invocation_discovery_worker", "invocation_ingest", "invocation_runtime", "invocation_discovery_outbox", "invocation_gateway"} {
		if _, err := connection.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_register_principals(session_user,'invocation_discovery_api','invocation_discovery_worker','invocation_ingest','invocation_runtime','invocation_discovery_outbox','invocation_gateway')`); err != nil {
		t.Fatal(err)
	}
	connect := func(name string) *pgx.Conn {
		config := connection.Config().Copy()
		config.User = name
		value, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { value.Close(context.Background()) })
		return value
	}
	return connection, runner, connect("invocation_adapter"), connect("invocation_worker")
}
