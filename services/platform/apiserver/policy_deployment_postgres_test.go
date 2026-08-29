package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestProductionPolicyDeploymentPostgresInstallsExactSingleWriterAuthority(t *testing.T) {
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
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	metadata := migrations.ProductionPolicyDeployment()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v28 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES($1,$2,$3)`, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_policy_deployment_execution_live_fingerprint()`).Scan(&fingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionPolicyDeploymentSemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v28 candidate fingerprint=%s", fingerprint)
	}
	var candidateReady bool
	if err := probe.QueryRow(ctx, `SELECT zasp_policy_deployment_execution_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&candidateReady); err != nil || !candidateReady {
		_ = probe.Rollback(ctx)
		t.Fatalf("v28 candidate readiness=%t err=%v", candidateReady, err)
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionPolicyDeployment(ctx); err != nil {
		t.Fatalf("v28 up: %v", err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_policy_deployment_execution_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v28 readiness=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v28 did not preserve exact v27 public readiness=%t err=%v", ready, err)
	}
	assertProductionPolicyDeploymentLifecycle(t, ctx, dsn, connection)
}

func assertProductionPolicyDeploymentLifecycle(t *testing.T, ctx context.Context, dsn string, connection *pgx.Conn) {
	t.Helper()
	const (
		organizationID  = "pid_71000001-0000-4000-8000-000000000001"
		workspaceID     = "pid_71000002-0000-4000-8000-000000000002"
		environmentID   = "pid_71000003-0000-4000-8000-000000000003"
		deviceID        = "pid_71000004-0000-4000-8000-000000000004"
		enrollmentID    = "pid_71000005-0000-4000-8000-000000000005"
		credentialID    = "pid_71000006-0000-4000-8000-000000000006"
		workerPrincipal = "policy_deployment_v28_login"
	)
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_principal_bindings(principal_name,authority_role) VALUES(session_user,'zasp_discovery_authority') ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `CREATE ROLE policy_deployment_v28_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_policy_deployment_register_principal(session_user,$1)`, workerPrincipal).Scan(&registered); err != nil || !registered {
		t.Fatalf("register=%t err=%v", registered, err)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Policy tenant','policy.invalid')`, []any{organizationID}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Production')`, []any{workspaceID, organizationID}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, []any{environmentID, organizationID, workspaceID}},
		{`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Policy gateway','active')`, []any{organizationID, workspaceID, environmentID, deviceID}},
		{`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',decode(repeat('11',16),'hex'),decode(repeat('12',32),'hex'),transaction_timestamp()+interval '1 hour')`, []any{organizationID, workspaceID, environmentID, enrollmentID, deviceID}},
		{`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('13',32),'hex'),'runtime-gateway','ref:gateway/public/policy-key',decode(repeat('14',32),'hex'),transaction_timestamp()+interval '1 day',1,1,'policy-gateway-key','Ed25519',transaction_timestamp())`, []any{organizationID, workspaceID, environmentID, credentialID, deviceID, enrollmentID}},
		{`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy','policy-v28',$4::jsonb)`, []any{organizationID, workspaceID, environmentID, `{"id":"policy-v28","name":"Block writes","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"block","rollout":"monitor","failure_mode":"closed"}`}},
	} {
		if _, err := connection.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", statement.sql, err)
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = workerPrincipal
	workerConnection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer workerConnection.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: workerConnection})
	if err != nil {
		t.Fatal(err)
	}
	var readinessPayload []byte
	if err := workerConnection.QueryRow(ctx, postgresPolicyDeploymentReadySQL, migrations.ProductionPolicyDeployment().Checksum(), migrations.ProductionPolicyDeploymentSemanticFingerprint()).Scan(&readinessPayload); err != nil {
		t.Fatalf("worker readiness query: %v", err)
	}
	var liveFingerprint string
	var securityReady bool
	var storedChecksum, marker string
	if err := connection.QueryRow(ctx, `SELECT zasp_policy_deployment_execution_live_fingerprint(),zasp_policy_deployment_execution_security_ready()`).Scan(&liveFingerprint, &securityReady); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT (SELECT checksum FROM zasp_schema_versions WHERE version=28),(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema')`).Scan(&storedChecksum, &marker); err != nil {
		t.Fatal(err)
	}
	var migrationReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_policy_deployment_execution_readiness($1,$2)`, migrations.ProductionPolicyDeployment().Checksum(), migrations.ProductionPolicyDeploymentSemanticFingerprint()).Scan(&migrationReady); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPolicyDeploymentRepository(database)
	if err != nil {
		t.Fatalf("%v payload=%s live=%s pinned=%s security=%t migration_ready=%t stored=%s expected=%s marker=%s", err, readinessPayload, liveFingerprint, migrations.ProductionPolicyDeploymentSemanticFingerprint(), securityReady, migrationReady, storedChecksum, migrations.ProductionPolicyDeployment().Checksum(), marker)
	}
	claims, err := repository.ClaimPolicyDeployments(ctx, "policy-deployment-v28", "lease-token-policy-v28-0001", 60, 8)
	if err != nil || len(claims) != 1 || len(claims[0].PersistentPolicies) != 1 || len(claims[0].TemporaryPolicies) != 0 {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal(err)
	}
	deploy := func(claim PolicyDeploymentClaim) string {
		t.Helper()
		compiled := make([]policy.CompiledPolicy, 0, len(claim.PersistentPolicies))
		failureMode := "open"
		for _, source := range claim.PersistentPolicies {
			value, active, err := policy.CompileGatewayPolicy(source)
			if err != nil {
				t.Fatal(err)
			}
			if active {
				compiled = append(compiled, value)
			}
			if source.FailureMode == "closed" {
				failureMode = "closed"
			}
		}
		now := time.Now().UTC().Truncate(time.Second)
		envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "gateway-key-v28", Binding: policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), FailureMode: failureMode, Policies: compiled}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := repository.StorePolicyDeployment(ctx, claim, "policy-deployment-v28", "lease-token-policy-v28-0001", envelope)
		if err != nil {
			t.Fatal(err)
		}
		readback, err := repository.ReadPolicyDeployment(ctx, claim)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{envelope.KeyID: publicKey})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := policy.VerifyGatewayPolicyEnvelope(readback, keys, policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, now); err != nil {
			t.Fatalf("stored policy envelope signature did not survive PostgreSQL readback: %v", err)
		}
		if err := repository.FinishPolicyDeployment(ctx, claim, "policy-deployment-v28", "lease-token-policy-v28-0001", digest); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	firstDigest := deploy(claims[0])
	if _, err := connection.Exec(ctx, `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{rollout}','"disabled"'::jsonb),version=version+1,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'policy','policy-v28')`, organizationID, workspaceID, environmentID); err != nil {
		t.Fatal(err)
	}
	claims, err = repository.ClaimPolicyDeployments(ctx, "policy-deployment-v28", "lease-token-policy-v28-0001", 60, 8)
	if err != nil || len(claims) != 1 || len(claims[0].PersistentPolicies) != 0 || claims[0].Sequence != 2 {
		t.Fatalf("disable claims=%+v err=%v", claims, err)
	}
	secondDigest := deploy(claims[0])
	if firstDigest == secondDigest {
		t.Fatal("monotonic bundles reused one digest")
	}
	var bundles int
	var latestPolicies int
	if err := connection.QueryRow(ctx, `SELECT count(*),(SELECT jsonb_array_length(policies) FROM zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=($1,$2,$3,$4) ORDER BY sequence DESC LIMIT 1) FROM zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=($1,$2,$3,$4)`, organizationID, workspaceID, environmentID, deviceID).Scan(&bundles, &latestPolicies); err != nil || bundles != 2 || latestPolicies != 0 {
		t.Fatalf("bundles=%d latest_policies=%d err=%v", bundles, latestPolicies, err)
	}
}
