package apiserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestConnectorAuthorizationPostgresRiskMutationSurvivesV10UpgradeAndRollback(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)

	runner := migrateToProductionDiscovery(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	seedConnectorRiskFinding(t, ctx, connection, identity, riskFindingID)
	if err := runner.UpConnectorAuthorization(ctx); err != nil {
		t.Fatalf("v10 to v11 migration: %v", err)
	}
	repository := connectorRiskRepository(t, connection)
	first := RiskFindingMutation{
		Operation: "updateFinding", FindingID: riskFindingID,
		IdempotencyKey: "idem-v11-risk-update-0001", ExpectedVersion: 1, Status: "under_review",
		AuditID: "pid_72000001-0000-4000-8000-000000000001", CorrelationID: "pid_72000002-0000-4000-8000-000000000002", ReceiptID: "pid_72000003-0000-4000-8000-000000000003",
	}
	result, err := repository.MutateRiskFinding(ctx, identity, first)
	if err != nil || result.Version != 2 || result.Body.Status != "under_review" || result.Replayed || result.ReceiptID != first.ReceiptID {
		t.Fatalf("v11 risk mutation = %#v, %v", result, err)
	}
	replay, err := repository.MutateRiskFinding(ctx, identity, first)
	if err != nil || !replay.Replayed || replay.Version != result.Version || replay.AuditID != result.AuditID || replay.ReceiptID != result.ReceiptID {
		t.Fatalf("v11 risk replay = %#v, %v; first=%#v", replay, err, result)
	}
	pat := identity
	pat.CredentialKind = CredentialBearerToken
	second := RiskFindingMutation{
		Operation: "acceptFindingRisk", FindingID: riskFindingID,
		IdempotencyKey: "idem-v11-risk-accept-0001", ExpectedVersion: 2, Status: "accepted", Reason: "Approved before rollback",
		AuditID: "pid_72000004-0000-4000-8000-000000000004", CorrelationID: "pid_72000005-0000-4000-8000-000000000005",
	}
	result, err = repository.MutateRiskFinding(ctx, pat, second)
	if err != nil || result.Version != 3 || result.Body.Status != "accepted" || result.Body.AcceptanceReason != second.Reason || result.ReceiptID != "" {
		t.Fatalf("v11 PAT risk mutation = %#v, %v", result, err)
	}

	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_connector_audit ADD COLUMN hostile_drift text`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownConnectorAuthorization(ctx); err == nil {
		t.Fatal("v11 semantic drift did not block down")
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 11 {
		t.Fatalf("failed down was not atomic: version=%d err=%v", version, versionErr)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_connector_audit DROP COLUMN hostile_drift`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownConnectorAuthorization(ctx); err != nil {
		t.Fatalf("v11 to v10 down: %v", err)
	}
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 10 {
		t.Fatalf("down version=%d err=%v", version, versionErr)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_readiness($1,$2)`, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		fingerprintQuery := postgresSchemaVersionSQL[:strings.Index(postgresSchemaVersionSQL, "SELECT metadata.value")] + "SELECT value FROM semantic_fingerprint"
		var liveFingerprint, schemaFingerprint, releaseFingerprint, marker, checksum string
		var securityReady bool
		_ = connection.QueryRow(ctx, fingerprintQuery).Scan(&liveFingerprint)
		_ = connection.QueryRow(ctx, `SELECT (SELECT value FROM zasp_schema_metadata WHERE key='production_discovery_fingerprint'),(SELECT value FROM zasp_schema_metadata WHERE key='production_discovery_release_fingerprint'),(SELECT value FROM zasp_schema_metadata WHERE key='production_core_schema'),(SELECT checksum FROM zasp_schema_versions WHERE version=10),zasp_discovery_security_ready()`).Scan(&schemaFingerprint, &releaseFingerprint, &marker, &checksum, &securityReady)
		t.Fatalf("v10 readiness after v11 down = %v, %v; live=%q schema=%q release=%q marker=%q checksum=%q security=%v", ready, err, liveFingerprint, schemaFingerprint, releaseFingerprint, marker, checksum, securityReady)
	}
	repository = connectorRiskRepository(t, connection)
	third := RiskFindingMutation{
		Operation: "updateFinding", FindingID: riskFindingID,
		IdempotencyKey: "idem-v10-risk-update-0001", ExpectedVersion: 3, Status: "resolved",
		AuditID: "pid_72000006-0000-4000-8000-000000000006", CorrelationID: "pid_72000007-0000-4000-8000-000000000007", ReceiptID: "pid_72000008-0000-4000-8000-000000000008",
	}
	result, err = repository.MutateRiskFinding(ctx, identity, third)
	if err != nil || result.Version != 4 || result.Body.Status != "resolved" || result.Body.AcceptanceReason != "" || result.ReceiptID != third.ReceiptID {
		t.Fatalf("v10 risk mutation after v11 down = %#v, %v", result, err)
	}
	var audits, receipts int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE resource_id=$1),(SELECT count(*) FROM zasp_workflow_receipts WHERE resource_id=$1)`, riskFindingID).Scan(&audits, &receipts); err != nil || audits != 3 || receipts != 2 {
		t.Fatalf("risk receipt/PAT semantics after upgrade/down = audits:%d receipts:%d err:%v", audits, receipts, err)
	}
	if err := runner.UpConnectorAuthorization(ctx); err != nil {
		t.Fatalf("v10 compatibility cycle re-upgrade: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_readiness($1,$2)`, migrations.ConnectorAuthorization().Checksum(), migrations.ConnectorAuthorizationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v11 readiness after compatibility re-upgrade = %v, %v", ready, err)
	}
	repository = connectorRiskRepository(t, connection)
	fourth := RiskFindingMutation{
		Operation: "updateFinding", FindingID: riskFindingID,
		IdempotencyKey: "idem-v11-risk-reupgrade-0001", ExpectedVersion: 4, Status: "open",
		AuditID: "pid_72000009-0000-4000-8000-000000000009", CorrelationID: "pid_7200000a-0000-4000-8000-00000000000a", ReceiptID: "pid_7200000b-0000-4000-8000-00000000000b",
	}
	result, err = repository.MutateRiskFinding(ctx, identity, fourth)
	if err != nil || result.Version != 5 || result.Body.Status != "open" || result.ReceiptID != fourth.ReceiptID {
		t.Fatalf("v11 risk mutation after compatibility re-upgrade = %#v, %v", result, err)
	}
}

func TestConnectorAuthorizationPostgresRiskMutationWorksAfterFreshV1ToV11Chain(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)

	migrateToConnectorAuthorization(t, ctx, connection)
	identity := fixtureRequestIdentity(t)
	findingID := "pid_72000010-0000-4000-8000-000000000010"
	seedConnectorRiskFinding(t, ctx, connection, identity, findingID)
	repository := connectorRiskRepository(t, connection)
	mutation := RiskFindingMutation{
		Operation: "updateFinding", FindingID: findingID,
		IdempotencyKey: "idem-fresh-v11-risk-0001", ExpectedVersion: 1, Status: "resolved",
		AuditID: "pid_72000011-0000-4000-8000-000000000011", CorrelationID: "pid_72000012-0000-4000-8000-000000000012", ReceiptID: "pid_72000013-0000-4000-8000-000000000013",
	}
	result, err := repository.MutateRiskFinding(ctx, identity, mutation)
	if err != nil || result.Version != 2 || result.Body.Status != "resolved" || result.ReceiptID != mutation.ReceiptID {
		t.Fatalf("fresh v1 to v11 risk mutation = %#v, %v", result, err)
	}
}

func seedConnectorRiskFinding(t *testing.T, ctx context.Context, connection *pgx.Conn, identity RequestIdentity, findingID string) {
	t.Helper()
	organization, workspace, environment := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	evidenceID := "pid_72000020-0000-4000-8000-000000000020"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$4,'posture','Connector release risk finding','high','open')`, organization, workspace, environment, findingID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,$5)`, organization, workspace, environment, findingID, evidenceID); err != nil {
		t.Fatal(err)
	}
}

func connectorRiskRepository(t *testing.T, connection *pgx.Conn) *PostgresRepository {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	return repository
}
