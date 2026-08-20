package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestProductionRuntimeDataPlanePostgresKeepsInheritedProductAuthorityReady(t *testing.T) {
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
		t.Fatalf("v15 migration: %v", err)
	}

	metadata := migrations.ProductionRuntimeDataPlane()
	for _, role := range []string{
		"zasp_discovery_api",
		"zasp_discovery_worker",
		"zasp_runtime_ingest",
		"zasp_runtime_worker",
		"zasp_outbox_worker",
		"zasp_runtime_gateway",
		"zasp_discovery_scheduler",
		"zasp_projection_risk_worker",
		"zasp_projection_graph_worker",
		"zasp_projection_search_worker",
	} {
		t.Run(role, func(t *testing.T) {
			transaction, err := connection.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer transaction.Rollback(context.Background())
			if _, err := transaction.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatalf("set role: %v", err)
			}
			var ready bool
			if err := transaction.QueryRow(ctx, `SELECT zasp_runtime_data_plane_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()).Scan(&ready); err != nil || !ready {
				t.Fatalf("v15 readiness=%t err=%v", ready, err)
			}
		})
	}

	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if version, err := database.SchemaVersion(ctx); err != nil || version != RuntimeDataPlaneSchemaVersion {
		t.Fatalf("schema version=(%q,%v)", version, err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatalf("product repository: %v", err)
	}
	if _, err := NewPostgresInventoryRepository(database); err != nil {
		t.Fatalf("inventory repository: %v", err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	policy := json.RawMessage(`{"id":"policy-v15-compatibility","name":"V15 compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	workflow, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{
		Action: "create", Kind: "policy", ID: "policy-v15-compatibility", Operation: "createPolicy", IdempotencyKey: "runtime-v15-workflow-0001",
		Intent: json.RawMessage(`{"body":` + string(policy) + `,"expected_version":0,"resource_id":""}`), Body: policy,
		AuditID: "pid_97000001-0000-4000-8000-000000000001", CorrelationID: "pid_97000002-0000-4000-8000-000000000002",
	})
	if err != nil || workflow.Version != 1 || workflow.Replayed {
		t.Fatalf("v15 workflow mutation=%#v err=%v", workflow, err)
	}
	findingID := "pid_97000003-0000-4000-8000-000000000003"
	seedConnectorRiskFinding(t, ctx, connection, identity, findingID)
	risk, err := repository.MutateRiskFinding(ctx, identity, RiskFindingMutation{
		Operation: "updateFinding", FindingID: findingID, IdempotencyKey: "runtime-v15-risk-0001", ExpectedVersion: 1, Status: "resolved",
		AuditID: "pid_97000004-0000-4000-8000-000000000004", CorrelationID: "pid_97000005-0000-4000-8000-000000000005",
	})
	if err != nil || risk.Version != 2 || risk.Body.Status != "resolved" {
		t.Fatalf("v15 risk mutation=%#v err=%v", risk, err)
	}

	if _, err := connection.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_inventory_page(text,text,text,text,text,integer) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_data_plane_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()).Scan(&ready); err != nil || ready {
		t.Fatalf("v15 inherited-authority drift readiness=%t err=%v", ready, err)
	}
}

func TestProductionRuntimeDataPlanePostgresSensorPublicAuthority(t *testing.T) {
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
		t.Fatalf("v15 migration: %v", err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSensorPublicRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	sensorID := "pid_96000001-0000-4000-8000-000000000001"
	tokenID := "pid_96000002-0000-4000-8000-000000000002"
	tokenProductID, _ := domain.ParseProductID(tokenID)
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	locator, secret, err := credential.Parts()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(locator)
	defer clear(secret)
	locatorDigest, _ := credential.LocatorDigest()
	salt := bytes.Repeat([]byte{0x33}, 32)
	tokenHash, _ := credential.Hash(sensor.SensorTokenAudienceEventIngest, tokenProductID, 1, salt)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Microsecond)
	createDigest := sha256.Sum256([]byte("sensor-public-create"))
	create := SensorCreateMutation{SensorID: sensorID, Name: "Production runtime", Kind: "tetragon", Mode: "metadata_only", IdempotencyKey: "sensor-public-create-0001", RequestDigest: createDigest[:], TokenID: tokenID, TokenGeneration: 1, LocatorDigest: locatorDigest[:], Salt: salt, TokenHash: tokenHash[:], TokenExpiresAt: expires}
	created, err := repository.CreateSensor(ctx, identity, create)
	if err != nil || created.Sensor.ID != sensorID || created.Sensor.Version != 1 || created.TokenID != tokenID || created.Replayed {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	replayCreate := create
	replayCreate.SensorID = "pid_96000009-0000-4000-8000-000000000009"
	replayCreate.TokenID = "pid_96000010-0000-4000-8000-000000000010"
	replayed, err := repository.CreateSensor(ctx, identity, replayCreate)
	if err != nil || !replayed.Replayed || replayed.Sensor.ID != sensorID || replayed.TokenID != tokenID {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	wire, _ := credential.Wire()
	var leaked bool
	if err := connection.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_runtime_sensor_mutations WHERE result::text LIKE '%'||$1||'%')`, wire).Scan(&leaked); err != nil || leaked {
		t.Fatalf("wire token persisted=%t err=%v", leaked, err)
	}
	if _, err := repository.ListSensors(ctx, identity.Scope, "", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_sensor_heartbeat($1,$2,'event-ingest',1,'healthy','["network","process"]'::jsonb,'6.8.0',true,12,0)`, locator, secret); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	coverage, err := repository.GetSensorCoverage(ctx, identity.Scope, sensorID)
	if err != nil || coverage.Status != "healthy" || coverage.Kernel != "6.8.0" || len(coverage.Capabilities) != 2 {
		t.Fatalf("coverage=%#v err=%v", coverage, err)
	}
	updateDigest := sha256.Sum256([]byte("sensor-public-update"))
	updated, err := repository.UpdateSensor(ctx, identity, SensorUpdateMutation{SensorID: sensorID, Name: "Production runtime renamed", Mode: "full", ExpectedVersion: 1, IdempotencyKey: "sensor-public-update-0001", RequestDigest: updateDigest[:]})
	if err != nil || updated.Sensor.Version != 2 || updated.Sensor.Mode != "full" || updated.Sensor.TokenExpiresAt == nil {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	replacementID := "pid_96000003-0000-4000-8000-000000000003"
	replacementProductID, _ := domain.ParseProductID(replacementID)
	replacement, _ := sensor.NewTokenCredential(bytes.Repeat([]byte{0x44}, 16), bytes.Repeat([]byte{0x55}, 32))
	defer replacement.Destroy()
	replacementDigest, _ := replacement.LocatorDigest()
	replacementHash, _ := replacement.Hash(sensor.SensorTokenAudienceEventIngest, replacementProductID, 2, salt)
	rotateDigest := sha256.Sum256([]byte("sensor-public-rotate"))
	rotated, err := repository.RotateSensorToken(ctx, identity, SensorRotateMutation{SensorID: sensorID, ExpectedVersion: 2, IdempotencyKey: "sensor-public-rotate-0001", RequestDigest: rotateDigest[:], TokenID: replacementID, TokenGeneration: 2, LocatorDigest: replacementDigest[:], Salt: salt, TokenHash: replacementHash[:], TokenExpiresAt: expires})
	if err != nil || rotated.Replayed || rotated.TokenGeneration != 2 {
		t.Fatalf("rotated=%#v err=%v", rotated, err)
	}
	authority, err := repository.GetSensorTokenAuthority(ctx, identity.Scope, sensorID)
	if err != nil || authority.Generation != 2 || authority.SensorVersion != 2 {
		t.Fatalf("authority=%#v err=%v", authority, err)
	}
	replayedRotation, err := repository.RotateSensorToken(ctx, identity, SensorRotateMutation{SensorID: sensorID, ExpectedVersion: 2, IdempotencyKey: "sensor-public-rotate-0001", RequestDigest: rotateDigest[:], TokenID: "pid_96000011-0000-4000-8000-000000000011", TokenGeneration: 3, LocatorDigest: replacementDigest[:], Salt: salt, TokenHash: replacementHash[:], TokenExpiresAt: expires})
	if err != nil || !replayedRotation.Replayed || replayedRotation.TokenID != replacementID || replayedRotation.TokenGeneration != 2 {
		t.Fatalf("replayed rotation=%#v err=%v", replayedRotation, err)
	}
	deleteDigest := sha256.Sum256([]byte("sensor-public-delete"))
	deleted, err := repository.DeleteSensor(ctx, identity, SensorDeleteMutation{SensorID: sensorID, ExpectedVersion: 2, IdempotencyKey: "sensor-public-delete-0001", RequestDigest: deleteDigest[:]})
	if err != nil || deleted.Sensor.State != "deleted" || deleted.Sensor.TokenExpiresAt != nil || deleted.Sensor.Version != 3 {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	page, err := repository.ListSensors(ctx, identity.Scope, "", 100)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
}

func TestProductionRuntimeDataPlanePostgresAuthenticatesTokenDerivedHeartbeat(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)

	scope := fixtureRequestIdentity(t).Scope
	sensorID := "pid_76000001-0000-4000-8000-000000000001"
	legacyTokenID := "pid_76000002-0000-4000-8000-000000000002"
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'runtime-sensor','tetragon')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_issue_sensor_token($1,$2,$3,$4,$5,$6,$7,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, legacyTokenID, bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)); err != nil {
		t.Fatal(err)
	}

	metadata := migrations.ProductionRuntimeDataPlane()
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		_, detail := connection.Exec(ctx, metadata.UpSQL())
		var liveFingerprint string
		var securityReady bool
		_ = connection.QueryRow(ctx, `SELECT zasp_runtime_data_plane_live_fingerprint(),zasp_runtime_data_plane_security_ready()`).Scan(&liveFingerprint, &securityReady)
		t.Fatalf("v15 migration: %v (%v) live=%q expected=%q security=%t", err, detail, liveFingerprint, migrations.ProductionRuntimeDataPlaneSemanticFingerprint(), securityReady)
	}
	var live string
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_data_plane_live_fingerprint()`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != migrations.ProductionRuntimeDataPlaneSemanticFingerprint() {
		t.Fatalf("v15 live fingerprint=%s marker=%s", live, migrations.ProductionRuntimeDataPlaneSemanticFingerprint())
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_data_plane_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v15 readiness=%t err=%v", ready, err)
	}

	var legacyRevoked time.Time
	if err := connection.QueryRow(ctx, `SELECT revoked_at FROM zasp_sensor_tokens WHERE id=$1`, legacyTokenID).Scan(&legacyRevoked); err != nil || legacyRevoked.IsZero() {
		t.Fatalf("legacy token revoked=%v err=%v", legacyRevoked, err)
	}

	locator := bytes.Repeat([]byte{0x31}, 16)
	secret := bytes.Repeat([]byte{0x41}, 32)
	salt := bytes.Repeat([]byte{0x51}, 32)
	credential, err := sensor.NewTokenCredential(locator, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	tokenID := "pid_76000003-0000-4000-8000-000000000003"
	locatorDigest, err := credential.LocatorDigest()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, tokenID), 1, salt)
	if err != nil {
		t.Fatal(err)
	}
	var issued json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, tokenID, locatorDigest[:], salt, tokenHash[:]).Scan(&issued); err != nil {
		t.Fatalf("issue v15 token: %v", err)
	}
	if bytes.Contains(issued, locator) || bytes.Contains(issued, secret) || bytes.Contains(issued, tokenHash[:]) {
		t.Fatalf("issued result leaked credential material: %s", issued)
	}

	wrongSecret := bytes.Repeat([]byte{0x42}, 32)
	_, wrongSecretErr := connection.Exec(ctx, `SELECT zasp_runtime_authenticate_sensor($1,$2,'event-ingest')`, locator, wrongSecret)
	if wrongSecretErr == nil {
		t.Fatal("wrong secret authenticated")
	}
	_, missingLocatorErr := connection.Exec(ctx, `SELECT zasp_runtime_authenticate_sensor($1,$2,'event-ingest')`, bytes.Repeat([]byte{0x32}, 16), secret)
	if missingLocatorErr == nil || pgErrorSignature(t, missingLocatorErr) != pgErrorSignature(t, wrongSecretErr) {
		t.Fatalf("token oracle wrong=%q missing=%q", pgErrorSignature(t, wrongSecretErr), pgErrorSignature(t, missingLocatorErr))
	}
	var heartbeat json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_sensor_heartbeat($1,$2,'event-ingest',7,'healthy',$3::jsonb,'6.8.1',true,19,2)`, locator, secret, json.RawMessage(`["network","process"]`)).Scan(&heartbeat); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !bytes.Contains(heartbeat, []byte(`"sequence": 7`)) && !bytes.Contains(heartbeat, []byte(`"sequence":7`)) {
		t.Fatalf("heartbeat result=%s", heartbeat)
	}
	var organizationID, observedSensorID, status string
	var sequence int64
	if err := connection.QueryRow(ctx, `SELECT organization_id,sensor_id,sequence,status FROM zasp_sensor_heartbeats WHERE sensor_id=$1`, sensorID).Scan(&organizationID, &observedSensorID, &sequence, &status); err != nil || organizationID != scope.OrganizationID().String() || observedSensorID != sensorID || sequence != 7 || status != "healthy" {
		t.Fatalf("derived heartbeat=%s/%s/%d/%s err=%v", organizationID, observedSensorID, sequence, status, err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_sensor_heartbeat($1,$2,'wrong-audience',8,'healthy',$3::jsonb,'6.8.1',true,19,2)`, locator, secret, json.RawMessage(`["network","process"]`)); err == nil {
		t.Fatal("wrong audience heartbeat succeeded")
	}

	contentDigest := sha256.Sum256([]byte("runtime-batch-v15"))
	var reservation struct {
		BatchID       string `json:"batch_id"`
		Generation    int64  `json:"generation"`
		ArtifactKey   string `json:"artifact_key"`
		RequestDigest string `json:"request_digest"`
		State         string `json:"state"`
		Replayed      bool   `json:"replayed"`
	}
	reserveSQL := `SELECT zasp_runtime_reserve_batch($1,$2,'event-ingest',$3,$4,$5,'tetragon','application/json','runtime-event-v1',128,2)`
	batchID := "pid_76000005-0000-4000-8000-000000000005"
	if err := connection.QueryRow(ctx, reserveSQL, locator, secret, batchID, "runtime-batch-key-0001", contentDigest[:]).Scan(&reservation); err != nil || reservation.BatchID != batchID || reservation.Generation != 1 || reservation.State != "uploading" || reservation.Replayed || reservation.ArtifactKey == "" || len(reservation.RequestDigest) != 64 {
		t.Fatalf("reservation=%#v err=%v", reservation, err)
	}
	if err := connection.QueryRow(ctx, reserveSQL, locator, secret, batchID, "runtime-batch-key-0001", contentDigest[:]).Scan(&reservation); err != nil || !reservation.Replayed {
		t.Fatalf("reservation replay=%#v err=%v", reservation, err)
	}
	jobID := "pid_76000006-0000-4000-8000-000000000006"
	outboxID := "pid_76000007-0000-4000-8000-000000000007"
	artifactReference := "s3://zasp-runtime/" + reservation.ArtifactKey
	artifactVersion := "version-v15-0001"
	kmsKey := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	finalizeSQL := `SELECT zasp_runtime_finalize_batch($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9,128,$10)`
	if _, err := connection.Exec(ctx, finalizeSQL, locator, secret, batchID, jobID, outboxID, artifactReference, reservation.ArtifactKey, artifactVersion, bytes.Repeat([]byte{0x91}, 32), kmsKey); err == nil {
		t.Fatal("mismatched artifact checksum finalized")
	}
	var finalized struct {
		BatchID    string `json:"batch_id"`
		Generation int64  `json:"generation"`
		State      string `json:"state"`
		Replayed   bool   `json:"replayed"`
	}
	if err := connection.QueryRow(ctx, finalizeSQL, locator, secret, batchID, jobID, outboxID, artifactReference, reservation.ArtifactKey, artifactVersion, contentDigest[:], kmsKey).Scan(&finalized); err != nil || finalized.BatchID != batchID || finalized.Generation != 1 || finalized.State != "queued" || finalized.Replayed {
		t.Fatalf("finalized=%#v err=%v", finalized, err)
	}
	if err := connection.QueryRow(ctx, finalizeSQL, locator, secret, batchID, jobID, outboxID, artifactReference, reservation.ArtifactKey, artifactVersion, contentDigest[:], kmsKey).Scan(&finalized); err != nil || !finalized.Replayed {
		t.Fatalf("finalize replay=%#v err=%v", finalized, err)
	}
	var stageCount, legacyBatchCount int
	var outboxPayload []byte
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_stage_work WHERE batch_id=$1),(SELECT count(*) FROM zasp_runtime_batches WHERE id=$1),(SELECT payload::text::bytea FROM zasp_discovery_outbox WHERE id=$2)`, batchID, outboxID).Scan(&stageCount, &legacyBatchCount, &outboxPayload); err != nil || stageCount != 5 || legacyBatchCount != 1 || bytes.Contains(outboxPayload, locator) || bytes.Contains(outboxPayload, secret) {
		t.Fatalf("finalized authority stages=%d legacy=%d payload=%s err=%v", stageCount, legacyBatchCount, outboxPayload, err)
	}

	var migrationPrincipal string
	if err := connection.QueryRow(ctx, `SELECT session_user`).Scan(&migrationPrincipal); err != nil {
		t.Fatal(err)
	}
	legacyPrincipalNames := []string{"runtime_api_login", "runtime_discovery_login", "runtime_ingest_login", "runtime_worker_login", "runtime_outbox_login", "runtime_legacy_gateway_login"}
	for _, principal := range legacyPrincipalNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	var legacyRegistered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, migrationPrincipal, legacyPrincipalNames[0], legacyPrincipalNames[1], legacyPrincipalNames[2], legacyPrincipalNames[3], legacyPrincipalNames[4], legacyPrincipalNames[5]).Scan(&legacyRegistered); err != nil || !legacyRegistered {
		t.Fatalf("register legacy runtime principals=%t err=%v", legacyRegistered, err)
	}
	principalNames := []string{"runtime_coordinator_login", "runtime_archive_login", "runtime_index_login", "runtime_correlation_login", "runtime_projection_login", "runtime_gateway_login"}
	for _, principal := range principalNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	var registered bool
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_register_principals($1,$2,$3,$4,$5,$6,$7)`, migrationPrincipal, principalNames[0], principalNames[1], principalNames[2], principalNames[3], principalNames[4], principalNames[5]).Scan(&registered); err != nil || !registered {
		t.Fatalf("register runtime principals=%t err=%v", registered, err)
	}
	archiveConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, principalNames[1])
	defer archiveConnection.Close(context.Background())
	indexConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, principalNames[2])
	defer indexConnection.Close(context.Background())
	coordinatorConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, principalNames[0])
	defer coordinatorConnection.Close(context.Background())
	correlationConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, principalNames[3])
	defer correlationConnection.Close(context.Background())
	projectionConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, principalNames[4])
	defer projectionConnection.Close(context.Background())
	outboxConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, legacyPrincipalNames[4])
	defer outboxConnection.Close(context.Background())
	outboxDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: outboxConnection})
	if err != nil {
		t.Fatal(err)
	}
	if repository, err := NewRuntimeOutboxRepository(outboxDatabase); err != nil || repository.Ready(ctx) != nil {
		t.Fatalf("runtime outbox repository=%v err=%v", repository, err)
	}
	var ingestPrincipal string
	if err := connection.QueryRow(ctx, `SELECT principal_name::text FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_runtime_ingest'`).Scan(&ingestPrincipal); err != nil {
		t.Fatal(err)
	}
	ingestConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, ingestPrincipal)
	defer ingestConnection.Close(context.Background())
	var messageDigest []byte
	if err := connection.QueryRow(ctx, `SELECT payload_digest FROM zasp_discovery_outbox WHERE id=$1`, outboxID).Scan(&messageDigest); err != nil {
		t.Fatal(err)
	}
	var outboxClaim json.RawMessage
	if err := outboxConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox('runtime-events','runtime-outbox-worker','runtime-outbox-lease-0001',30,1)`).Scan(&outboxClaim); err != nil || !bytes.Contains(outboxClaim, []byte(outboxID)) || bytes.Contains(outboxClaim, locator) || bytes.Contains(outboxClaim, secret) {
		t.Fatalf("runtime outbox claim=%s err=%v", outboxClaim, err)
	}
	if _, err := outboxConnection.Exec(ctx, `SELECT zasp_runtime_heartbeat_outbox('runtime-events','runtime-outbox-worker','runtime-outbox-lease-0001',30,1)`); err != nil {
		t.Fatalf("runtime outbox heartbeat: %v", err)
	}
	if _, err := outboxConnection.Exec(ctx, `SELECT zasp_runtime_ack_outbox('runtime-events',$1,$2,$3,$4,'runtime-outbox-worker','runtime-outbox-lease-0001',$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), outboxID, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatalf("runtime outbox ack: %v", err)
	}
	if _, err := outboxConnection.Exec(ctx, `SELECT zasp_runtime_claim_outbox('discovery-jobs','runtime-outbox-worker','runtime-outbox-lease-0002',30,1)`); err == nil {
		t.Fatal("runtime outbox claimed discovery topic")
	}
	messageID := "runtime-message-v15-0001"
	var deliveryClaim json.RawMessage
	if err := coordinatorConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_delivery($1,$2,$3,$4,1,$5,$6,1,'coordinator-worker','coordinator-lease-0001',30,60)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest).Scan(&deliveryClaim); err != nil || !bytes.Contains(deliveryClaim, []byte(`"disposition": "claimed"`)) && !bytes.Contains(deliveryClaim, []byte(`"disposition":"claimed"`)) {
		t.Fatalf("delivery claim=%s err=%v", deliveryClaim, err)
	}
	var replayedDelivery json.RawMessage
	if err := coordinatorConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_delivery($1,$2,$3,$4,1,$5,$6,1,'coordinator-worker','coordinator-lease-0001',30,60)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest).Scan(&replayedDelivery); err != nil || !bytes.Contains(replayedDelivery, []byte(`"replayed": true`)) && !bytes.Contains(replayedDelivery, []byte(`"replayed":true`)) {
		t.Fatalf("delivery replay=%s err=%v", replayedDelivery, err)
	}
	var busyDelivery json.RawMessage
	if err := coordinatorConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_delivery($1,$2,$3,$4,1,$5,$6,2,'other-coordinator','other-coordinator-lease',30,60)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest).Scan(&busyDelivery); err != nil || !bytes.Contains(busyDelivery, []byte(`"disposition": "busy"`)) && !bytes.Contains(busyDelivery, []byte(`"disposition":"busy"`)) {
		t.Fatalf("delivery busy=%s err=%v", busyDelivery, err)
	}
	if _, err := coordinatorConnection.Exec(ctx, `SELECT zasp_runtime_heartbeat_delivery($1,$2,$3,$4,1,$5,$6,'coordinator-worker','wrong-delivery-lease',30,60)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest); err == nil {
		t.Fatal("wrong delivery heartbeat lease succeeded")
	}
	if _, err := coordinatorConnection.Exec(ctx, `SELECT zasp_runtime_heartbeat_delivery($1,$2,$3,$4,1,$5,$6,'coordinator-worker','coordinator-lease-0001',30,60)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest); err != nil {
		t.Fatalf("delivery heartbeat: %v", err)
	}
	prematureAckDigest := sha256.Sum256([]byte("premature-delete-ack"))
	if _, err := coordinatorConnection.Exec(ctx, `SELECT zasp_runtime_ack_delivery($1,$2,$3,$4,1,$5,$6,'coordinator-worker','coordinator-lease-0001',$7)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest, prematureAckDigest[:]); err == nil {
		t.Fatal("delivery acknowledged before terminal stage")
	}

	var claimedBeforeArchive json.RawMessage
	if err := indexConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('index-worker','index-lease-token-0001',30,1)`).Scan(&claimedBeforeArchive); err != nil || string(claimedBeforeArchive) != "[]" {
		t.Fatalf("index predecessor gate=%s err=%v", claimedBeforeArchive, err)
	}
	type stageClaim struct {
		BatchID               string    `json:"batch_id"`
		Generation            int64     `json:"generation"`
		Stage                 string    `json:"stage"`
		Attempt               int       `json:"attempt"`
		ImplementationVersion string    `json:"implementation_version"`
		InputDigest           string    `json:"input_digest"`
		LeaseExpiresAt        time.Time `json:"lease_expires_at"`
	}
	var archiveClaims []stageClaim
	var archiveClaimJSON json.RawMessage
	if err := archiveConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('archive-worker','archive-lease-token-0001',30,1)`).Scan(&archiveClaimJSON); err != nil {
		t.Fatalf("archive claim: %v", err)
	}
	if err := json.Unmarshal(archiveClaimJSON, &archiveClaims); err != nil || len(archiveClaims) != 1 || archiveClaims[0].BatchID != batchID || archiveClaims[0].Generation != 1 || archiveClaims[0].Stage != "archive" || archiveClaims[0].Attempt != 1 || archiveClaims[0].ImplementationVersion != "runtime-archive-v1" || archiveClaims[0].InputDigest != fmt.Sprintf("%x", contentDigest) || archiveClaims[0].LeaseExpiresAt.IsZero() {
		t.Fatalf("archive claims=%s decoded=%#v err=%v", archiveClaimJSON, archiveClaims, err)
	}
	if _, err := archiveConnection.Exec(ctx, `SELECT zasp_runtime_heartbeat_stage($1,$2,$3,$4,1,'archive-worker','wrong-archive-lease',30)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID); err == nil {
		t.Fatal("wrong archive heartbeat lease succeeded")
	}
	effectDigest := sha256.Sum256([]byte("archive-effect-v1"))
	resultDigest := sha256.Sum256([]byte("archive-result-v1"))
	finishArchiveSQL := `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,1,'archive-worker','archive-lease-token-0001',1,$5,'runtime-archive-v1','succeeded',$6,'s3://zasp-runtime/normalized/version-v15-0001','normalized-version-v15-0001',$7,NULL,0)`
	if _, err := archiveConnection.Exec(ctx, finishArchiveSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, bytes.Repeat([]byte{0xaa}, 32), effectDigest[:], resultDigest[:]); err == nil {
		t.Fatal("archive finish accepted drifted input digest")
	}
	if _, err := archiveConnection.Exec(ctx, finishArchiveSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, contentDigest[:], effectDigest[:], resultDigest[:]); err != nil {
		t.Fatalf("archive finish: %v", err)
	}
	var replayedArchive json.RawMessage
	if err := archiveConnection.QueryRow(ctx, finishArchiveSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, contentDigest[:], effectDigest[:], resultDigest[:]).Scan(&replayedArchive); err != nil || !bytes.Contains(replayedArchive, []byte(`"state": "succeeded"`)) && !bytes.Contains(replayedArchive, []byte(`"state":"succeeded"`)) {
		t.Fatalf("archive completion replay=%s err=%v", replayedArchive, err)
	}
	var indexClaims []stageClaim
	var indexClaimJSON json.RawMessage
	if err := indexConnection.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('index-worker','index-lease-token-0001',30,1)`).Scan(&indexClaimJSON); err != nil {
		t.Fatalf("index claim: %v", err)
	}
	if err := json.Unmarshal(indexClaimJSON, &indexClaims); err != nil || len(indexClaims) != 1 || indexClaims[0].BatchID != batchID || indexClaims[0].InputDigest != fmt.Sprintf("%x", effectDigest) {
		t.Fatalf("index claims=%s decoded=%#v err=%v", indexClaimJSON, indexClaims, err)
	}
	finishStage := func(label string, stageConnection *pgx.Conn, worker, leaseToken, implementation string, inputDigest [32]byte, attempt int) [32]byte {
		t.Helper()
		effect := sha256.Sum256([]byte(label + "-effect-v1"))
		result := sha256.Sum256([]byte(label + "-result-v1"))
		resultReference := "ref:runtime/" + label + "/" + batchID
		resultVersion := label + "-version-v15-0001"
		var completed json.RawMessage
		if err := stageConnection.QueryRow(ctx, `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,1,$5,$6,$7,$8,$9,'succeeded',$10,$11,$12,$13,NULL,0)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, worker, leaseToken, attempt, inputDigest[:], implementation, effect[:], resultReference, resultVersion, result[:]).Scan(&completed); err != nil {
			t.Fatalf("%s finish: %v", label, err)
		}
		return effect
	}
	indexEffect := finishStage("index", indexConnection, "index-worker", "index-lease-token-0001", "runtime-index-v1", effectDigest, 1)
	type stageLane struct {
		label          string
		connection     *pgx.Conn
		worker         string
		leaseToken     string
		implementation string
		input          [32]byte
	}
	lanes := []stageLane{
		{label: "correlate", connection: correlationConnection, worker: "correlation-worker", leaseToken: "correlation-lease-0001", implementation: "runtime-correlation-v1", input: indexEffect},
		{label: "project", connection: projectionConnection, worker: "projection-worker", leaseToken: "projection-lease-0001", implementation: "runtime-projection-v1"},
		{label: "complete", connection: coordinatorConnection, worker: "coordinator-worker", leaseToken: "coordinator-stage-lease-0001", implementation: "runtime-complete-v1"},
	}
	for index := range lanes {
		if index > 0 {
			lanes[index].input = lanes[index-1].input
		}
		var claimJSON json.RawMessage
		if err := lanes[index].connection.QueryRow(ctx, `SELECT zasp_runtime_claim_stage($1,$2,30,1)`, lanes[index].worker, lanes[index].leaseToken).Scan(&claimJSON); err != nil {
			t.Fatalf("%s claim: %v", lanes[index].label, err)
		}
		var claims []stageClaim
		if err := json.Unmarshal(claimJSON, &claims); err != nil || len(claims) != 1 || claims[0].Stage != lanes[index].label || claims[0].InputDigest != fmt.Sprintf("%x", lanes[index].input) {
			t.Fatalf("%s claims=%s decoded=%#v err=%v", lanes[index].label, claimJSON, claims, err)
		}
		lanes[index].input = finishStage(lanes[index].label, lanes[index].connection, lanes[index].worker, lanes[index].leaseToken, lanes[index].implementation, lanes[index].input, claims[0].Attempt)
	}
	providerAckDigest := sha256.Sum256([]byte("runtime-delete-ack-v1"))
	var acknowledged json.RawMessage
	if err := coordinatorConnection.QueryRow(ctx, `SELECT zasp_runtime_ack_delivery($1,$2,$3,$4,1,$5,$6,'coordinator-worker','coordinator-lease-0001',$7)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest, providerAckDigest[:]).Scan(&acknowledged); err != nil || !bytes.Contains(acknowledged, []byte(`"disposition": "acked"`)) && !bytes.Contains(acknowledged, []byte(`"disposition":"acked"`)) {
		t.Fatalf("delivery ack=%s err=%v", acknowledged, err)
	}
	var replayedAck json.RawMessage
	if err := coordinatorConnection.QueryRow(ctx, `SELECT zasp_runtime_ack_delivery($1,$2,$3,$4,1,$5,$6,'coordinator-worker','coordinator-lease-0001',$7)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID, messageID, messageDigest, providerAckDigest[:]).Scan(&replayedAck); err != nil || !bytes.Contains(replayedAck, []byte(`"replayed": true`)) && !bytes.Contains(replayedAck, []byte(`"replayed":true`)) {
		t.Fatalf("delivery ack replay=%s err=%v", replayedAck, err)
	}
	var batchState, jobState, deliveryDisposition string
	if err := connection.QueryRow(ctx, `SELECT authority.state,job.state,delivery.disposition FROM zasp_runtime_batch_authorities authority JOIN zasp_discovery_jobs job ON (job.organization_id,job.workspace_id,job.environment_id,job.kind,job.authority_id)=(authority.organization_id,authority.workspace_id,authority.environment_id,'runtime',authority.batch_id) JOIN zasp_runtime_deliveries delivery ON (delivery.organization_id,delivery.workspace_id,delivery.environment_id,delivery.batch_id)=(authority.organization_id,authority.workspace_id,authority.environment_id,authority.batch_id) WHERE authority.batch_id=$1`, batchID).Scan(&batchState, &jobState, &deliveryDisposition); err != nil || batchState != "succeeded" || jobState != "succeeded" || deliveryDisposition != "acked" {
		t.Fatalf("terminal runtime authority batch=%q job=%q delivery=%q err=%v", batchState, jobState, deliveryDisposition, err)
	}

	replacementLocator := bytes.Repeat([]byte{0x71}, 16)
	replacementSecret := bytes.Repeat([]byte{0x72}, 32)
	replacementSalt := bytes.Repeat([]byte{0x73}, 32)
	replacement, err := sensor.NewTokenCredential(replacementLocator, replacementSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Destroy()
	replacementID := "pid_76000004-0000-4000-8000-000000000004"
	replacementLocatorDigest, _ := replacement.LocatorDigest()
	replacementHash, _ := replacement.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, replacementID), 2, replacementSalt)
	reconcileDigest := sha256.Sum256([]byte("runtime-reconcile-v15"))
	reconcileBatchID := "pid_76000008-0000-4000-8000-000000000008"
	var reconcileReservation struct {
		Generation    int64  `json:"generation"`
		ArtifactKey   string `json:"artifact_key"`
		RequestDigest string `json:"request_digest"`
	}
	if err := connection.QueryRow(ctx, reserveSQL, locator, secret, reconcileBatchID, "runtime-batch-key-0002", reconcileDigest[:]).Scan(&reconcileReservation); err != nil {
		t.Fatalf("reconcile reservation: %v", err)
	}
	var rotated json.RawMessage
	rotationSQL := `SELECT zasp_runtime_rotate_sensor_token($1,$2,$3,$4,$5,$6,2,1,$7,$8,$9,$10)`
	replacementExpiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	rotationArguments := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, tokenID, replacementID, replacementLocatorDigest[:], replacementSalt, replacementHash[:], replacementExpiry}
	if err := connection.QueryRow(ctx, rotationSQL, rotationArguments...).Scan(&rotated); err != nil || !bytes.Contains(rotated, []byte(`"replayed": false`)) && !bytes.Contains(rotated, []byte(`"replayed":false`)) {
		t.Fatalf("rotate=%s err=%v", rotated, err)
	}
	if err := connection.QueryRow(ctx, rotationSQL, rotationArguments...).Scan(&rotated); err != nil || !bytes.Contains(rotated, []byte(`"replayed": true`)) && !bytes.Contains(rotated, []byte(`"replayed":true`)) {
		t.Fatalf("rotation replay=%s err=%v", rotated, err)
	}
	reconcileJobID := "pid_76000009-0000-4000-8000-000000000009"
	reconcileOutboxID := "pid_76000010-0000-4000-8000-000000000010"
	reconcileReference := "s3://zasp-runtime/" + reconcileReservation.ArtifactKey
	if _, err := connection.Exec(ctx, finalizeSQL, locator, secret, reconcileBatchID, reconcileJobID, reconcileOutboxID, reconcileReference, reconcileReservation.ArtifactKey, "version-v15-reconcile", reconcileDigest[:], kmsKey); err == nil {
		t.Fatal("rotated token finalized an abandoned upload")
	}
	var reconciled json.RawMessage
	if err := ingestConnection.QueryRow(ctx, `SELECT zasp_runtime_reconcile_batch($1,$2,$3,$4,$5,decode($6,'hex'),$7,$8,$9,$10,$11,$12,128,$13)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), reconcileBatchID, reconcileReservation.Generation, reconcileReservation.RequestDigest, reconcileJobID, reconcileOutboxID, reconcileReference, reconcileReservation.ArtifactKey, "version-v15-reconcile", reconcileDigest[:], kmsKey).Scan(&reconciled); err != nil || !bytes.Contains(reconciled, []byte(`"state": "queued"`)) && !bytes.Contains(reconciled, []byte(`"state":"queued"`)) {
		t.Fatalf("reconciled upload=%s err=%v", reconciled, err)
	}
	if err := ingestConnection.QueryRow(ctx, `SELECT zasp_runtime_reconcile_batch($1,$2,$3,$4,$5,decode($6,'hex'),$7,$8,$9,$10,$11,$12,128,$13)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), reconcileBatchID, reconcileReservation.Generation, reconcileReservation.RequestDigest, reconcileJobID, reconcileOutboxID, reconcileReference, reconcileReservation.ArtifactKey, "version-v15-reconcile", reconcileDigest[:], kmsKey).Scan(&reconciled); err != nil || !bytes.Contains(reconciled, []byte(`"replayed": true`)) && !bytes.Contains(reconciled, []byte(`"replayed":true`)) {
		t.Fatalf("reconciled upload replay=%s err=%v", reconciled, err)
	}
	driftDigest := sha256.Sum256([]byte("runtime-reconcile-drift-v15"))
	driftBatchID := "pid_76000013-0000-4000-8000-000000000013"
	var driftReservation struct {
		Generation    int64  `json:"generation"`
		ArtifactKey   string `json:"artifact_key"`
		RequestDigest string `json:"request_digest"`
	}
	if err := connection.QueryRow(ctx, reserveSQL, replacementLocator, replacementSecret, driftBatchID, "runtime-batch-key-0003", driftDigest[:]).Scan(&driftReservation); err != nil {
		t.Fatalf("drift reservation: %v", err)
	}
	driftReference := "s3://zasp-runtime/" + driftReservation.ArtifactKey
	var quarantined json.RawMessage
	if err := ingestConnection.QueryRow(ctx, `SELECT zasp_runtime_reconcile_batch($1,$2,$3,$4,$5,decode($6,'hex'),$7,$8,$9,$10,$11,$12,128,$13)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), driftBatchID, driftReservation.Generation, driftReservation.RequestDigest, "pid_76000014-0000-4000-8000-000000000014", "pid_76000015-0000-4000-8000-000000000015", driftReference, driftReservation.ArtifactKey, "version-v15-drift", bytes.Repeat([]byte{0xee}, 32), kmsKey).Scan(&quarantined); err != nil || !bytes.Contains(quarantined, []byte(`"state": "quarantined"`)) && !bytes.Contains(quarantined, []byte(`"state":"quarantined"`)) {
		t.Fatalf("drifted upload=%s err=%v", quarantined, err)
	}
	var driftState string
	var driftStages, driftOutbox int
	if err := connection.QueryRow(ctx, `SELECT authority.state,(SELECT count(*) FROM zasp_runtime_stage_work stage WHERE stage.batch_id=authority.batch_id),(SELECT count(*) FROM zasp_discovery_outbox outbox WHERE outbox.deterministic_key='runtime:'||authority.batch_id) FROM zasp_runtime_batch_authorities authority WHERE authority.batch_id=$1`, driftBatchID).Scan(&driftState, &driftStages, &driftOutbox); err != nil || driftState != "quarantined" || driftStages != 0 || driftOutbox != 0 {
		t.Fatalf("drifted reconcile state=%q stages=%d outbox=%d err=%v", driftState, driftStages, driftOutbox, err)
	}
	_, oldAfterRotationErr := connection.Exec(ctx, `SELECT zasp_runtime_authenticate_sensor($1,$2,'event-ingest')`, locator, secret)
	if oldAfterRotationErr == nil || pgErrorSignature(t, oldAfterRotationErr) != pgErrorSignature(t, wrongSecretErr) {
		t.Fatalf("rotated token oracle wrong=%q rotated=%q", pgErrorSignature(t, wrongSecretErr), pgErrorSignature(t, oldAfterRotationErr))
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_authenticate_sensor($1,$2,'event-ingest')`, replacementLocator, replacementSecret); err != nil {
		t.Fatalf("replacement authentication: %v", err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_revoke_sensor_token($1,$2,$3,$4,$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, replacementID); err != nil {
		t.Fatalf("revoke replacement: %v", err)
	}
	_, revokedErr := connection.Exec(ctx, `SELECT zasp_runtime_authenticate_sensor($1,$2,'event-ingest')`, replacementLocator, replacementSecret)
	if revokedErr == nil || pgErrorSignature(t, revokedErr) != pgErrorSignature(t, wrongSecretErr) {
		t.Fatalf("revoked token oracle wrong=%q revoked=%q", pgErrorSignature(t, wrongSecretErr), pgErrorSignature(t, revokedErr))
	}
	var rawColumns int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='zasp_sensor_tokens' AND column_name IN('locator','secret','raw_token')`).Scan(&rawColumns); err != nil || rawColumns != 0 {
		t.Fatalf("raw token columns=%d err=%v", rawColumns, err)
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("used v15 rollback error=%v", err)
	}
}

func TestProductionRuntimeDataPlanePostgresRestoresUnusedLegacyTokenOnDownAndReup(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	scope := fixtureRequestIdentity(t).Scope
	sensorID := "pid_76000011-0000-4000-8000-000000000011"
	legacyTokenID := "pid_76000012-0000-4000-8000-000000000012"
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'rollback-sensor','otlp')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_issue_sensor_token($1,$2,$3,$4,$5,$6,$7,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, legacyTokenID, bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 up: %v", err)
	}
	principalNames := []string{"runtime_rollback_coordinator", "runtime_rollback_archive", "runtime_rollback_index", "runtime_rollback_correlation", "runtime_rollback_projection", "runtime_rollback_gateway"}
	for _, principal := range principalNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	var migrationPrincipal string
	if err := connection.QueryRow(ctx, `SELECT session_user`).Scan(&migrationPrincipal); err != nil {
		t.Fatal(err)
	}
	var registered, principalsReady bool
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_register_principals($1,$2,$3,$4,$5,$6,$7)`, migrationPrincipal, principalNames[0], principalNames[1], principalNames[2], principalNames[3], principalNames[4], principalNames[5]).Scan(&registered); err != nil || !registered {
		t.Fatalf("register rollback principals=%t err=%v", registered, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_principals_ready()`).Scan(&principalsReady); err != nil || !principalsReady {
		t.Fatalf("runtime principals ready=%t err=%v", principalsReady, err)
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("unused v15 down: %v", err)
	}
	var runtimeOutboxRemoved, runtimeTopicRemoved bool
	if err := connection.QueryRow(ctx, `SELECT to_regprocedure('zasp_runtime_claim_outbox(text,text,text,integer,integer)') IS NULL,position('runtime-events' IN pg_get_constraintdef((SELECT oid FROM pg_constraint WHERE conrelid='zasp_discovery_outbox_topic_fairness'::regclass AND conname='zasp_discovery_outbox_topic_fairness_topic_check')))=0`).Scan(&runtimeOutboxRemoved, &runtimeTopicRemoved); err != nil || !runtimeOutboxRemoved || !runtimeTopicRemoved {
		t.Fatalf("runtime outbox down function=%t topic=%t err=%v", runtimeOutboxRemoved, runtimeTopicRemoved, err)
	}
	var retainedMemberships int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM pg_auth_members membership JOIN pg_roles member_value ON member_value.oid=membership.member JOIN pg_roles granted ON granted.oid=membership.roleid WHERE member_value.rolname=ANY($1) AND granted.rolname LIKE 'zasp_runtime_%'`, principalNames).Scan(&retainedMemberships); err != nil || retainedMemberships != 0 {
		t.Fatalf("retained runtime memberships=%d err=%v", retainedMemberships, err)
	}
	var revokedAt *time.Time
	if err := connection.QueryRow(ctx, `SELECT revoked_at FROM zasp_sensor_tokens WHERE id=$1`, legacyTokenID).Scan(&revokedAt); err != nil || revokedAt != nil {
		t.Fatalf("legacy token revoked_at=%v err=%v", revokedAt, err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_readiness($1,$2)`, migrations.ProductionTypedInventoryCutover().Checksum(), migrations.ProductionTypedInventoryCutoverSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("restored v14 readiness=%t err=%v", ready, err)
	}
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 re-up: %v", err)
	}
	var runtimeOutboxRestored, runtimeTopicRestored bool
	if err := connection.QueryRow(ctx, `SELECT to_regprocedure('zasp_runtime_claim_outbox(text,text,text,integer,integer)') IS NOT NULL,position('runtime-events' IN pg_get_constraintdef((SELECT oid FROM pg_constraint WHERE conrelid='zasp_discovery_outbox_topic_fairness'::regclass AND conname='zasp_discovery_outbox_topic_fairness_topic_check')))>0`).Scan(&runtimeOutboxRestored, &runtimeTopicRestored); err != nil || !runtimeOutboxRestored || !runtimeTopicRestored {
		t.Fatalf("runtime outbox re-up function=%t topic=%t err=%v", runtimeOutboxRestored, runtimeTopicRestored, err)
	}
}

func TestProductionRuntimeDataPlanePostgresBindsGatewayEnrollmentReplayAndPolicy(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	scope := fixtureRequestIdentity(t).Scope
	deviceID := "pid_76000101-0000-4000-8000-000000000101"
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_create_gateway_device($1,$2,$3,$4,'runtime-gateway')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deviceID); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatalf("v15 up: %v", err)
	}
	principalNames := []string{"gateway_test_coordinator", "gateway_test_archive", "gateway_test_index", "gateway_test_correlation", "gateway_test_projection", "gateway_test_control"}
	for _, principal := range principalNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	var migrationPrincipal string
	if err := connection.QueryRow(ctx, `SELECT session_user`).Scan(&migrationPrincipal); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT zasp_runtime_register_principals($1,$2,$3,$4,$5,$6,$7)`, migrationPrincipal, principalNames[0], principalNames[1], principalNames[2], principalNames[3], principalNames[4], principalNames[5]); err != nil {
		t.Fatal(err)
	}
	gatewayConnection := connectRuntimeDataPlanePrincipal(t, ctx, dsn, principalNames[5])
	defer gatewayConnection.Close(context.Background())

	enrollmentID := "pid_76000102-0000-4000-8000-000000000102"
	locator := bytes.Repeat([]byte{0x81}, 16)
	secret := bytes.Repeat([]byte{0x82}, 32)
	salt := bytes.Repeat([]byte{0x83}, 32)
	locatorDigest := sha256.Sum256(locator)
	hash := sha256.New()
	hash.Write([]byte("zasp-gateway-enrollment-token-hash-v1"))
	hash.Write([]byte{0})
	hash.Write([]byte("runtime-gateway-enroll"))
	hash.Write([]byte{0})
	hash.Write([]byte(enrollmentID))
	hash.Write([]byte{0})
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], 1)
	hash.Write(generation[:])
	hash.Write(salt)
	hash.Write(secret)
	tokenHash := hash.Sum(nil)
	var issued json.RawMessage
	if err := connection.QueryRow(ctx, `SELECT zasp_runtime_issue_gateway_enrollment($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 hour')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), enrollmentID, deviceID, locatorDigest[:], salt, tokenHash).Scan(&issued); err != nil || bytes.Contains(issued, locator) || bytes.Contains(issued, secret) || bytes.Contains(issued, tokenHash) {
		t.Fatalf("gateway enrollment issue=%s err=%v", issued, err)
	}
	wrongSecret := bytes.Repeat([]byte{0x84}, 32)
	_, wrongSecretErr := gatewayConnection.Exec(ctx, `SELECT zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll')`, locator, wrongSecret)
	_, missingLocatorErr := gatewayConnection.Exec(ctx, `SELECT zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll')`, bytes.Repeat([]byte{0x85}, 16), secret)
	if wrongSecretErr == nil || missingLocatorErr == nil || pgErrorSignature(t, wrongSecretErr) != pgErrorSignature(t, missingLocatorErr) {
		t.Fatalf("gateway token oracle wrong=%q missing=%q", pgErrorSignature(t, wrongSecretErr), pgErrorSignature(t, missingLocatorErr))
	}
	credentialID := "pid_76000103-0000-4000-8000-000000000103"
	publicKey := bytes.Repeat([]byte{0x86}, 32)
	credentialExpiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	enrollSQL := `SELECT zasp_runtime_gateway_enroll($1,$2,'runtime-gateway-enroll',$3,1,'gateway-key-1','Ed25519',$4,$5)`
	var enrolled json.RawMessage
	if err := gatewayConnection.QueryRow(ctx, enrollSQL, locator, secret, credentialID, publicKey, credentialExpiry).Scan(&enrolled); err != nil || !bytes.Contains(enrolled, []byte(`"replayed": false`)) && !bytes.Contains(enrolled, []byte(`"replayed":false`)) || bytes.Contains(enrolled, secret) {
		t.Fatalf("gateway enroll=%s err=%v", enrolled, err)
	}
	if err := gatewayConnection.QueryRow(ctx, enrollSQL, locator, secret, credentialID, publicKey, credentialExpiry).Scan(&enrolled); err != nil || !bytes.Contains(enrolled, []byte(`"replayed": true`)) && !bytes.Contains(enrolled, []byte(`"replayed":true`)) {
		t.Fatalf("gateway enroll replay=%s err=%v", enrolled, err)
	}
	var credentialAuthority json.RawMessage
	if err := gatewayConnection.QueryRow(ctx, `SELECT zasp_runtime_gateway_credential_authority($1,'runtime-gateway')`, credentialID).Scan(&credentialAuthority); err != nil || !bytes.Contains(credentialAuthority, []byte(scope.OrganizationID().String())) || !bytes.Contains(credentialAuthority, []byte(deviceID)) || bytes.Contains(credentialAuthority, secret) {
		t.Fatalf("gateway credential authority=%s err=%v", credentialAuthority, err)
	}
	requestDigest := sha256.Sum256([]byte("gateway-signed-request-v1"))
	var replayFloor json.RawMessage
	advanceSQL := `SELECT zasp_runtime_gateway_advance_replay($1,0,1,$2)`
	if err := gatewayConnection.QueryRow(ctx, advanceSQL, credentialID, requestDigest[:]).Scan(&replayFloor); err != nil || !bytes.Contains(replayFloor, []byte(`"replayed": false`)) && !bytes.Contains(replayFloor, []byte(`"replayed":false`)) {
		t.Fatalf("gateway replay advance=%s err=%v", replayFloor, err)
	}
	if err := gatewayConnection.QueryRow(ctx, advanceSQL, credentialID, requestDigest[:]).Scan(&replayFloor); err != nil || !bytes.Contains(replayFloor, []byte(`"replayed": true`)) && !bytes.Contains(replayFloor, []byte(`"replayed":true`)) {
		t.Fatalf("gateway replay exact=%s err=%v", replayFloor, err)
	}
	if _, err := gatewayConnection.Exec(ctx, advanceSQL, credentialID, bytes.Repeat([]byte{0x87}, 32)); err == nil {
		t.Fatal("gateway replay accepted same floor drift")
	}

	policies := json.RawMessage(`[{"id":"policy-runtime-1","effect":"block"}]`)
	payloadDigest := sha256.Sum256(policies)
	envelopeDigest := sha256.Sum256([]byte("gateway-envelope-v1"))
	signature := bytes.Repeat([]byte{0x88}, 64)
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)
	expiresAt := issuedAt.Add(time.Hour)
	putPolicySQL := `SELECT zasp_runtime_gateway_put_policy_bundle($1,1,1,'gateway-signing-key-1',$2,$3,'closed',$4,$5::jsonb,$6,$7)`
	var storedPolicy json.RawMessage
	if err := gatewayConnection.QueryRow(ctx, putPolicySQL, credentialID, issuedAt, expiresAt, payloadDigest[:], policies, signature, envelopeDigest[:]).Scan(&storedPolicy); err != nil || !bytes.Contains(storedPolicy, []byte(`"replayed": false`)) && !bytes.Contains(storedPolicy, []byte(`"replayed":false`)) {
		t.Fatalf("gateway policy store=%s err=%v", storedPolicy, err)
	}
	if err := gatewayConnection.QueryRow(ctx, putPolicySQL, credentialID, issuedAt, expiresAt, payloadDigest[:], policies, signature, envelopeDigest[:]).Scan(&storedPolicy); err != nil || !bytes.Contains(storedPolicy, []byte(`"replayed": true`)) && !bytes.Contains(storedPolicy, []byte(`"replayed":true`)) {
		t.Fatalf("gateway policy replay=%s err=%v", storedPolicy, err)
	}
	if _, err := gatewayConnection.Exec(ctx, putPolicySQL, credentialID, issuedAt, expiresAt, bytes.Repeat([]byte{0x89}, 32), policies, signature, envelopeDigest[:]); err == nil {
		t.Fatal("gateway policy accepted same-sequence drift")
	}
	var fetchedPolicy json.RawMessage
	if err := gatewayConnection.QueryRow(ctx, `SELECT zasp_runtime_gateway_policy_bundle($1,0)`, credentialID).Scan(&fetchedPolicy); err != nil || !bytes.Contains(fetchedPolicy, []byte(`"algorithm": "Ed25519"`)) && !bytes.Contains(fetchedPolicy, []byte(`"algorithm":"Ed25519"`)) || !bytes.Contains(fetchedPolicy, []byte(`"audience": "runtime-gateway-policy"`)) && !bytes.Contains(fetchedPolicy, []byte(`"audience":"runtime-gateway-policy"`)) || bytes.Contains(fetchedPolicy, secret) {
		t.Fatalf("gateway policy fetch=%s err=%v", fetchedPolicy, err)
	}
	eventID := "pid_76000104-0000-4000-8000-000000000104"
	classification := json.RawMessage(`{"category":"process","outcome":"blocked"}`)
	occurredAt := time.Now().UTC().Truncate(time.Microsecond)
	var eventDigest []byte
	if err := connection.QueryRow(ctx, `SELECT digest(convert_to(jsonb_build_object('credential_id',$1::text,'device_id',$2::text,'event_id',$3::text,'expected_floor',1::bigint,'next_floor',2::bigint,'policy_version',1::bigint,'decision','block','action_kind','http','classification',$4::jsonb,'occurred_at',to_char($5::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8'),'sha256')`, credentialID, deviceID, eventID, classification, occurredAt).Scan(&eventDigest); err != nil {
		t.Fatal(err)
	}
	recordEventSQL := `SELECT zasp_runtime_gateway_record_event($1,$2,1,2,$3,1,'block','http',$4::jsonb,$5)`
	var recordedEvent json.RawMessage
	if err := gatewayConnection.QueryRow(ctx, recordEventSQL, credentialID, eventID, eventDigest, classification, occurredAt).Scan(&recordedEvent); err != nil || !bytes.Contains(recordedEvent, []byte(`"replayed": false`)) && !bytes.Contains(recordedEvent, []byte(`"replayed":false`)) {
		t.Fatalf("gateway event=%s err=%v", recordedEvent, err)
	}
	if err := gatewayConnection.QueryRow(ctx, recordEventSQL, credentialID, eventID, eventDigest, classification, occurredAt).Scan(&recordedEvent); err != nil || !bytes.Contains(recordedEvent, []byte(`"replayed": true`)) && !bytes.Contains(recordedEvent, []byte(`"replayed":true`)) {
		t.Fatalf("gateway event replay=%s err=%v", recordedEvent, err)
	}
	if _, err := gatewayConnection.Exec(ctx, recordEventSQL, credentialID, "pid_76000105-0000-4000-8000-000000000105", eventDigest, json.RawMessage(`{"authorization":"Bearer secret"}`), occurredAt); err == nil {
		t.Fatal("gateway event accepted secret-shaped metadata")
	}
	if _, err := gatewayConnection.Exec(ctx, `SELECT count(*) FROM zasp_gateway_credentials`); err == nil {
		t.Fatal("gateway control principal received direct credential table access")
	}
	if err := runner.DownProductionRuntimeDataPlane(ctx); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("used gateway v15 rollback error=%v", err)
	}
}

func mustProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func connectRuntimeDataPlanePrincipal(t *testing.T, ctx context.Context, dsn, principal string) *pgx.Conn {
	t.Helper()
	configuration, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.User = principal
	connection, err := pgx.ConnectConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func pgErrorSignature(t *testing.T, err error) string {
	t.Helper()
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		t.Fatalf("not PostgreSQL error: %v", err)
	}
	return pgError.Code + ":" + pgError.Message
}
