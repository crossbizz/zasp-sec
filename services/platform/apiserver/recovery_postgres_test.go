package apiserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionRecoveryPostgresInstallsExactAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
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
	} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}

	metadata := migrations.ProductionRecovery()
	probe, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, metadata.UpSQL()); err != nil {
		_ = probe.Rollback(ctx)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			t.Fatalf("v27 SQL position=%d detail=%s where=%s: %v", postgresError.Position, postgresError.Detail, postgresError.Where, err)
		}
		t.Fatalf("v27 SQL: %v", err)
	}
	var fingerprint string
	if err := probe.QueryRow(ctx, `SELECT zasp_recovery_execution_live_fingerprint()`).Scan(&fingerprint); err != nil {
		_ = probe.Rollback(ctx)
		t.Fatal(err)
	}
	if fingerprint != migrations.ProductionRecoverySemanticFingerprint() {
		_ = probe.Rollback(ctx)
		t.Fatalf("v27 candidate fingerprint=%s pinned=%s", fingerprint, migrations.ProductionRecoverySemanticFingerprint())
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRecovery(ctx); err != nil {
		t.Fatalf("v27 up: %v", err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("v27 readiness=%t err=%v", ready, err)
	}

	principalNames := []string{"recovery_api_login", "recovery_discovery_login", "recovery_ingest_login", "recovery_runtime_login", "recovery_discovery_outbox_login", "recovery_gateway_login", "recovery_worker_login", "recovery_outbox_login"}
	for _, principal := range principalNames {
		if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_register_principals(session_user,$1,$2,$3,$4,$5,$6)`, principalNames[0], principalNames[1], principalNames[2], principalNames[3], principalNames[4], principalNames[5]).Scan(&ready); err != nil || !ready {
		t.Fatalf("discovery registration=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_register_principals(session_user,$1,$2)`, principalNames[6], principalNames[7]).Scan(&ready); err != nil || !ready {
		t.Fatalf("recovery registration=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_principals_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("recovery principals=%t err=%v", ready, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_recovery_execution_readiness($1,$2)`, metadata.Checksum(), fingerprint).Scan(&ready); err != nil || !ready {
		t.Fatalf("registered v27 readiness=%t err=%v", ready, err)
	}

	connectAs := func(principal string) *pgx.Conn {
		t.Helper()
		configuration, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		configuration.User = principal
		value, connectErr := pgx.ConnectConfig(ctx, configuration)
		if connectErr != nil {
			t.Fatal(connectErr)
		}
		return value
	}
	api := connectAs(principalNames[0])
	defer api.Close(context.Background())
	worker := connectAs(principalNames[6])
	defer worker.Close(context.Background())
	outbox := connectAs(principalNames[7])
	defer outbox.Close(context.Background())

	scopes := [][3]string{
		{"pid_7b000001-0000-4000-8000-000000000001", "pid_7b000002-0000-4000-8000-000000000002", "pid_7b000003-0000-4000-8000-000000000003"},
		{"pid_7c000001-0000-4000-8000-000000000001", "pid_7c000002-0000-4000-8000-000000000002", "pid_7c000003-0000-4000-8000-000000000003"},
	}
	for index, scope := range scopes {
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_organizations(id,name,domain) VALUES($1,$2,$3)`, scope[0], fmt.Sprintf("Recovery tenant %d", index+1), fmt.Sprintf("recovery-%d.invalid", index+1)); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Security')`, scope[1], scope[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, scope[2], scope[0], scope[1]); err != nil {
			t.Fatal(err)
		}
	}
	integrationIDs := []string{"pid_7b000004-0000-4000-8000-000000000004", "pid_7c000004-0000-4000-8000-000000000004"}
	for index, scope := range scopes {
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES($1,$2,$3,$4,'aws','aws-v1',$5,'{"account_id":"123456789012"}'::jsonb,'active')`, scope[0], scope[1], scope[2], integrationIDs[index], fmt.Sprintf("AWS %d", index+1)); err != nil {
			t.Fatal(err)
		}
	}
	projectionSyncID := "pid_7b000040-0000-4000-8000-000000000040"
	projectionSnapshotID := "pid_7b000041-0000-4000-8000-000000000041"
	projectionEntityID := "pid_7b000042-0000-4000-8000-000000000042"
	projectionDigest := bytes.Repeat([]byte{0x40}, 32)
	if _, err := connection.Exec(ctx, `
INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,parser_version,tool_version,started_at)
VALUES($1,$2,$3,$4,$5,'recovery-projection-sync-0001',$6,'manual','pid_7b000043-0000-4000-8000-000000000043','running','parser-v1','tool-v1',transaction_timestamp());
INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at)
VALUES($1,$2,$3,$7,$5,$4,7,'aws','s3://zasp-evidence/organizations/recovery-projection-manifest.json',$6,'complete',$6,'{}'::jsonb,true,true,transaction_timestamp(),transaction_timestamp());
UPDATE zasp_discovery_syncs SET state='succeeded',snapshot_id=$7,completed_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4);
INSERT INTO zasp_discovery_snapshot_inputs(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,generation,candidate_digest,manifest_reference,manifest_key,manifest_version_id,manifest_checksum,manifest_size_bytes,manifest_media_type,manifest_schema_version,parser_version,tool_version,entities,relationships,evidence)
VALUES($1,$2,$3,$7,$5,'aws',7,$6,'s3://zasp-evidence/organizations/recovery-projection-manifest.json','organizations/recovery-projection-manifest.json','version-recovery-1',$6,4096,'application/json','manifest-v1','parser-v1','tool-v1',jsonb_build_array(jsonb_build_object('id',$8,'kind','database','source_native_id','db-recovery','display_name','Recovery database','stable_fields',jsonb_build_object('engine','postgres'),'attributes','{}'::jsonb)),'[]'::jsonb,'[]'::jsonb);
INSERT INTO zasp_discovery_snapshot_projection_items(organization_id,workspace_id,environment_id,snapshot_id,integration_id,source,section,item_id,payload)
SELECT $1,$2,$3,$7,$5,'aws','entities',item->>'id',item FROM jsonb_array_elements((SELECT entities FROM zasp_discovery_snapshot_inputs WHERE (organization_id,workspace_id,environment_id,snapshot_id)=($1,$2,$3,$7))) item;
INSERT INTO zasp_projection_work(organization_id,workspace_id,environment_id,snapshot_id,kind,version,input_digest,state,completed_at)
VALUES($1,$2,$3,$7,'graph','v1',$6,'succeeded',transaction_timestamp()),($1,$2,$3,$7,'search','v1',$6,'succeeded',transaction_timestamp());
INSERT INTO zasp_discovery_projection_cursors(organization_id,workspace_id,environment_id,integration_id,source,kind,generation,snapshot_id,input_digest)
VALUES($1,$2,$3,$5,'aws','graph',7,$7,$6),($1,$2,$3,$5,'aws','search',7,$7,$6);
INSERT INTO zasp_discovery_projection_receipts(organization_id,workspace_id,environment_id,snapshot_id,kind,version,integration_id,source,generation,input_digest,driver_receipt,driver_digest)
VALUES($1,$2,$3,$7,'graph','v1',$5,'aws',7,$6,'neo4j:snapshot:recovery',decode(repeat('41',32),'hex')),($1,$2,$3,$7,'search','v1',$5,'aws',7,$6,'opensearch:snapshot:recovery',decode(repeat('42',32),'hex'))`, pgx.QueryExecModeSimpleProtocol, scopes[0][0], scopes[0][1], scopes[0][2], projectionSyncID, integrationIDs[0], projectionDigest, projectionSnapshotID, projectionEntityID); err != nil {
		t.Fatalf("seed recovery projection: %v", err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_discovery_projection_receipts WHERE (organization_id,workspace_id,environment_id,snapshot_id,kind,version)=($1,$2,$3,$4,'search','v1')`, scopes[0][0], scopes[0][1], scopes[0][2], projectionSnapshotID); err != nil {
		t.Fatal(err)
	}
	var rejectedProjection []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_validate_scope($1,$2,$3)`, scopes[0][0], scopes[0][1], scopes[0][2]).Scan(&rejectedProjection); err == nil {
		t.Fatal("recovery scope accepted a projection cursor without a durable receipt")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_projection_receipts(organization_id,workspace_id,environment_id,snapshot_id,kind,version,integration_id,source,generation,input_digest,driver_receipt,driver_digest) VALUES($1,$2,$3,$4,'search','v1',$5,'aws',7,$6,'opensearch:snapshot:recovery',decode(repeat('42',32),'hex'))`, scopes[0][0], scopes[0][1], scopes[0][2], projectionSnapshotID, integrationIDs[0], projectionDigest); err != nil {
		t.Fatal(err)
	}
	createBackup := func(scope [3]string, backupID, idempotency string, digestByte byte) []byte {
		t.Helper()
		var result []byte
		digest := bytes.Repeat([]byte{digestByte}, 32)
		identity := func(value byte) string { return fmt.Sprintf("pid_7b0000%02x-0000-4000-8000-%012x", value, value) }
		if err := api.QueryRow(ctx, `SELECT zasp_recovery_create_backup($1,$2,$3,$4,$5,$6,$7,30,$8,$9,$10)`, scope[0], scope[1], scope[2], "pid_7b000010-0000-4000-8000-000000000010", idempotency, backupID, identity(digestByte), identity(digestByte+1), identity(digestByte+2), digest).Scan(&result); err != nil {
			t.Fatalf("create backup: %v", err)
		}
		return result
	}
	backupID := "pid_7b000020-0000-4000-8000-000000000020"
	created := createBackup(scopes[0], backupID, "recovery-backup-key-0001", 0x27)
	replayed := createBackup(scopes[0], backupID, "recovery-backup-key-0001", 0x27)
	if !bytes.Contains(created, []byte(`"replayed": false`)) || !bytes.Contains(replayed, []byte(`"replayed": true`)) {
		t.Fatalf("backup replay created=%s replayed=%s", created, replayed)
	}
	var rejected []byte
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_create_backup($1,$2,$3,$4,$5,$6,$7,30,$8,$9,$10)`, scopes[0][0], scopes[0][1], scopes[0][2], "pid_7b000010-0000-4000-8000-000000000010", "recovery-backup-key-0001", backupID, "pid_7b000011-0000-4000-8000-000000000011", "pid_7b000012-0000-4000-8000-000000000012", "pid_7b000013-0000-4000-8000-000000000013", bytes.Repeat([]byte{0x28}, 32)).Scan(&rejected); err == nil {
		t.Fatal("request digest drift accepted")
	}

	outboxToken := bytes.Repeat([]byte{0x31}, 32)
	var claimedOutbox []byte
	if err := outbox.QueryRow(ctx, `SELECT zasp_recovery_claim_outbox('recovery-backup-jobs','recovery-outbox-worker',$1,30,10)`, outboxToken).Scan(&claimedOutbox); err != nil || !bytes.Contains(claimedOutbox, []byte(backupID)) {
		t.Fatalf("outbox claim=%s err=%v", claimedOutbox, err)
	}
	var outboxEnvelope struct {
		Items []struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
			OutboxID       string `json:"outbox_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(claimedOutbox, &outboxEnvelope); err != nil || len(outboxEnvelope.Items) != 1 {
		t.Fatalf("outbox envelope=%s err=%v", claimedOutbox, err)
	}
	var ack []byte
	item := outboxEnvelope.Items[0]
	if err := outbox.QueryRow(ctx, `SELECT zasp_recovery_ack_outbox($1,$2,$3,$4,'recovery-outbox-worker',$5,$6)`, item.OrganizationID, item.WorkspaceID, item.EnvironmentID, item.OutboxID, outboxToken, "sha256:"+fmt.Sprintf("%064x", 27)).Scan(&ack); err != nil {
		t.Fatalf("outbox ack: %v", err)
	}

	operationToken := bytes.Repeat([]byte{0x32}, 32)
	var claimedOperation []byte
	workerID := "recovery-worker-1"
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_claim_operation('backup',$1,$2,30,10)`, workerID, operationToken).Scan(&claimedOperation); err != nil || !bytes.Contains(claimedOperation, []byte(backupID)) {
		t.Fatalf("operation claim=%s err=%v", claimedOperation, err)
	}
	var held []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_begin_hold($1,$2,$3,$4,$5,$6)`, scopes[0][0], scopes[0][1], scopes[0][2], backupID, workerID, operationToken).Scan(&held); err != nil || !bytes.Contains(held, []byte(`"state": "held"`)) {
		t.Fatalf("begin hold=%s err=%v", held, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET display_name='blocked' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], integrationIDs[0]); err == nil {
		t.Fatal("held tenant mutation succeeded")
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET display_name='foreign tenant remains mutable' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, scopes[1][0], scopes[1][1], scopes[1][2], integrationIDs[1]); err != nil {
		t.Fatalf("foreign tenant mutation: %v", err)
	}
	var page []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_capture_page($1,$2,$3,$4,$5,$6,'configuration',NULL,100)`, scopes[0][0], scopes[0][1], scopes[0][2], backupID, workerID, operationToken).Scan(&page); err != nil || !bytes.Contains(page, []byte(integrationIDs[0])) {
		t.Fatalf("capture page=%s err=%v", page, err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_capture_page($1,$2,$3,$4,$5,$6,'projection',NULL,100)`, scopes[0][0], scopes[0][1], scopes[0][2], backupID, workerID, operationToken).Scan(&page); err != nil || !bytes.Contains(page, []byte(projectionSnapshotID)) || !bytes.Contains(page, []byte(`"driver_digest": "4141414141414141414141414141414141414141414141414141414141414141"`)) {
		t.Fatalf("projection capture=%s err=%v", page, err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_projection_page($1,$2,$3,$4,'entities',NULL,500)`, scopes[0][0], scopes[0][1], scopes[0][2], projectionSnapshotID).Scan(&page); err != nil || !bytes.Contains(page, []byte(projectionEntityID)) || !bytes.Contains(page, []byte(hex.EncodeToString(projectionDigest))) {
		t.Fatalf("projection page=%s err=%v", page, err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_projection_page($1,$2,$3,$4,'entities',NULL,500)`, scopes[0][0], scopes[0][1], scopes[0][2], projectionSnapshotID).Scan(&page); err == nil {
		t.Fatal("API executed recovery projection page")
	}
	var restoredScope []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_validate_scope($1,$2,$3)`, scopes[0][0], scopes[0][1], scopes[0][2]).Scan(&restoredScope); err != nil || !bytes.Contains(restoredScope, []byte(`"counts"`)) || !bytes.Contains(restoredScope, []byte(`"evidence_samples": []`)) || !bytes.Contains(restoredScope, []byte(`"projection"`)) || bytes.Contains(restoredScope, []byte(integrationIDs[1])) {
		t.Fatalf("restored scope=%s err=%v", restoredScope, err)
	}
	manifest := []byte(`{"reference":"s3://zasp-evidence/organizations/pid_7b000001-0000-4000-8000-000000000001/workspaces/pid_7b000002-0000-4000-8000-000000000002/environments/pid_7b000003-0000-4000-8000-000000000003/artifacts/pid_7b000020-0000-4000-8000-000000000020","version_id":"version-27","sha256":"2727272727272727272727272727272727272727272727272727272727272727","size_bytes":2048,"media_type":"application/vnd.zasp.recovery-manifest+json","schema":"recovery_signed_manifest_v1","signing_key_id":"123e4567-e89b-42d3-a456-426614174000","signature":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`)
	var finished []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_finish_backup($1,$2,$3,$4,$5,$6,$7::jsonb)`, scopes[0][0], scopes[0][1], scopes[0][2], backupID, workerID, operationToken, manifest).Scan(&finished); err != nil || !bytes.Contains(finished, []byte(`"state": "succeeded"`)) {
		t.Fatalf("finish backup=%s err=%v", finished, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET display_name='released' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], integrationIDs[0]); err != nil {
		t.Fatalf("released tenant mutation: %v", err)
	}

	restoreID := "pid_7b000022-0000-4000-8000-000000000022"
	restoreDigest := bytes.Repeat([]byte{0x34}, 32)
	var createdRestore []byte
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, scopes[0][0], scopes[0][1], scopes[0][2], "pid_7b000010-0000-4000-8000-000000000010", "recovery-restore-key-0001", restoreID, "recovery-e2e-01", "pid_7b000034-0000-4000-8000-000000000034", "pid_7b000035-0000-4000-8000-000000000035", "pid_7b000036-0000-4000-8000-000000000036", restoreDigest, manifest, bytes.Repeat([]byte{0x27}, 32)).Scan(&createdRestore); err != nil || !bytes.Contains(createdRestore, []byte(`"target_environment": "recovery-e2e-01"`)) || !bytes.Contains(createdRestore, []byte(`"manifest"`)) {
		t.Fatalf("create restore=%s err=%v", createdRestore, err)
	}
	var readRestore []byte
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_get_restore($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], restoreID).Scan(&readRestore); err != nil || !bytes.Contains(readRestore, []byte(`"target_environment": "recovery-e2e-01"`)) || !bytes.Contains(readRestore, []byte(`"manifest"`)) {
		t.Fatalf("read restore=%s err=%v", readRestore, err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, scopes[0][0], scopes[0][1], scopes[0][2], "pid_7b000010-0000-4000-8000-000000000010", "recovery-restore-key-0002", "pid_7b000023-0000-4000-8000-000000000023", "production", "pid_7b000037-0000-4000-8000-000000000037", "pid_7b000038-0000-4000-8000-000000000038", "pid_7b000039-0000-4000-8000-000000000039", bytes.Repeat([]byte{0x35}, 32), manifest, bytes.Repeat([]byte{0x27}, 32)).Scan(&rejected); err == nil {
		t.Fatal("production restore target accepted")
	}
	foreignManifest := bytes.Replace(manifest, []byte(scopes[0][0]), []byte(scopes[1][0]), 1)
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, scopes[0][0], scopes[0][1], scopes[0][2], "pid_7b000010-0000-4000-8000-000000000010", "recovery-restore-key-0003", "pid_7b000024-0000-4000-8000-000000000024", "recovery-e2e-02", "pid_7b00003a-0000-4000-8000-00000000003a", "pid_7b00003b-0000-4000-8000-00000000003b", "pid_7b00003c-0000-4000-8000-00000000003c", bytes.Repeat([]byte{0x36}, 32), foreignManifest, bytes.Repeat([]byte{0x27}, 32)).Scan(&rejected); err == nil {
		t.Fatal("foreign manifest authority accepted")
	}

	restoreToken := bytes.Repeat([]byte{0x37}, 32)
	var claimedRestore []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_claim_operation('restore',$1,$2,30,1)`, workerID, restoreToken).Scan(&claimedRestore); err != nil || !bytes.Contains(claimedRestore, []byte(restoreID)) || !bytes.Contains(claimedRestore, []byte(`"target_environment": "recovery-e2e-01"`)) {
		t.Fatalf("restore claim=%s err=%v", claimedRestore, err)
	}
	checkpoint := func(from, to string, evidence []byte) {
		t.Helper()
		var result []byte
		if err := worker.QueryRow(ctx, `SELECT zasp_recovery_checkpoint_restore($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, scopes[0][0], scopes[0][1], scopes[0][2], restoreID, workerID, restoreToken, from, to, evidence).Scan(&result); err != nil || !bytes.Contains(result, []byte(`"state": "`+to+`"`)) {
			t.Fatalf("checkpoint %s->%s=%s err=%v", from, to, result, err)
		}
	}
	validationArtifact := []byte(`{"reference":"s3://zasp-evidence/organizations/pid_7b000001-0000-4000-8000-000000000001/workspaces/pid_7b000002-0000-4000-8000-000000000002/environments/pid_7b000003-0000-4000-8000-000000000003/artifacts/pid_7b000025-0000-4000-8000-000000000025","version_id":"version-validation-27","sha256":"3737373737373737373737373737373737373737373737373737373737373737","size_bytes":128,"media_type":"application/json","schema":"recovery_validation_v1"}`)
	cleanupArtifact := []byte(`{"reference":"s3://zasp-evidence/organizations/pid_7b000001-0000-4000-8000-000000000001/workspaces/pid_7b000002-0000-4000-8000-000000000002/environments/pid_7b000003-0000-4000-8000-000000000003/artifacts/pid_7b000026-0000-4000-8000-000000000026","version_id":"version-cleanup-27","sha256":"3838383838383838383838383838383838383838383838383838383838383838","size_bytes":128,"media_type":"application/json","schema":"recovery_cleanup_v1"}`)
	observed := []byte(`{"assets":3,"findings":2,"policies":1}`)
	validation := []byte(`{"state":"validated","expected_counts":{"assets":3,"findings":2,"policies":1},"observed_counts":{"assets":3,"findings":2,"policies":1},"evidence":` + string(validationArtifact) + `}`)
	cleanup := []byte(`{"state":"deleted","evidence":` + string(cleanupArtifact) + `}`)
	checkpoint("verifying", "provisioning", []byte(`{"state":"verified"}`))
	checkpoint("provisioning", "validating", []byte(`{"state":"provisioned"}`))
	checkpoint("validating", "rebuilding", validation)
	checkpoint("rebuilding", "cleanup_required", []byte(`{"state":"rebuilt"}`))
	checkpoint("cleanup_required", "cleaning", []byte(`{"state":"cleanup_started"}`))
	badValidation := bytes.Replace(validation, []byte(`"assets":3`), []byte(`"assets":4`), 1)
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_finish_restore($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb)`, scopes[0][0], scopes[0][1], scopes[0][2], restoreID, workerID, restoreToken, observed, badValidation, cleanup).Scan(&rejected); err == nil {
		t.Fatal("restore expected/observed count drift accepted")
	}
	var finishedRestore []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_finish_restore($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb)`, scopes[0][0], scopes[0][1], scopes[0][2], restoreID, workerID, restoreToken, observed, validation, cleanup).Scan(&finishedRestore); err != nil || !bytes.Contains(finishedRestore, []byte(`"state": "succeeded"`)) {
		t.Fatalf("finish restore=%s err=%v", finishedRestore, err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_recovery_get_restore($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], restoreID).Scan(&readRestore); err != nil || !bytes.Contains(readRestore, []byte(`"observed_counts"`)) || !bytes.Contains(readRestore, []byte(`"cleanup_evidence"`)) {
		t.Fatalf("completed restore=%s err=%v", readRestore, err)
	}

	createBackup(scopes[0], "pid_7b000021-0000-4000-8000-000000000021", "recovery-backup-key-0002", 0x29)
	createBackup(scopes[1], "pid_7c000021-0000-4000-8000-000000000021", "recovery-backup-key-0003", 0x30)
	operationToken = bytes.Repeat([]byte{0x33}, 32)
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_claim_operation('backup',$1,$2,30,2)`, workerID, operationToken).Scan(&claimedOperation); err != nil {
		t.Fatalf("fair operation claim: %v", err)
	}
	var operationEnvelope struct {
		Items []struct {
			OrganizationID string `json:"organization_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(claimedOperation, &operationEnvelope); err != nil || len(operationEnvelope.Items) != 2 || operationEnvelope.Items[0].OrganizationID == operationEnvelope.Items[1].OrganizationID {
		t.Fatalf("fair operation envelope=%s err=%v", claimedOperation, err)
	}
	exhaustedBackupID := "pid_7b000021-0000-4000-8000-000000000021"
	if _, err := connection.Exec(ctx, `UPDATE zasp_recovery_backups SET state='retryable',attempt=100,available_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,backup_id)=($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], exhaustedBackupID); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_claim_operation('backup',$1,$2,30,1)`, workerID, bytes.Repeat([]byte{0x39}, 32)).Scan(&claimedOperation); err != nil {
		t.Fatal(err)
	}
	var exhaustedState, exhaustedCode string
	if err := connection.QueryRow(ctx, `SELECT state,error_code FROM zasp_recovery_backups WHERE (organization_id,workspace_id,environment_id,backup_id)=($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], exhaustedBackupID).Scan(&exhaustedState, &exhaustedCode); err != nil || exhaustedState != "failed" || exhaustedCode != "exhausted" || bytes.Contains(claimedOperation, []byte(exhaustedBackupID)) {
		t.Fatalf("exhausted backup state=%q code=%q claim=%s err=%v", exhaustedState, exhaustedCode, claimedOperation, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_recovery_outbox SET state='retryable',attempt=100,available_at=transaction_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE organization_id=$1 AND topic='recovery-backup-jobs' AND state='pending'`, scopes[0][0]); err != nil {
		t.Fatal(err)
	}
	if err := outbox.QueryRow(ctx, `SELECT zasp_recovery_claim_outbox('recovery-backup-jobs','recovery-outbox-worker',$1,30,1)`, bytes.Repeat([]byte{0x3a}, 32)).Scan(&claimedOutbox); err != nil {
		t.Fatal(err)
	}
	var exhaustedOutbox int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_recovery_outbox WHERE organization_id=$1 AND topic='recovery-backup-jobs' AND attempt=100 AND state='exhausted'`, scopes[0][0]).Scan(&exhaustedOutbox); err != nil || exhaustedOutbox != 1 {
		t.Fatalf("exhausted outbox=%d claim=%s err=%v", exhaustedOutbox, claimedOutbox, err)
	}
}
