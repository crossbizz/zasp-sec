package apiserver

import (
	"bytes"
	"context"
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
	manifest := []byte(`{"schema_version":"recovery_signed_manifest_v1","signing_key_arn":"arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-42d3-a456-426614174000","payload":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`)
	var finished []byte
	if err := worker.QueryRow(ctx, `SELECT zasp_recovery_finish_backup($1,$2,$3,$4,$5,$6,$7::jsonb)`, scopes[0][0], scopes[0][1], scopes[0][2], backupID, workerID, operationToken, manifest).Scan(&finished); err != nil || !bytes.Contains(finished, []byte(`"state": "succeeded"`)) {
		t.Fatalf("finish backup=%s err=%v", finished, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_integrations SET display_name='released' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, scopes[0][0], scopes[0][1], scopes[0][2], integrationIDs[0]); err != nil {
		t.Fatalf("released tenant mutation: %v", err)
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
}
