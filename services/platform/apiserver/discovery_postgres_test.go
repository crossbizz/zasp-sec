package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrateToProductionDiscovery(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance, runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	return runner
}

func TestProductionDiscoveryPostgresFreshUpgradeRestartDriftAndGuardedDown(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner := migrateToProductionDiscovery(t, ctx, connection)
	if version, err := runner.Version(ctx); err != nil || version != 10 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	fingerprintQuery := postgresSchemaVersionSQL[:strings.Index(postgresSchemaVersionSQL, "SELECT metadata.value")] + "SELECT value FROM semantic_fingerprint"
	var actualFingerprint string
	if err := connection.QueryRow(ctx, fingerprintQuery).Scan(&actualFingerprint); err != nil {
		t.Fatal(err)
	}
	if actualFingerprint != migrations.ProductionDiscoverySemanticFingerprint() {
		t.Fatalf("v10 semantic fingerprint=%q marker=%q", actualFingerprint, migrations.ProductionDiscoverySemanticFingerprint())
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_readiness($1,$2)`, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("readiness=%v err=%v", ready, err)
	}
	var canonical1, canonical2 string
	args := []any{"pid_10000001-0000-4000-8000-000000000001", "pid_10000002-0000-4000-8000-000000000002", "pid_10000003-0000-4000-8000-000000000003", "aws_account", "123456789012"}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,$4,$5),zasp_discovery_canonical_id($1,$2,$3,$4,$5)`, args...).Scan(&canonical1, &canonical2); err != nil || canonical1 != canonical2 || !strings.HasPrefix(canonical1, "pid_") {
		t.Fatalf("canonical=%q/%q err=%v", canonical1, canonical2, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	connection, err = pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, _ = migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if version, err := runner.Version(ctx); err != nil || version != 10 {
		t.Fatalf("restart version=%d err=%v", version, err)
	}
	if err := runner.UpProductionDiscovery(ctx); err == nil {
		t.Fatal("reapply unexpectedly succeeded")
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_integrations ADD COLUMN hostile_drift text`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionDiscovery(ctx); err == nil {
		t.Fatal("semantic drift did not block down")
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_integrations DROP COLUMN hostile_drift`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionDiscovery(ctx); err != nil {
		t.Fatalf("empty guarded down: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 9 {
		t.Fatalf("down version=%d err=%v", version, err)
	}
}

func TestProductionDiscoveryPostgresAtomicSnapshotReplayIsolationLeaseAndGateway(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrateToProductionDiscovery(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if _, err := NewPostgresRepository(database); err != nil {
		t.Fatalf("v9 repository compatibility on v10: %v", err)
	}
	repository, err := newDiscoveryRepositoryUnchecked(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	integrationID := "pid_41000001-0000-4000-8000-000000000001"
	if _, err := repository.CreateIntegration(ctx, identity, IntegrationCreate{ID: integrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "AWS", Configuration: json.RawMessage(`{"role_reference":"ref:aws/role/prod0001"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionIntegration(ctx, scope, IntegrationTransition{ID: integrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("sync-one"))
	request := SyncRequest{IntegrationID: integrationID, SyncID: "pid_41000002-0000-4000-8000-000000000002", JobID: "pid_41000003-0000-4000-8000-000000000003", OutboxID: "pid_41000004-0000-4000-8000-000000000004", IdempotencyKey: "sync-idempotency-0001", RequestDigest: digest[:], TriggerKind: "manual", ParserVersion: "1.0.0", ToolVersion: "1.0.0"}
	secondConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConnection.Close(ctx)
	secondDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: secondConnection})
	secondRepository, err := newDiscoveryRepositoryUnchecked(secondDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondConnection.Exec(ctx, `SET TIME ZONE 'Asia/Kolkata'`); err != nil {
		t.Fatal(err)
	}
	results := make([]SyncRequestResult, 2)
	requestErrors := make([]error, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index, current := range []*DiscoveryRepository{repository, secondRepository} {
		group.Add(1)
		go func(index int, current *DiscoveryRepository) {
			defer group.Done()
			<-start
			results[index], requestErrors[index] = current.RequestDiscoverySync(ctx, identity, request)
		}(index, current)
	}
	close(start)
	group.Wait()
	if requestErrors[0] != nil || requestErrors[1] != nil || results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent replay=%#v errors=%v", results, requestErrors)
	}
	var syncs, jobs, outbox int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_discovery_syncs),(SELECT count(*) FROM zasp_discovery_jobs),(SELECT count(*) FROM zasp_discovery_outbox)`).Scan(&syncs, &jobs, &outbox); err != nil || syncs != 1 || jobs != 1 || outbox != 1 {
		t.Fatalf("residue=%d/%d/%d err=%v", syncs, jobs, outbox, err)
	}
	entityID, err := CanonicalDiscoveryID(scope, "aws_account", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	var databaseCanonical string
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'aws_account','123456789012')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&databaseCanonical); err != nil || databaseCanonical != entityID {
		t.Fatalf("canonical=%q/%q err=%v", entityID, databaseCanonical, err)
	}
	candidate := CompleteSnapshot{IntegrationID: integrationID, SyncID: request.SyncID, SnapshotID: "pid_41000005-0000-4000-8000-000000000005", Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/exact/manifest-1.json", ManifestChecksum: make([]byte, 32), CollectedAt: time.Now().UTC(), CursorProvider: "aws", CursorValue: "cursor-1", Entities: json.RawMessage(`[{"id":"` + entityID + `","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}]`), Relationships: json.RawMessage(`[]`), Evidence: json.RawMessage(`[]`)}
	firstApply, err := repository.ApplyCompleteSnapshot(ctx, scope, candidate)
	if err != nil || firstApply.SnapshotID != candidate.SnapshotID {
		t.Fatalf("snapshot=%#v err=%v", firstApply, err)
	}
	replayResults := make([]SnapshotApplyResult, 2)
	replayErrors := make([]error, 2)
	replayStart := make(chan struct{})
	group = sync.WaitGroup{}
	for index, current := range []*DiscoveryRepository{repository, secondRepository} {
		group.Add(1)
		go func(index int, current *DiscoveryRepository) {
			defer group.Done()
			<-replayStart
			replayResults[index], replayErrors[index] = current.ApplyCompleteSnapshot(ctx, scope, candidate)
		}(index, current)
	}
	close(replayStart)
	group.Wait()
	if replayErrors[0] != nil || replayErrors[1] != nil || replayResults[0] != firstApply || replayResults[1] != firstApply {
		t.Fatalf("snapshot replay=%#v errors=%v first=%#v", replayResults, replayErrors, firstApply)
	}
	var entityVersion int64
	if err := connection.QueryRow(ctx, `SELECT version FROM zasp_inventory_entities WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), entityID).Scan(&entityVersion); err != nil || entityVersion != 1 {
		t.Fatalf("snapshot replay churn version=%d err=%v", entityVersion, err)
	}
	foreignEnvironment := "pid_99999999-0000-4999-8999-999999999999"
	var foreignPage []byte
	var foreignCanonical string
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_entity_page($1,$2,$3,NULL,100)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), foreignEnvironment).Scan(&foreignPage); err != nil || strings.Contains(string(foreignPage), entityID) {
		t.Fatalf("foreign page=%s err=%v", foreignPage, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'aws_account','123456789012')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), foreignEnvironment).Scan(&foreignCanonical); err != nil || foreignCanonical == entityID {
		t.Fatalf("foreign canonical=%q err=%v", foreignCanonical, err)
	}
	for _, pageID := range []string{"pid_b0000001-0000-4000-8000-000000000001", "pid_c0000001-0000-4000-8000-000000000001", "pid_d0000001-0000-4000-8000-000000000001"} {
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,'test','Page row',transaction_timestamp(),transaction_timestamp())`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), pageID); err != nil {
			t.Fatal(err)
		}
	}
	firstPage, err := repository.ListInventoryEntityPage(ctx, scope, "", 2)
	if err != nil || len(firstPage.Items) != 2 || firstPage.NextID == "" {
		t.Fatalf("stable first page=%#v err=%v", firstPage, err)
	}
	if _, err := connection.Exec(ctx, `DELETE FROM zasp_inventory_entities WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id='pid_c0000001-0000-4000-8000-000000000001'`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,first_seen_at,last_seen_at) VALUES($1,$2,$3,'pid_f0000001-0000-4000-8000-000000000001','test','Inserted row',transaction_timestamp(),transaction_timestamp())`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	last := ""
	for _, item := range firstPage.Items {
		seen[item.ID] = true
		last = item.ID
	}
	cursor := firstPage.NextID
	for cursor != "" {
		page, err := repository.ListInventoryEntityPage(ctx, scope, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if seen[item.ID] || item.ID <= last {
				t.Fatalf("unstable keyset id=%s last=%s", item.ID, last)
			}
			seen[item.ID] = true
			last = item.ID
		}
		cursor = page.NextID
	}
	if !seen["pid_f0000001-0000-4000-8000-000000000001"] {
		t.Fatal("insert after cursor was starved")
	}
	secondIntegrationID := "pid_42000001-0000-4000-8000-000000000001"
	if _, err := repository.CreateIntegration(ctx, identity, IntegrationCreate{ID: secondIntegrationID, Kind: "aws", ConnectorVersion: "1.0.0", DisplayName: "AWS secondary", Configuration: json.RawMessage(`{"role_reference":"ref:aws/role/prod0002"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionIntegration(ctx, scope, IntegrationTransition{ID: secondIntegrationID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	wrongParentSnapshot := "pid_42000002-0000-4000-8000-000000000002"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,candidate_digest,state,complete,collected_at) VALUES($1,$2,$3,$4,$5,$6,1,'aws','s3://zasp-evidence/exact/wrong.json',$7,$7,'candidate',false,transaction_timestamp())`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), wrongParentSnapshot, secondIntegrationID, request.SyncID, make([]byte, 32)); err == nil {
		t.Fatal("wrong-integration sync parent unexpectedly accepted")
	}
	var wrongParentRows int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_discovery_snapshots WHERE id=$1`, wrongParentSnapshot).Scan(&wrongParentRows); err != nil || wrongParentRows != 0 {
		t.Fatalf("wrong-parent residue=%d err=%v", wrongParentRows, err)
	}
	secondDigest := sha256.Sum256([]byte("sync-two"))
	secondRequest := SyncRequest{IntegrationID: integrationID, SyncID: "pid_42000003-0000-4000-8000-000000000003", JobID: "pid_42000004-0000-4000-8000-000000000004", OutboxID: "pid_42000005-0000-4000-8000-000000000005", IdempotencyKey: "sync-idempotency-0002", RequestDigest: secondDigest[:], TriggerKind: "manual", ParserVersion: "1.0.0", ToolVersion: "1.0.0"}
	if _, err := repository.RequestDiscoverySync(ctx, identity, secondRequest); err != nil {
		t.Fatal(err)
	}
	invalidCandidate := candidate
	invalidCandidate.SyncID = secondRequest.SyncID
	invalidCandidate.SnapshotID = "pid_42000006-0000-4000-8000-000000000006"
	invalidCandidate.Generation = 2
	invalidCandidate.CursorValue = "cursor-2"
	invalidCandidate.Entities = json.RawMessage(`[{"id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff","kind":"aws_account","source_native_id":"123456789012","display_name":"Hostile","stable_fields":{},"attributes":{}}]`)
	if _, err := repository.ApplyCompleteSnapshot(ctx, scope, invalidCandidate); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("invalid candidate error=%v", err)
	}
	var lastGood, cursorValue, syncState string
	if err := connection.QueryRow(ctx, `SELECT (SELECT id FROM zasp_discovery_snapshots WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND is_last_good),(SELECT cursor_value FROM zasp_discovery_cursors WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND provider='aws'),(SELECT state FROM zasp_discovery_syncs WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID, secondRequest.SyncID).Scan(&lastGood, &cursorValue, &syncState); err != nil || lastGood != candidate.SnapshotID || cursorValue != "cursor-1" || syncState != "queued" {
		t.Fatalf("last-good=%s cursor=%s sync=%s err=%v", lastGood, cursorValue, syncState, err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,'aws',$5,'foreign-native',$6,'present','{}',transaction_timestamp(),transaction_timestamp())`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), secondIntegrationID, entityID, candidate.SnapshotID); err == nil {
		t.Fatal("wrong-integration observation snapshot unexpectedly accepted")
	}
	claims, err := repository.ClaimOutbox(ctx, "worker-a", "lease-token-00000001", 30, 10)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%#v err=%v", claims, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_outbox SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE id=$1`, request.OutboxID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := repository.ClaimOutbox(ctx, "worker-b", "lease-token-00000002", 30, 10)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Attempt != 2 {
		t.Fatalf("reclaim=%#v err=%v", reclaimed, err)
	}
	if err := repository.AcknowledgeOutbox(ctx, scope, request.OutboxID, "worker-a", "lease-token-00000001", "wrong-owner"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("wrong-owner ack=%v", err)
	}
	if err := repository.RetryOutbox(ctx, scope, request.OutboxID, "worker-a", "lease-token-00000001", 5, "expired owner"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("expired-owner retry=%v", err)
	}
	if err := repository.AcknowledgeOutbox(ctx, scope, request.OutboxID, "worker-b", "lease-token-00000002", "provider-ack-1"); err != nil {
		t.Fatal(err)
	}
	var jobClaim1, jobClaim2 []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_claim_jobs('job-worker-a','job-lease-token-0001',30,10,'discovery')`).Scan(&jobClaim1); err != nil || !strings.Contains(string(jobClaim1), request.JobID) {
		t.Fatalf("job claim=%s err=%v", jobClaim1, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_discovery_jobs SET updated_at=created_at,lease_expires_at=created_at+interval '1 microsecond' WHERE id=$1`, request.JobID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_claim_jobs('job-worker-b','job-lease-token-0002',30,10,'discovery')`).Scan(&jobClaim2); err != nil || !strings.Contains(string(jobClaim2), request.JobID) {
		t.Fatalf("job reclaim=%s err=%v", jobClaim2, err)
	}
	if _, err := repository.FinishDiscoveryJob(ctx, scope, DiscoveryJobCompletion{ID: request.JobID, Worker: "job-worker-a", LeaseToken: "job-lease-token-0001", Outcome: "failed", LastError: "expired owner"}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("expired-owner job completion=%v", err)
	}
	scheduleID := "pid_42000007-0000-4000-8000-000000000007"
	if _, err := repository.PutDiscoverySchedule(ctx, scope, DiscoverySchedulePut{ID: scheduleID, IntegrationID: integrationID, CadenceSeconds: 300, NextRunAt: time.Now().UTC().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var scheduleClaim []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_claim_schedules('schedule-worker','schedule-token-00001',30,10)`).Scan(&scheduleClaim); err != nil || !strings.Contains(string(scheduleClaim), scheduleID) {
		t.Fatalf("schedule claim=%s err=%v", scheduleClaim, err)
	}
	var projectionClaim []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_claim_projection_work('projection-worker','projection-token-001',30,10)`).Scan(&projectionClaim); err != nil || !strings.Contains(string(projectionClaim), candidate.SnapshotID) {
		t.Fatalf("projection claim=%s err=%v", projectionClaim, err)
	}

	deviceID := "pid_41000006-0000-4000-8000-000000000006"
	enrollmentID := "pid_41000007-0000-4000-8000-000000000007"
	credentialID := "pid_41000008-0000-4000-8000-000000000008"
	tokenHash := sha256.Sum256([]byte("gateway-token"))
	if _, err := repository.CreateGatewayDevice(ctx, scope, GatewayDeviceCreate{ID: deviceID, Name: "Gateway"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.IssueGatewayEnrollmentToken(ctx, scope, GatewayEnrollmentTokenIssue{ID: enrollmentID, DeviceID: deviceID, Salt: make([]byte, 16), TokenHash: tokenHash[:], ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	enrollment := GatewayEnrollment{DeviceID: deviceID, EnrollmentID: enrollmentID, CredentialID: credentialID, Audience: "runtime-gateway", KeyReference: "ref:kms/gateway/key-0001", TokenHash: tokenHash[:], Salt: make([]byte, 16), PublicKey: make([]byte, 32), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if record, err := repository.EnrollGateway(ctx, scope, enrollment); err != nil || record.ID != credentialID {
		t.Fatalf("gateway=%#v err=%v", record, err)
	}
	if replayed, err := repository.EnrollGateway(ctx, scope, enrollment); err != nil || replayed.ID != credentialID {
		t.Fatalf("enrollment replay=%#v err=%v", replayed, err)
	}
	conflictingEnrollment := enrollment
	conflictingEnrollment.PublicKey = []byte(strings.Repeat("x", 32))
	if _, err := repository.EnrollGateway(ctx, scope, conflictingEnrollment); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("enrollment conflict=%v", err)
	}
	if err := repository.AdvanceGatewayReplay(ctx, scope, deviceID, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := repository.AdvanceGatewayReplay(ctx, scope, deviceID, 0, 1); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("gateway replay floor=%v", err)
	}
	replacementID := "pid_41000012-0000-4000-8000-000000000012"
	rotation := GatewayCredentialRotation{DeviceID: deviceID, CurrentCredentialID: credentialID, ReplacementCredentialID: replacementID, KeyReference: "ref:kms/gateway/key-rotated", PublicKey: bytes.Repeat([]byte{2}, 32), ExpiresAt: time.Now().UTC().Add(2 * time.Hour)}
	if rotated, err := repository.RotateGatewayCredential(ctx, scope, rotation); err != nil || rotated.ID != replacementID {
		t.Fatalf("gateway rotation=%#v err=%v", rotated, err)
	}
	if replayed, err := repository.RotateGatewayCredential(ctx, scope, rotation); err != nil || replayed.ID != replacementID {
		t.Fatalf("gateway rotation replay=%#v err=%v", replayed, err)
	}
	if err := repository.RevokeGatewayCredential(ctx, scope, deviceID, replacementID); err != nil {
		t.Fatal(err)
	}
	policy := GatewayPolicySubscription{DeviceID: deviceID, PolicyID: "pid_41000013-0000-4000-8000-000000000013", PolicyVersion: 1, PolicyDigest: make([]byte, 32), Signature: bytes.Repeat([]byte{3}, 64), IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), Sequence: 2}
	if err := repository.PutGatewayPolicySubscription(ctx, scope, policy); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutGatewayPolicySubscription(ctx, scope, policy); err != nil {
		t.Fatalf("policy replay=%v", err)
	}
	stalePolicy := policy
	stalePolicy.Sequence = 1
	if err := repository.PutGatewayPolicySubscription(ctx, scope, stalePolicy); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("stale policy=%v", err)
	}
	foreignDevice := "pid_41000009-0000-4000-8000-000000000009"
	if _, err := repository.CreateGatewayDevice(ctx, scope, GatewayDeviceCreate{ID: foreignDevice, Name: "Foreign"}); err != nil {
		t.Fatal(err)
	}
	foreignEnrollment := "pid_41000011-0000-4000-8000-000000000011"
	if _, err := repository.IssueGatewayEnrollmentToken(ctx, scope, GatewayEnrollmentTokenIssue{ID: foreignEnrollment, DeviceID: foreignDevice, Salt: make([]byte, 16), TokenHash: sha256.New().Sum(nil), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,rotated_from_id) VALUES($1,$2,$3,'pid_41000010-0000-4000-8000-000000000010',$4,$5,$6,'runtime-gateway','ref:kms/gateway/key-0002',$7,transaction_timestamp()+interval '1 hour',$8)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), foreignDevice, foreignEnrollment, make([]byte, 32), make([]byte, 32), credentialID); err == nil {
		t.Fatal("wrong-device rotation unexpectedly succeeded")
	}
	sensorOne := "pid_43000001-0000-4000-8000-000000000001"
	sensorTwo := "pid_43000002-0000-4000-8000-000000000002"
	sensorToken := "pid_43000003-0000-4000-8000-000000000003"
	if _, err := repository.CreateSensor(ctx, scope, SensorCreate{ID: sensorOne, Name: "one", Kind: "otlp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateSensor(ctx, scope, SensorCreate{ID: sensorTwo, Name: "two", Kind: "otlp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.IssueSensorToken(ctx, scope, SensorTokenIssue{SensorID: sensorOne, TokenID: sensorToken, Salt: make([]byte, 16), TokenHash: make([]byte, 32), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rotatedSensorToken := "pid_43000005-0000-4000-8000-000000000005"
	sensorRotation := SensorTokenRotation{SensorID: sensorOne, CurrentTokenID: sensorToken, ReplacementTokenID: rotatedSensorToken, Salt: bytes.Repeat([]byte{4}, 16), TokenHash: bytes.Repeat([]byte{5}, 32), ExpiresAt: time.Now().UTC().Add(2 * time.Hour)}
	if record, err := repository.RotateSensorToken(ctx, scope, sensorRotation); err != nil || record.ID != rotatedSensorToken {
		t.Fatalf("sensor rotation=%#v err=%v", record, err)
	}
	if record, err := repository.RotateSensorToken(ctx, scope, sensorRotation); err != nil || record.ID != rotatedSensorToken {
		t.Fatalf("sensor rotation replay=%#v err=%v", record, err)
	}
	conflictingSensorRotation := sensorRotation
	conflictingSensorRotation.ExpiresAt = conflictingSensorRotation.ExpiresAt.Add(time.Minute)
	if _, err := repository.RotateSensorToken(ctx, scope, conflictingSensorRotation); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("sensor rotation conflict=%v", err)
	}
	heartbeat := SensorHeartbeat{SensorID: sensorOne, Sequence: 1, Status: "healthy", DroppedEvents: 0, Metadata: json.RawMessage(`{"agent_version":"1.0.0"}`)}
	if err := repository.RecordSensorHeartbeat(ctx, scope, heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordSensorHeartbeat(ctx, scope, heartbeat); err != nil {
		t.Fatalf("heartbeat replay=%v", err)
	}
	conflictingHeartbeat := heartbeat
	conflictingHeartbeat.Status = "degraded"
	if err := repository.RecordSensorHeartbeat(ctx, scope, conflictingHeartbeat); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("heartbeat conflict=%v", err)
	}
	runtimeDigest := sha256.Sum256([]byte("runtime-batch"))
	runtimeBatch := RuntimeBatchCreate{SensorID: sensorOne, BatchID: "pid_43000006-0000-4000-8000-000000000006", JobID: "pid_43000007-0000-4000-8000-000000000007", OutboxID: "pid_43000008-0000-4000-8000-000000000008", IdempotencyKey: "runtime-batch-key-0001", PayloadDigest: runtimeDigest[:], EventCount: 2, ObjectReference: "s3://zasp-runtime/exact/batch.jsonl", PayloadBytes: 256, MediaType: "application/x-ndjson", SchemaVersion: "runtime-event-v1"}
	if result, err := repository.CreateRuntimeBatch(ctx, scope, runtimeBatch); err != nil || result.Replayed {
		t.Fatalf("runtime batch=%#v err=%v", result, err)
	}
	if result, err := repository.CreateRuntimeBatch(ctx, scope, runtimeBatch); err != nil || !result.Replayed {
		t.Fatalf("runtime batch replay=%#v err=%v", result, err)
	}
	stage := RuntimeStageCompletion{BatchID: runtimeBatch.BatchID, Stage: "archive", InputDigest: runtimeDigest[:], Succeeded: true, ResultReference: "s3://zasp-runtime/exact/batch.json"}
	if err := repository.CompleteRuntimeStage(ctx, scope, stage); err != nil {
		t.Fatal(err)
	}
	if err := repository.CompleteRuntimeStage(ctx, scope, stage); err != nil {
		t.Fatalf("runtime stage replay=%v", err)
	}
	conflictingStage := stage
	conflictingStage.ResultReference = "s3://zasp-runtime/exact/other.json"
	if err := repository.CompleteRuntimeStage(ctx, scope, conflictingStage); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("runtime stage conflict=%v", err)
	}
	evidenceID := "pid_43000009-0000-4000-8000-000000000009"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7,'s3://zasp-evidence/exact/entity.json',$8,'application/json','1','1',transaction_timestamp())`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), evidenceID, integrationID, candidate.SnapshotID, entityID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if evidence, err := repository.GetInventoryEvidence(ctx, scope, evidenceID); err != nil || evidence.ID != evidenceID {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at,rotated_from_id) VALUES($1,$2,$3,'pid_43000004-0000-4000-8000-000000000004',$4,$5,$6,transaction_timestamp()+interval '1 hour',$7)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorTwo, make([]byte, 16), bytes.Repeat([]byte{1}, 32), sensorToken); err == nil {
		t.Fatal("wrong-sensor rotation unexpectedly succeeded")
	}
}
