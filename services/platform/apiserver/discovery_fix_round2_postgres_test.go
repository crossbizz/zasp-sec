package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestProductionDiscoveryRuntimeBatchPersistsImmutableDurableEnvelope(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	sensorID := "pid_71000001-0000-4000-8000-000000000001"
	if _, err := fixture.repository.CreateSensor(fixture.ctx, fixture.scope, SensorCreate{ID: sensorID, Name: "Runtime", Kind: "tetragon"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionSensor(fixture.ctx, fixture.scope, IntegrationTransition{ID: sensorID, ExpectedVersion: 1, State: "active"}); err != nil {
		t.Fatal(err)
	}
	input := RuntimeBatchCreate{
		SensorID: sensorID, BatchID: "pid_71000002-0000-4000-8000-000000000002",
		JobID: "pid_71000003-0000-4000-8000-000000000003", OutboxID: "pid_71000004-0000-4000-8000-000000000004",
		IdempotencyKey: "runtime-envelope-0001", PayloadDigest: bytes32(71), EventCount: 2,
		ObjectReference: "s3://zasp-runtime/scoped/normalized-0001.jsonl", PayloadBytes: 4096,
		MediaType: "application/x-ndjson", SchemaVersion: "runtime-event-v1",
	}
	created, err := fixture.repository.CreateRuntimeBatch(fixture.ctx, fixture.scope, input)
	if err != nil || created.BatchID != input.BatchID || created.Replayed {
		t.Fatalf("create runtime envelope=%#v err=%v", created, err)
	}
	replayed, err := fixture.repository.CreateRuntimeBatch(fixture.ctx, fixture.scope, input)
	if err != nil || !replayed.Replayed {
		t.Fatalf("replay runtime envelope=%#v err=%v", replayed, err)
	}
	conflict := input
	conflict.ObjectReference = "s3://zasp-runtime/scoped/changed.jsonl"
	if _, err := fixture.repository.CreateRuntimeBatch(fixture.ctx, fixture.scope, conflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("changed envelope error=%v", err)
	}
	var objectReference, mediaType, schemaVersion string
	var payloadBytes int64
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT payload_reference,payload_size_bytes,payload_media_type,payload_schema_version FROM zasp_runtime_batches WHERE id=$1`, input.BatchID).Scan(&objectReference, &payloadBytes, &mediaType, &schemaVersion); err != nil {
		t.Fatal(err)
	}
	if objectReference != input.ObjectReference || payloadBytes != input.PayloadBytes || mediaType != input.MediaType || schemaVersion != input.SchemaVersion {
		t.Fatalf("stored envelope=%q/%d/%q/%q", objectReference, payloadBytes, mediaType, schemaVersion)
	}
	var outboxReference string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT payload->>'payload_reference' FROM zasp_discovery_outbox WHERE id=$1`, input.OutboxID).Scan(&outboxReference); err != nil || outboxReference != input.ObjectReference {
		t.Fatalf("outbox payload reference=%q err=%v", outboxReference, err)
	}
}

func TestProductionDiscoveryRejectsRuntimeActivityForTerminalParents(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	sensorID := "pid_72000001-0000-4000-8000-000000000001"
	if _, err := fixture.repository.CreateSensor(fixture.ctx, fixture.scope, SensorCreate{ID: sensorID, Name: "Terminal", Kind: "otlp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionSensor(fixture.ctx, fixture.scope, IntegrationTransition{ID: sensorID, ExpectedVersion: 1, State: "revoked"}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repository.RecordSensorHeartbeat(fixture.ctx, fixture.scope, SensorHeartbeat{SensorID: sensorID, Sequence: 1, Status: "healthy", Metadata: []byte(`{}`)}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("revoked sensor heartbeat error=%v", err)
	}
	if _, err := fixture.repository.IssueSensorToken(fixture.ctx, fixture.scope, SensorTokenIssue{SensorID: sensorID, TokenID: "pid_72000002-0000-4000-8000-000000000002", Salt: make([]byte, 16), TokenHash: bytes32(72), ExpiresAt: time.Now().UTC().Add(time.Hour)}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("revoked sensor token error=%v", err)
	}
	deviceID := "pid_72000003-0000-4000-8000-000000000003"
	if _, err := fixture.repository.CreateGatewayDevice(fixture.ctx, fixture.scope, GatewayDeviceCreate{ID: deviceID, Name: "Terminal"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.TransitionGatewayDevice(fixture.ctx, fixture.scope, IntegrationTransition{ID: deviceID, ExpectedVersion: 1, State: "revoked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repository.IssueGatewayEnrollmentToken(fixture.ctx, fixture.scope, GatewayEnrollmentTokenIssue{ID: "pid_72000004-0000-4000-8000-000000000004", DeviceID: deviceID, Salt: make([]byte, 16), TokenHash: bytes32(73), ExpiresAt: time.Now().UTC().Add(time.Hour)}); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("revoked device enrollment error=%v", err)
	}
}

func TestProductionDiscoveryClaimsExhaustExpiredFinalAttemptsAndPropagatesSyncState(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_73000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Recovery")
	request := fixture.requestSync(integrationID, 301)
	claims, err := fixture.repository.ClaimDiscoveryJobs(fixture.ctx, "discovery-worker", "job-lease-token-7301", "discovery", 30, 1)
	if err != nil || len(claims) != 1 || claims[0].ID != request.JobID {
		t.Fatalf("initial job claim=%#v err=%v", claims, err)
	}
	var syncState string
	var syncAttempt int
	var startedAt *time.Time
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT state,attempt,started_at FROM zasp_discovery_syncs WHERE id=$1`, request.SyncID).Scan(&syncState, &syncAttempt, &startedAt); err != nil || syncState != "running" || syncAttempt != 1 || startedAt == nil {
		t.Fatalf("running sync=%q/%d/%v err=%v", syncState, syncAttempt, startedAt, err)
	}
	if _, err := fixture.repository.FinishDiscoveryJob(fixture.ctx, fixture.scope, DiscoveryJobCompletion{ID: request.JobID, Worker: "discovery-worker", LeaseToken: "job-lease-token-7301", Outcome: "retryable", LastError: "provider timeout"}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT state,attempt FROM zasp_discovery_syncs WHERE id=$1`, request.SyncID).Scan(&syncState, &syncAttempt); err != nil || syncState != "queued" || syncAttempt != 1 {
		t.Fatalf("retryable sync=%q/%d err=%v", syncState, syncAttempt, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_discovery_jobs SET state='leased',attempt=5,lease_owner='dead-worker',lease_token='dead-lease-token-7301',lease_expires_at=created_at+interval '1 microsecond',available_at=created_at,updated_at=created_at,completion_digest=NULL,completion_result=NULL WHERE id=$1`, request.JobID); err != nil {
		t.Fatal(err)
	}
	claims, err = fixture.repository.ClaimDiscoveryJobs(fixture.ctx, "recovery-worker", "job-lease-token-7302", "discovery", 30, 1)
	if err != nil || len(claims) != 0 {
		t.Fatalf("exhausted job claim=%#v err=%v", claims, err)
	}
	var jobState string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT j.state,s.state FROM zasp_discovery_jobs j JOIN zasp_discovery_syncs s ON s.id=j.authority_id WHERE j.id=$1`, request.JobID).Scan(&jobState, &syncState); err != nil || jobState != "failed" || syncState != "failed" {
		t.Fatalf("exhausted job/sync=%q/%q err=%v", jobState, syncState, err)
	}

	projectionRequest := fixture.requestSync(integrationID, 302)
	snapshotID := "pid_73000002-0000-4000-8000-000000000002"
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{IntegrationID: integrationID, SyncID: projectionRequest.SyncID, SnapshotID: snapshotID, Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/recovery/projection.json", ManifestChecksum: bytes32(74), CollectedAt: time.Now().UTC(), CursorProvider: "aws", CursorValue: "cursor-7301", Entities: []byte(`[]`), Relationships: []byte(`[]`), Evidence: []byte(`[]`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_projection_work SET state='leased',attempt=5,lease_owner='dead-worker',lease_token='dead-lease-token-7302',lease_expires_at=transaction_timestamp()-interval '1 second',available_at=transaction_timestamp()-interval '1 second' WHERE snapshot_id=$1`, snapshotID); err != nil {
		t.Fatal(err)
	}
	projectionClaims, err := fixture.repository.ClaimProjectionWork(fixture.ctx, "recovery-worker", "projection-token-7301", 30, 3)
	if err != nil || len(projectionClaims) != 0 {
		t.Fatalf("exhausted projection claim=%#v err=%v", projectionClaims, err)
	}
	var exhaustedProjectionCount int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FROM zasp_projection_work WHERE snapshot_id=$1 AND state='failed' AND attempt=5 AND completed_at IS NOT NULL`, snapshotID).Scan(&exhaustedProjectionCount); err != nil || exhaustedProjectionCount != 3 {
		t.Fatalf("exhausted projections=%d err=%v", exhaustedProjectionCount, err)
	}
}

func TestProductionDiscoveryOutboxAttemptCapAndLostResponseReplay(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Outbox")
	ackRequest := fixture.requestSync(integrationID, 401)
	claimed, err := fixture.repository.ClaimOutbox(fixture.ctx, "outbox-worker", "outbox-lease-token-7401", 30, 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != ackRequest.OutboxID {
		t.Fatalf("ack claim=%#v err=%v", claimed, err)
	}
	if err := fixture.repository.AcknowledgeOutbox(fixture.ctx, fixture.scope, ackRequest.OutboxID, "outbox-worker", "outbox-lease-token-7401", "sqs-message-7401"); err != nil {
		t.Fatal(err)
	}
	var publishedAt time.Time
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT published_at FROM zasp_discovery_outbox WHERE id=$1`, ackRequest.OutboxID).Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repository.AcknowledgeOutbox(fixture.ctx, fixture.scope, ackRequest.OutboxID, "outbox-worker", "outbox-lease-token-7401", "sqs-message-7401"); err != nil {
		t.Fatalf("ack replay=%v", err)
	}
	var replayedPublishedAt time.Time
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT published_at FROM zasp_discovery_outbox WHERE id=$1`, ackRequest.OutboxID).Scan(&replayedPublishedAt); err != nil || !replayedPublishedAt.Equal(publishedAt) {
		t.Fatalf("ack replay timestamp=%v/%v err=%v", publishedAt, replayedPublishedAt, err)
	}
	if err := fixture.repository.AcknowledgeOutbox(fixture.ctx, fixture.scope, ackRequest.OutboxID, "outbox-worker", "outbox-lease-token-7401", "changed-ack"); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("conflicting ack=%v", err)
	}

	retryRequest := fixture.requestSync(integrationID, 402)
	claimed, err = fixture.repository.ClaimOutbox(fixture.ctx, "outbox-worker", "outbox-lease-token-7402", 30, 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != retryRequest.OutboxID {
		t.Fatalf("retry claim=%#v err=%v", claimed, err)
	}
	if err := fixture.repository.RetryOutbox(fixture.ctx, fixture.scope, retryRequest.OutboxID, "outbox-worker", "outbox-lease-token-7402", 30, "sqs timeout"); err != nil {
		t.Fatal(err)
	}
	var availableAt time.Time
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT available_at FROM zasp_discovery_outbox WHERE id=$1`, retryRequest.OutboxID).Scan(&availableAt); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repository.RetryOutbox(fixture.ctx, fixture.scope, retryRequest.OutboxID, "outbox-worker", "outbox-lease-token-7402", 30, "sqs timeout"); err != nil {
		t.Fatalf("retry replay=%v", err)
	}
	var replayedAvailableAt time.Time
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT available_at FROM zasp_discovery_outbox WHERE id=$1`, retryRequest.OutboxID).Scan(&replayedAvailableAt); err != nil || !replayedAvailableAt.Equal(availableAt) {
		t.Fatalf("retry replay timestamp=%v/%v err=%v", availableAt, replayedAvailableAt, err)
	}
	if err := fixture.repository.RetryOutbox(fixture.ctx, fixture.scope, retryRequest.OutboxID, "outbox-worker", "outbox-lease-token-7402", 31, "changed"); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("conflicting retry=%v", err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `UPDATE zasp_discovery_outbox SET state='failed',attempt=100,available_at=transaction_timestamp()-interval '1 second' WHERE id=$1`, retryRequest.OutboxID); err != nil {
		t.Fatal(err)
	}
	claimed, err = fixture.repository.ClaimOutbox(fixture.ctx, "outbox-worker", "outbox-lease-token-7403", 30, 1)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("attempt-cap claim=%#v err=%v", claimed, err)
	}
	var cappedState string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT state FROM zasp_discovery_outbox WHERE id=$1`, retryRequest.OutboxID).Scan(&cappedState); err != nil || cappedState != "exhausted" {
		t.Fatalf("attempt-cap state=%q err=%v", cappedState, err)
	}
}

func TestProductionDiscoveryRequiresSourceCursorMatchAndExactSyncSnapshotParent(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	firstIntegration := "pid_75000001-0000-4000-8000-000000000001"
	secondIntegration := "pid_75000002-0000-4000-8000-000000000002"
	fixture.createActiveIntegration(firstIntegration, "First")
	fixture.createActiveIntegration(secondIntegration, "Second")
	firstRequest := fixture.requestSync(firstIntegration, 501)
	wrongCursor := CompleteSnapshot{IntegrationID: firstIntegration, SyncID: firstRequest.SyncID, SnapshotID: "pid_75000003-0000-4000-8000-000000000003", Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/parents/wrong-cursor.json", ManifestChecksum: bytes32(75), CollectedAt: time.Now().UTC(), CursorProvider: "azure", CursorValue: "wrong", Entities: []byte(`[]`), Relationships: []byte(`[]`), Evidence: []byte(`[]`)}
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, wrongCursor); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("source/cursor mismatch=%v", err)
	}
	secondRequest := fixture.requestSync(secondIntegration, 502)
	snapshotID := "pid_75000004-0000-4000-8000-000000000004"
	if _, err := fixture.repository.ApplyCompleteSnapshot(fixture.ctx, fixture.scope, CompleteSnapshot{IntegrationID: secondIntegration, SyncID: secondRequest.SyncID, SnapshotID: snapshotID, Generation: 1, Source: "aws", ManifestReference: "s3://zasp-evidence/parents/second.json", ManifestChecksum: bytes32(76), CollectedAt: time.Now().UTC(), CursorProvider: "aws", CursorValue: "second", Entities: []byte(`[]`), Relationships: []byte(`[]`), Evidence: []byte(`[]`)}); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.connection.Begin(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(fixture.ctx, `UPDATE zasp_discovery_syncs SET snapshot_id=$1,state='succeeded',completed_at=transaction_timestamp() WHERE id=$2`, snapshotID, firstRequest.SyncID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(fixture.ctx); err == nil {
		t.Fatal("wrong-integration sync snapshot committed")
	}
	var firstSnapshot *string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT snapshot_id FROM zasp_discovery_syncs WHERE id=$1`, firstRequest.SyncID).Scan(&firstSnapshot); err != nil || firstSnapshot != nil {
		t.Fatalf("wrong-parent residue=%v err=%v", firstSnapshot, err)
	}
}

func TestProductionDiscoveryConnectionCanReauthorizeAfterInvalidOrRevoked(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_76000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Reconnect")
	connectionID := "pid_76000002-0000-4000-8000-000000000002"
	if _, err := fixture.repository.PutIntegrationConnection(fixture.ctx, fixture.scope, IntegrationConnectionPut{ID: connectionID, IntegrationID: integrationID, Provider: "aws", ConnectionReference: "ref:aws/reconnect"}); err != nil {
		t.Fatal(err)
	}
	transitions := []struct {
		version int64
		state   string
	}{{1, "verified"}, {2, "invalid"}, {3, "pending"}, {4, "verified"}, {5, "revoked"}, {6, "pending"}, {7, "verified"}}
	for _, transition := range transitions {
		if _, err := fixture.repository.TransitionIntegrationConnection(fixture.ctx, fixture.scope, integrationID, IntegrationTransition{ID: connectionID, ExpectedVersion: transition.version, State: transition.state}); err != nil {
			t.Fatalf("transition %d -> %s: %v", transition.version, transition.state, err)
		}
	}
}

func TestProductionDiscoverySnapshotSQLRejectsSourceCursorMismatch(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	integrationID := "pid_77000001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "SQL source guard")
	request := fixture.requestSync(integrationID, 601)
	digest := sha256.Sum256([]byte("manifest"))
	_, err := fixture.connection.Exec(fixture.ctx, `SELECT zasp_discovery_apply_snapshot($1,$2,$3,$4,$5,$6,1,'aws','s3://zasp-evidence/source/guard.json',$7,transaction_timestamp(),'azure','wrong','[]'::jsonb,'[]'::jsonb,'[]'::jsonb)`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String(), integrationID, request.SyncID, "pid_77000002-0000-4000-8000-000000000002", digest[:])
	if err == nil {
		t.Fatal("SQL accepted source/cursor mismatch")
	}
}
