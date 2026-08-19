package apiserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

func TestProductionDiscoveryRejectsAmbiguousObjectReferencesWithoutResidue(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	for _, reference := range []string{"s3://bucket/key with space", "s3://bucket/key?version=1", "s3://bucket//key", "s3://bucket/../key", "s3://bucket/"} {
		var valid bool
		if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_s3_object_reference($1)`, reference).Scan(&valid); err != nil || valid {
			t.Fatalf("reference %q valid=%v err=%v", reference, valid, err)
		}
	}
	integrationID := "pid_77100001-0000-4000-8000-000000000001"
	fixture.createActiveIntegration(integrationID, "Object reference guard")
	request := fixture.requestSync(integrationID, 602)
	digest := sha256.Sum256([]byte("manifest"))
	_, err := fixture.connection.Exec(fixture.ctx, `SELECT zasp_discovery_apply_snapshot($1,$2,$3,$4,$5,$6,1,'aws','s3://bucket/key?version=1',$7,transaction_timestamp(),'aws','cursor','[]'::jsonb,'[]'::jsonb,'[]'::jsonb)`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String(), integrationID, request.SyncID, "pid_77100002-0000-4000-8000-000000000002", digest[:])
	if err == nil {
		t.Fatal("snapshot accepted ambiguous manifest reference")
	}
	var snapshotCount int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FROM zasp_discovery_snapshots WHERE integration_id=$1`, integrationID).Scan(&snapshotCount); err != nil || snapshotCount != 0 {
		t.Fatalf("ambiguous reference residue snapshots=%d err=%v", snapshotCount, err)
	}
}

func TestProductionDiscoveryActualSessionPrincipalsHaveExactAuthorities(t *testing.T) {
	fixture := newDiscoveryFixPostgresFixture(t)
	var migrationPrincipal string
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT session_user`).Scan(&migrationPrincipal); err != nil {
		t.Fatal(err)
	}
	principalNames := []string{"zasp_test_api_login", "zasp_test_discovery_login", "zasp_test_ingest_login", "zasp_test_runtime_login", "zasp_test_outbox_login", "zasp_test_gateway_login"}
	for _, principal := range principalNames {
		if _, err := fixture.connection.Exec(fixture.ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, principal)); err != nil {
			t.Fatal(err)
		}
	}
	registrationArguments := []any{migrationPrincipal, principalNames[0], principalNames[1], principalNames[2], principalNames[3], principalNames[4], principalNames[5]}
	if _, err := fixture.connection.Exec(fixture.ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, registrationArguments...); err != nil {
		t.Fatal(err)
	}
	var registered bool
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, registrationArguments...).Scan(&registered); err != nil || !registered {
		t.Fatalf("exact registration replay registered=%v err=%v", registered, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `CREATE ROLE zasp_test_conflicting_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	conflictingArguments := append([]any(nil), registrationArguments...)
	conflictingArguments[1] = "zasp_test_conflicting_login"
	if _, err := fixture.connection.Exec(fixture.ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, conflictingArguments...); err == nil {
		t.Fatal("principal registration accepted changed API identity")
	}
	var bindingCount int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FROM zasp_discovery_principal_bindings`).Scan(&bindingCount); err != nil || bindingCount != 7 {
		t.Fatalf("principal registration residue count=%d err=%v", bindingCount, err)
	}
	connectAs := func(principal string) (*pgx.Conn, *PostgresJSONDatabase) {
		t.Helper()
		configuration, err := pgx.ParseConfig(fixture.dsn)
		if err != nil {
			t.Fatal(err)
		}
		configuration.User = principal
		connection, err := pgx.ConnectConfig(fixture.ctx, configuration)
		if err != nil {
			t.Fatal(err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		return connection, database
	}
	authorities := []string{DiscoveryDatabaseAuthorityAPI, DiscoveryDatabaseAuthorityWorker, DiscoveryDatabaseAuthorityIngest, DiscoveryDatabaseAuthorityRuntime, DiscoveryDatabaseAuthorityOutbox, DiscoveryDatabaseAuthorityGateway}
	for index, authority := range authorities {
		connection, database := connectAs(principalNames[index])
		if _, err := NewDiscoveryRepositoryForAuthority(database, authority); err != nil {
			connection.Close(context.Background())
			t.Fatalf("principal %s authority %s: %v", principalNames[index], authority, err)
		}
		if _, err := NewDiscoveryRepositoryForAuthority(database, authorities[(index+1)%len(authorities)]); !errors.Is(err, ErrRepositoryConfiguration) {
			connection.Close(context.Background())
			t.Fatalf("principal %s accepted wrong authority: %v", principalNames[index], err)
		}
		connection.Close(context.Background())
	}

	type privilegeCase struct {
		principal, allowed, denied string
	}
	for _, test := range []privilegeCase{
		{principalNames[0], "zasp_discovery_create_integration(text,text,text,text,text,text,text,jsonb,text)", "zasp_discovery_claim_outbox(text,text,integer,integer)"},
		{principalNames[1], "zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)", "zasp_discovery_create_runtime_batch(text,text,text,text,text,text,text,text,bytea,integer,text,bigint,text,text)"},
		{principalNames[2], "zasp_discovery_create_runtime_batch(text,text,text,text,text,text,text,text,bytea,integer,text,bigint,text,text)", "zasp_discovery_apply_snapshot(text,text,text,text,text,text,bigint,text,text,bytea,timestamptz,text,text,jsonb,jsonb,jsonb)"},
		{principalNames[3], "zasp_discovery_complete_runtime_stage(text,text,text,text,text,bytea,boolean,text)", "zasp_discovery_gateway_advance_replay(text,text,text,text,bigint,bigint)"},
		{principalNames[4], "zasp_discovery_claim_outbox(text,text,integer,integer)", "zasp_discovery_claim_schedules(text,text,integer,integer)"},
		{principalNames[5], "zasp_discovery_gateway_advance_replay(text,text,text,text,bigint,bigint)", "zasp_discovery_sensor_heartbeat(text,text,text,text,bigint,text,bigint,jsonb)"},
	} {
		connection, _ := connectAs(test.principal)
		var allowed, denied bool
		if err := connection.QueryRow(fixture.ctx, `SELECT has_function_privilege(session_user,$1,'EXECUTE'),has_function_privilege(session_user,$2,'EXECUTE')`, test.allowed, test.denied).Scan(&allowed, &denied); err != nil || !allowed || denied {
			connection.Close(context.Background())
			t.Fatalf("privileges %s allowed=%v denied=%v err=%v", test.principal, allowed, denied, err)
		}
		connection.Close(context.Background())
	}
	apiCompatibilityConnection, _ := connectAs(principalNames[0])
	var bootstrapRows, administrationRows, highRiskPaths int64
	if err := apiCompatibilityConnection.QueryRow(fixture.ctx, `SELECT (SELECT count(*) FROM zasp_core_payloads),(SELECT count(*) FROM zasp_organizations),zasp_risk_high_path_count($1,$2,$3)`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String()).Scan(&bootstrapRows, &administrationRows, &highRiskPaths); err != nil {
		apiCompatibilityConnection.Close(context.Background())
		t.Fatalf("legacy API compatibility query: %v", err)
	}
	var inventoryPage []byte
	if err := apiCompatibilityConnection.QueryRow(fixture.ctx, `SELECT zasp_discovery_entity_page($1,$2,$3,NULL,1)`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String()).Scan(&inventoryPage); err != nil {
		apiCompatibilityConnection.Close(context.Background())
		t.Fatalf("v10 API function: %v", err)
	}
	if _, err := apiCompatibilityConnection.Exec(fixture.ctx, `SELECT * FROM zasp_integrations`); err == nil {
		apiCompatibilityConnection.Close(context.Background())
		t.Fatal("API principal read v10 table directly")
	}
	if _, err := apiCompatibilityConnection.Exec(fixture.ctx, `SELECT zasp_discovery_claim_jobs('worker','lease-token-7600002',30,1,'discovery')`); err == nil {
		apiCompatibilityConnection.Close(context.Background())
		t.Fatal("API principal invoked v10 worker function")
	}
	apiCompatibilityConnection.Close(context.Background())
	discoveryJobID := "pid_76000001-0000-4000-8000-000000000001"
	runtimeJobID := "pid_76000001-0000-4000-8000-000000000002"
	if _, err := fixture.connection.Exec(fixture.ctx, `INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,'discovery','pid_76000002-0000-4000-8000-000000000001','domain-job-discovery',digest('discovery','sha256'),'leased',1,'worker','lease-token-domain-discovery',transaction_timestamp()+interval '30 seconds'),($1,$2,$3,$5,'runtime','pid_76000002-0000-4000-8000-000000000002','domain-job-runtime-01',digest('runtime','sha256'),'leased',1,'worker','lease-token-domain-runtime-01',transaction_timestamp()+interval '30 seconds')`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String(), discoveryJobID, runtimeJobID); err != nil {
		t.Fatal(err)
	}
	runtimeConnection, _ := connectAs(principalNames[3])
	if _, err := runtimeConnection.Exec(fixture.ctx, `SELECT zasp_discovery_finish_job($1,$2,$3,$4,'worker','lease-token-domain-discovery','succeeded',digest('result','sha256'),NULL,0)`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String(), discoveryJobID); err == nil {
		t.Fatal("runtime principal finished discovery job")
	}
	runtimeConnection.Close(context.Background())
	discoveryDomainConnection, _ := connectAs(principalNames[1])
	if _, err := discoveryDomainConnection.Exec(fixture.ctx, `SELECT zasp_discovery_complete_job($1,$2,$3,$4,'worker','lease-token-domain-runtime-01',digest('result','sha256'),false,NULL)`, fixture.scope.OrganizationID().String(), fixture.scope.WorkspaceID().String(), fixture.scope.EnvironmentID().String(), runtimeJobID); err == nil {
		t.Fatal("discovery principal completed runtime job through legacy wrapper")
	}
	discoveryDomainConnection.Close(context.Background())
	var leasedCount int
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT count(*) FROM zasp_discovery_jobs WHERE id=ANY($1) AND state='leased'`, []string{discoveryJobID, runtimeJobID}).Scan(&leasedCount); err != nil || leasedCount != 2 {
		t.Fatalf("cross-domain finish residue leased=%d err=%v", leasedCount, err)
	}
	discoveryConnection, _ := connectAs(principalNames[1])
	if _, err := discoveryConnection.Exec(fixture.ctx, `SELECT zasp_discovery_claim_jobs('worker','lease-token-7600001',30,1,'runtime')`); err == nil {
		discoveryConnection.Close(context.Background())
		t.Fatal("discovery principal claimed runtime jobs")
	}
	discoveryConnection.Close(context.Background())

	apiConnection, _ := connectAs(principalNames[0])
	if _, err := apiConnection.Exec(fixture.ctx, `SELECT zasp_discovery_register_principals($1,$2,$3,$4,$5,$6,$7)`, registrationArguments...); err == nil {
		t.Fatal("runtime principal executed principal registration")
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `GRANT SELECT ON zasp_integrations TO zasp_test_api_login`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := apiConnection.QueryRow(fixture.ctx, `SELECT zasp_discovery_principal_ready($1)`, DiscoveryDatabaseAuthorityAPI).Scan(&ready); err != nil || ready {
		t.Fatalf("direct ACL ready=%v err=%v", ready, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `REVOKE SELECT ON zasp_integrations FROM zasp_test_api_login; GRANT zasp_runtime_gateway TO zasp_test_api_login WITH ADMIN OPTION`); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(fixture.ctx, `SELECT zasp_discovery_principal_ready($1)`, DiscoveryDatabaseAuthorityAPI).Scan(&ready); err != nil || ready {
		t.Fatalf("unsafe membership ready=%v err=%v", ready, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `REVOKE zasp_runtime_gateway FROM zasp_test_api_login; GRANT zasp_discovery_api TO zasp_test_api_login WITH ADMIN OPTION`); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(fixture.ctx, `SELECT zasp_discovery_principal_ready($1)`, DiscoveryDatabaseAuthorityAPI).Scan(&ready); err != nil || ready {
		t.Fatalf("admin option ready=%v err=%v", ready, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `REVOKE ADMIN OPTION FOR zasp_discovery_api FROM zasp_test_api_login; ALTER ROLE zasp_test_api_login NOINHERIT`); err != nil {
		t.Fatal(err)
	}
	if err := apiConnection.QueryRow(fixture.ctx, `SELECT zasp_discovery_principal_ready($1)`, DiscoveryDatabaseAuthorityAPI).Scan(&ready); err != nil || ready {
		t.Fatalf("noinherit ready=%v err=%v", ready, err)
	}
	apiConnection.Close(context.Background())
	if _, err := fixture.connection.Exec(fixture.ctx, `ALTER ROLE zasp_test_api_login INHERIT; CREATE ROLE zasp_test_unbound_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT zasp_runtime_gateway TO zasp_test_unbound_login`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("unbound capability member security ready=%v err=%v", ready, err)
	}
	if _, err := fixture.connection.Exec(fixture.ctx, `REVOKE zasp_runtime_gateway FROM zasp_test_unbound_login`); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.connection.Exec(fixture.ctx, `CREATE ROLE zasp_test_rogue NOLOGIN; GRANT EXECUTE ON FUNCTION zasp_discovery_entity_page(text,text,text,text,integer) TO zasp_test_rogue`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.connection.QueryRow(fixture.ctx, `SELECT zasp_discovery_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("arbitrary ACL security ready=%v err=%v", ready, err)
	}
}
