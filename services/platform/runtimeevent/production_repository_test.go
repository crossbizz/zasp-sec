package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestPostgresProductionIngestRepositoryBindsExactV15Authority(t *testing.T) {
	scope := fixtureScope(t, 90)
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{
		json.RawMessage(`{"ready":true}`),
		json.RawMessage(`{"organization_id":"` + scope.OrganizationID().String() + `","workspace_id":"` + scope.WorkspaceID().String() + `","environment_id":"` + scope.EnvironmentID().String() + `","sensor_id":"pid_90000004-0000-4000-8000-000000000004","sensor_kind":"tetragon","sensor_mode":"full","sensor_version":1,"token_id":"pid_90000005-0000-4000-8000-000000000005","token_generation":2,"audience":"event-ingest"}`),
		json.RawMessage(`{"batch_id":"pid_00000096-0000-4000-8000-000000000096","generation":3,"artifact_key":"runtime/v15/key/pid_00000096-0000-4000-8000-000000000096.json","request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"uploading","replayed":false}`),
		json.RawMessage(`{"batch_id":"pid_00000096-0000-4000-8000-000000000096","generation":3,"state":"queued","replayed":false}`),
	}}
	repository, err := NewPostgresProductionIngestRepository(database)
	if err != nil || repository.Ready(context.Background()) != nil {
		t.Fatalf("repository=%v ready=%v", err, repository.Ready(context.Background()))
	}
	credential, _ := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
	defer credential.Destroy()
	authority, err := repository.Authenticate(context.Background(), credential)
	if err != nil || authority.Scope != scope || authority.Source != "tetragon" || authority.Mode != "full" || authority.TokenGeneration != 2 {
		t.Fatalf("authority=%#v err=%v", authority, err)
	}
	digest := sha256.Sum256([]byte("body"))
	batchID := fixtureID(t, 96)
	reservation, err := repository.Reserve(context.Background(), credential, IngestReserveRequest{Scope: scope, BatchID: batchID, IdempotencyKey: "runtime-event-request-0001", ContentDigest: digest, Source: "tetragon", MediaType: "application/json", SchemaVersion: "runtime-event-v1", PayloadSize: 4, EventCount: 1})
	if err != nil || reservation.BatchID != batchID || reservation.Generation != 3 || reservation.State != "uploading" {
		t.Fatalf("reservation=%#v err=%v", reservation, err)
	}
	artifact := RawArtifact{Scope: scope, Key: reservation.ArtifactKey, Reference: "s3://zasp-runtime/" + reservation.ArtifactKey, VersionID: "version-3", ContentDigest: digest, Size: 4, MediaType: "application/json", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}
	result, err := repository.Finalize(context.Background(), credential, IngestFinalizeRequest{BatchID: batchID, JobID: fixtureID(t, 97), OutboxID: fixtureID(t, 98), Artifact: artifact})
	if err != nil || result.BatchID != batchID || result.Generation != 3 || result.State != "queued" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if database.calls != 4 || len(database.arguments[1]) != 2 || !bytes.Equal(database.arguments[1][0].([]byte), bytes.Repeat([]byte{0x31}, 16)) || !bytes.Equal(database.arguments[1][1].([]byte), bytes.Repeat([]byte{0x41}, 32)) {
		t.Fatalf("database calls=%d arguments=%#v", database.calls, database.arguments)
	}
}

func TestPostgresProductionIngestRepositoryRejectsHostileOutput(t *testing.T) {
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true,"secret":"provider-secret"}`)}}
	repository, err := NewPostgresProductionIngestRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(context.Background()); !errors.Is(err, ErrProductionIngestUnavailable) || containsProductionSecret(err) {
		t.Fatalf("ready err=%v", err)
	}
}

func TestPostgresProductionIngestRepositoryClassifiesRateLimitWithoutDatabaseDetail(t *testing.T) {
	for _, databaseError := range []error{
		&pgconn.PgError{Code: "53300", Message: "runtime batch rate limited", Detail: "tenant-secret"},
		ErrProductionIngestRateLimited,
	} {
		database := &productionIngestDatabaseStub{errors: []error{databaseError}}
		repository, _ := NewPostgresProductionIngestRepository(database)
		credential, _ := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
		digest := sha256.Sum256([]byte("body"))
		_, err := repository.Reserve(context.Background(), credential, IngestReserveRequest{Scope: fixtureScope(t, 90), BatchID: fixtureID(t, 96), IdempotencyKey: "runtime-event-request-0001", ContentDigest: digest, Source: "tetragon", MediaType: "application/json", SchemaVersion: "runtime-event-v1", PayloadSize: 4, EventCount: 1})
		credential.Destroy()
		if !errors.Is(err, ErrProductionIngestRateLimited) || bytes.Contains([]byte(err.Error()), []byte("tenant-secret")) {
			t.Fatalf("database error=%T rate limit err=%v", databaseError, err)
		}
	}
}

func TestPostgresProductionIngestRepositoryRecordsTokenAuthenticatedHeartbeat(t *testing.T) {
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"sensor_id":"pid_00000100-0000-4000-8000-000000000100","sequence":7,"observed_at":"2026-08-20T12:00:00Z"}`)}}
	repository, _ := NewPostgresProductionIngestRepository(database)
	credential, _ := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
	defer credential.Destroy()
	report := sensor.PrivateHeartbeat{Sequence: 7, Status: "healthy", Capabilities: []string{"file", "network", "process"}, Kernel: "6.8.0", BTF: true, EventRate: 125, Drops: 0}
	if err := repository.RecordAuthenticatedHeartbeat(context.Background(), credential, report); err != nil {
		t.Fatal(err)
	}
	if database.calls != 1 || len(database.arguments[0]) != 9 || database.arguments[0][2] != int64(7) || database.arguments[0][3] != "healthy" || database.arguments[0][5] != "6.8.0" {
		t.Fatalf("arguments=%#v", database.arguments)
	}
}

func TestPostgresProductionIngestRepositoryClaimsAndTransitionsExactReconciliationLease(t *testing.T) {
	lease := reconciliationLease(t)
	leaseJSON := `[{"organization_id":"` + lease.Scope.OrganizationID().String() + `","workspace_id":"` + lease.Scope.WorkspaceID().String() + `","environment_id":"` + lease.Scope.EnvironmentID().String() + `","batch_id":"` + lease.BatchID.String() + `","generation":2,"attempt":1,"lease_expires_at":"` + lease.LeaseExpiresAt.Format(time.RFC3339Nano) + `","request_digest":"` + fmt.Sprintf("%x", lease.RequestDigest) + `","artifact_key":"` + lease.ArtifactKey + `","content_digest":"` + fmt.Sprintf("%x", lease.ContentDigest) + `","payload_size_bytes":23,"media_type":"application/json","schema_version":"runtime-event-v1"}]`
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{
		json.RawMessage(leaseJSON),
		json.RawMessage(`{"batch_id":"` + lease.BatchID.String() + `","generation":2,"state":"retryable","attempt":1,"error_code":"not_found","replayed":false}`),
		json.RawMessage(`{"batch_id":"` + lease.BatchID.String() + `","generation":2,"state":"queued","replayed":false}`),
		json.RawMessage(`{"batch_id":"` + lease.BatchID.String() + `","generation":2,"state":"quarantined","replayed":false}`),
	}}
	repository, _ := NewPostgresProductionIngestRepository(database)
	claims, err := repository.ClaimReconciliation(context.Background(), "ingest-reconciler-1", "runtime-reconciliation-token-0001", 60, 1)
	if err != nil || len(claims) != 1 || claims[0] != lease {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if err := repository.ReleaseReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001", 30*time.Second, "not_found"); err != nil {
		t.Fatal(err)
	}
	artifact := RawArtifact{Scope: lease.Scope, Key: lease.ArtifactKey, Reference: "s3://runtime/" + lease.ArtifactKey, VersionID: "version-17", ContentDigest: lease.ContentDigest, Size: lease.PayloadSize, MediaType: lease.MediaType, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}
	if err := repository.FinishReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001", reconciliationTestID(t, 1), reconciliationTestID(t, 2), artifact); err != nil {
		t.Fatal(err)
	}
	if err := repository.QuarantineReconciliation(context.Background(), lease, "ingest-reconciler-1", "runtime-reconciliation-token-0001"); err != nil {
		t.Fatal(err)
	}
	if database.calls != 4 || !strings.Contains(database.statements[0], "zasp_runtime_claim_reconciliation") || !strings.Contains(database.statements[1], "zasp_runtime_release_reconciliation") || !strings.Contains(database.statements[2], "zasp_runtime_finish_reconciliation") || !strings.Contains(database.statements[3], "zasp_runtime_quarantine_reconciliation") {
		t.Fatalf("statements=%#v", database.statements)
	}
}

type productionIngestDatabaseStub struct {
	responses  []json.RawMessage
	errors     []error
	calls      int
	arguments  [][]any
	statements []string
}

func (stub *productionIngestDatabaseStub) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	index := stub.calls
	stub.calls++
	retained := append([]any(nil), arguments...)
	for index, argument := range retained {
		if value, ok := argument.([]byte); ok {
			retained[index] = bytes.Clone(value)
		}
	}
	stub.arguments = append(stub.arguments, retained)
	stub.statements = append(stub.statements, statement)
	if index < len(stub.errors) && stub.errors[index] != nil {
		return nil, stub.errors[index]
	}
	if index >= len(stub.responses) {
		return nil, errors.New("provider-secret")
	}
	return append(json.RawMessage(nil), stub.responses[index]...), nil
}

func containsProductionSecret(err error) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte("provider-secret"))
}

var _ ProductionIngestDatabase = (*productionIngestDatabaseStub)(nil)
