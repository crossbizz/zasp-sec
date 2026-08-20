package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPostgresProductionPipelineRepositoryBindsDeliveryLifecycle(t *testing.T) {
	scope := fixtureScope(t, 120)
	batchID := fixtureID(t, 123)
	messageDigest := sha256.Sum256([]byte("message"))
	providerAck := sha256.Sum256([]byte("provider-ack"))
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{
		json.RawMessage(`{"ready":true}`),
		json.RawMessage(`{"batch_id":"` + batchID.String() + `","generation":2,"disposition":"claimed","replayed":false,"lease_expires_at":"2030-08-20T12:00:30Z","visibility_deadline":"2030-08-20T12:01:00Z","artifact_reference":"s3://zasp-runtime/runtime/v15/raw.json","artifact_key":"runtime/v15/raw.json","artifact_version_id":"version-2","artifact_checksum":"` + strings.Repeat("a", 64) + `","artifact_size_bytes":123,"artifact_kms_key":"arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111","request_digest":"` + strings.Repeat("b", 64) + `"}`),
		json.RawMessage(`{"batch_id":"` + batchID.String() + `","generation":2,"lease_expires_at":"2030-08-20T12:00:45Z","visibility_deadline":"2030-08-20T12:01:15Z"}`),
		json.RawMessage(`{"batch_id":"` + batchID.String() + `","generation":2,"disposition":"retryable","error_class":"retryable"}`),
		json.RawMessage(`{"batch_id":"` + batchID.String() + `","generation":2,"disposition":"acked","replayed":false}`),
	}}
	repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
	if err != nil || repository.Ready(context.Background()) != nil {
		t.Fatalf("repository=%v ready=%v", err, repository.Ready(context.Background()))
	}
	request := DeliveryClaimRequest{Scope: scope, BatchID: batchID, Generation: 2, MessageID: "sha256_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", MessageDigest: messageDigest, ReceiveCount: 1, WorkerID: "runtime-coordinator-01", LeaseToken: "0123456789abcdef", LeaseSeconds: 30, VisibilitySeconds: 60}
	claim, err := repository.ClaimDelivery(context.Background(), request)
	if err != nil || claim.Disposition != DeliveryDispositionClaimed || claim.Scope != scope || claim.BatchID != batchID || claim.Generation != 2 || claim.Artifact.VersionID != "version-2" || claim.LeaseExpiresAt.IsZero() {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	if _, err := repository.HeartbeatDelivery(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if result, err := repository.ReleaseDelivery(context.Background(), request, DeliveryOutcomeRetryable, "retryable"); err != nil || result.Disposition != DeliveryDispositionRetryable {
		t.Fatalf("release=%#v err=%v", result, err)
	}
	if result, err := repository.AcknowledgeDelivery(context.Background(), request, providerAck); err != nil || result.Disposition != DeliveryDispositionAcked || result.Replayed {
		t.Fatalf("ack=%#v err=%v", result, err)
	}
	if database.calls != 5 || !reflect.DeepEqual(database.arguments[1], []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String(), int64(2), request.MessageID, messageDigest[:], 1, request.WorkerID, request.LeaseToken, 30, 60}) {
		t.Fatalf("calls=%d claim args=%#v", database.calls, database.arguments[1])
	}
}

func TestPostgresProductionPipelineRepositoryBindsStageClaimHeartbeatAndFinish(t *testing.T) {
	scope := fixtureScope(t, 130)
	batchID := fixtureID(t, 133)
	var effectDigest, resultDigest [sha256.Size]byte
	for index := range effectDigest {
		effectDigest[index], resultDigest[index] = 0xcc, 0xdd
	}
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{
		json.RawMessage(`[{
          "organization_id":"` + scope.OrganizationID().String() + `","workspace_id":"` + scope.WorkspaceID().String() + `","environment_id":"` + scope.EnvironmentID().String() + `",
          "batch_id":"` + batchID.String() + `","generation":4,"stage":"index","attempt":2,"implementation_version":"runtime-index-v1","predecessor_digest":"` + strings.Repeat("a", 64) + `","input_digest":"` + strings.Repeat("b", 64) + `","input_reference":"s3://zasp-runtime/results/archive.json","input_version_id":"version-3","lease_expires_at":"2030-08-20T12:00:30Z"
        }]`),
		json.RawMessage(`{"batch_id":"` + batchID.String() + `","generation":4,"stage":"index","lease_expires_at":"2030-08-20T12:00:45Z"}`),
		json.RawMessage(`{"batch_id":"` + batchID.String() + `","generation":4,"stage":"index","state":"succeeded","attempt":2,"input_digest":"` + strings.Repeat("b", 64) + `","implementation_version":"runtime-index-v1","effect_digest":"` + strings.Repeat("c", 64) + `","result_reference":"s3://zasp-runtime/results/index.json","result_version_id":"version-4","result_digest":"` + strings.Repeat("d", 64) + `","error_class":null}`),
	}}
	repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityIndex)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := repository.ClaimStages(context.Background(), "runtime-index-01", "0123456789abcdef", 30, 1)
	if err != nil || len(leases) != 1 || leases[0].Scope != scope || leases[0].Stage != RuntimeStageIndex || leases[0].Attempt != 2 || leases[0].InputReference != "s3://zasp-runtime/results/archive.json" || leases[0].InputVersionID != "version-3" {
		t.Fatalf("leases=%#v err=%v", leases, err)
	}
	lease := leases[0]
	if _, err := repository.HeartbeatStage(context.Background(), lease, "runtime-index-01", "0123456789abcdef", 30); err != nil {
		t.Fatal(err)
	}
	finish := StageFinishRequest{Lease: lease, WorkerID: "runtime-index-01", LeaseToken: "0123456789abcdef", Outcome: StageOutcomeSucceeded, EffectDigest: effectDigest, ResultReference: "s3://zasp-runtime/results/index.json", ResultVersionID: "version-4", ResultDigest: resultDigest}
	result, err := repository.FinishStage(context.Background(), finish)
	if err != nil || result.Stage != RuntimeStageIndex || result.State != StageOutcomeSucceeded || result.Attempt != 2 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if database.calls != 3 || !reflect.DeepEqual(database.arguments[0], []any{"runtime-index-01", "0123456789abcdef", 30, 1}) {
		t.Fatalf("calls=%d args=%#v", database.calls, database.arguments)
	}
}

func TestPostgresProductionPipelineRepositoryRejectsAuthorityAndHostileOutput(t *testing.T) {
	for _, authority := range []ProductionPipelineAuthority{"", "runtime", "zasp_discovery_api"} {
		if repository, err := NewPostgresProductionPipelineRepository(&productionIngestDatabaseStub{}, authority); repository != nil || !errors.Is(err, ErrProductionPipeline) {
			t.Fatalf("authority=%q repository=%v err=%v", authority, repository, err)
		}
	}
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`[{"secret":"provider-secret"}]`)}}
	repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityArchive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ClaimStages(context.Background(), "runtime-archive-01", "0123456789abcdef", 30, 1); !errors.Is(err, ErrProductionPipelineUnavailable) || containsProductionSecret(err) {
		t.Fatalf("error=%v", err)
	}
}

func TestProductionPipelineLeaseValidationRejectsExpiredAndCrossStageValues(t *testing.T) {
	lease := StageLease{Scope: fixtureScope(t, 140), BatchID: fixtureID(t, 143), Generation: 1, Stage: RuntimeStageArchive, Attempt: 1, ImplementationVersion: "runtime-archive-v1", InputDigest: sha256.Sum256([]byte("input")), InputReference: "s3://zasp-runtime/runtime/v15/raw.json", InputVersionID: "version-1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	if !validStageLease(lease, RuntimeStageArchive, time.Now().UTC()) {
		t.Fatal("valid lease rejected")
	}
	lease.Stage = RuntimeStageProject
	if validStageLease(lease, RuntimeStageArchive, time.Now().UTC()) {
		t.Fatal("cross-stage lease accepted")
	}
}
