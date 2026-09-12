package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestPreciseIngestReservationRequiresPinnedAuthority(t *testing.T) {
	for _, ready := range []string{`{"ready":true}`, `{"ready":false}`, `{"ready":true,"extra":true}`, `{"ready":null}`} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(ready), nil}, errors: []error{nil, errors.New("reserve unavailable")}}
		repository, _ := NewPostgresPreciseProductionIngestRepository(database)
		credential, err := sensor.ParseTokenCredential(productionSensorToken(t))
		if err != nil {
			t.Fatal(err)
		}
		defer credential.Destroy()
		request := IngestReserveRequest{Scope: fixtureScope(t, 140), BatchID: fixtureID(t, 143), IdempotencyKey: "runtime-v2:0123456789abcdef", ContentDigest: sha256.Sum256([]byte("precise")), Source: "tetragon", MediaType: "application/json", SchemaVersion: "runtime-event-v2", PayloadSize: 100, EventCount: 1}
		_, err = repository.Reserve(context.Background(), credential, request)
		wantCalls := 1
		if ready == `{"ready":true}` {
			wantCalls = 2
		}
		if err == nil || database.calls != wantCalls || database.statements[0] != `SELECT jsonb_build_object('ready',zasp_production_runtime_precision_readiness($1,$2) AND zasp_discovery_principal_ready('zasp_runtime_ingest'))` {
			t.Fatal("precision reserve bypassed identity", err, database.statements)
		}
		if !reflect.DeepEqual(database.arguments[0], []any{migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()}) {
			t.Fatal("unpinned precise release")
		}
		if wantCalls == 2 && (database.statements[1] != productionIngestReserveSQL || database.arguments[1][7] != "runtime-event-v2") {
			t.Fatal("reserved wrong payload schema", database.statements, database.arguments)
		}
	}
}

func TestPreciseIngestSchemaCannotCrossHistoricalRepository(t *testing.T) {
	for _, precise := range []bool{false, true} {
		database := &productionIngestDatabaseStub{}
		repository, _ := NewPostgresProductionIngestRepository(database)
		if precise {
			repository, _ = NewPostgresPreciseProductionIngestRepository(database)
		}
		credential, _ := sensor.ParseTokenCredential(productionSensorToken(t))
		defer credential.Destroy()
		request := acceptanceRequestFixture(t)
		request.SchemaVersion = "runtime-event-v2"
		if precise {
			request.Source = "otlp"
		}
		if _, err := repository.Reserve(context.Background(), credential, request.IngestReserveRequest); err == nil || database.calls != 0 {
			t.Fatal("unauthorized schema reservation", err, database.calls)
		}
		if _, err := repository.LookupAcceptance(context.Background(), credential, request); err == nil || database.calls != 0 {
			t.Fatal("unauthorized schema replay", err, database.calls)
		}
	}
}

func TestPreciseIngestRechecksReadinessAtReplayAndFinalize(t *testing.T) {
	request := acceptanceRequestFixture(t)
	request.SchemaVersion = "runtime-event-v2"
	credential, _ := sensor.ParseTokenCredential(productionSensorToken(t))
	defer credential.Destroy()
	for _, operation := range []string{"lookup", "finalize"} {
		database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), json.RawMessage(`{"ready":false}`)}}
		repository, _ := NewPostgresPreciseProductionIngestRepository(database)
		if err := repository.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
		var err error
		if operation == "lookup" {
			_, err = repository.LookupAcceptance(context.Background(), credential, request)
		} else {
			artifact := RawArtifact{Scope: request.Scope, Key: "runtime/body.json", Reference: "s3://zasp-runtime/runtime/body.json", VersionID: "version-1", ContentDigest: request.ContentDigest, Size: 4, MediaType: "application/json", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}
			_, err = repository.Finalize(context.Background(), credential, IngestFinalizeRequest{BatchID: request.BatchID, JobID: request.JobID, OutboxID: request.OutboxID, Artifact: artifact})
		}
		if !errors.Is(err, ErrProductionIngestUnavailable) || database.calls != 2 || database.statements[0] != database.statements[1] {
			t.Fatal("cached readiness authorized mutation", operation, err, database.statements)
		}
	}
}
