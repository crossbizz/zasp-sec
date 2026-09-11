package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestProductionAcceptanceRepositoryClosedResponseAndExactRequest(t *testing.T) {
	request := acceptanceRequestFixture(t)
	accepted := `{"found":true,"batch_id":"` + request.BatchID.String() + `","generation":1,"state":"queued"}`
	for _, test := range []struct {
		name, body   string
		valid, found bool
	}{
		{"missing", `{"found":false}`, true, false},
		{"accepted", accepted, true, true},
		{"quarantined", strings.Replace(accepted, "queued", "quarantined", 1), true, true},
		{"duplicate", `{"found":false,"found":false}`, false, false},
		{"alias", `{"Found":false}`, false, false},
		{"extra empty metadata", `{"found":false,"state":""}`, false, false},
		{"missing found", `{}`, false, false},
		{"null found", `{"found":null}`, false, false},
		{"unfinalized", strings.Replace(accepted, "queued", "unknown", 1), false, false},
		{"different batch", strings.Replace(accepted, request.BatchID.String(), fixtureID(t, 199).String(), 1), false, false},
		{"unknown field", `{"found":false,"secret":"provider-secret"}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(test.body)}}
			repository, _ := NewPostgresProductionIngestRepository(database)
			credential, _ := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
			defer credential.Destroy()
			result, err := repository.LookupAcceptance(context.Background(), credential, request)
			if (err == nil) != test.valid || result.Found != test.found || containsProductionSecret(err) {
				t.Fatalf("response validation err=%v found=%t", err, result.Found)
			}
			if database.calls != 1 || database.statements[0] != productionLookupAcceptanceSQL || len(database.arguments[0]) != 15 {
				t.Fatal("lookup did not use exact single SQL boundary")
			}
			args := database.arguments[0]
			if args[13] != migrations.ProductionRuntimeAcceptance().Checksum() || args[14] != migrations.ProductionRuntimeAcceptanceSemanticFingerprint() {
				t.Fatal("lookup did not pin application release48 readiness")
			}
			if !bytes.Equal(args[0].([]byte), bytes.Repeat([]byte{0x31}, 16)) || !bytes.Equal(args[1].([]byte), bytes.Repeat([]byte{0x41}, 32)) || args[2] != request.EnrollmentBinding || args[3] != request.BatchID.String() || args[4] != request.IdempotencyKey || !bytes.Equal(args[5].([]byte), request.ContentDigest[:]) || args[6] != request.Source || args[7] != request.MediaType || args[8] != request.SchemaVersion || args[9] != request.PayloadSize || args[10] != request.EventCount || args[11] != request.JobID.String() || args[12] != request.OutboxID.String() {
				t.Fatal("lookup lost frozen request constraints")
			}
		})
	}
}

func TestProductionAcceptanceRepositoryCancellationAfterDatabaseReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	database := acceptanceDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		cancel()
		return json.RawMessage(`{"found":false}`), nil
	})
	repository, _ := NewPostgresProductionIngestRepository(database)
	credential, _ := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
	defer credential.Destroy()
	if result, err := repository.LookupAcceptance(ctx, credential, acceptanceRequestFixture(t)); !errors.Is(err, ErrProductionIngestUnavailable) || result != (IngestAcceptance{}) {
		t.Fatal("canceled lookup returned acceptance")
	}
}

func acceptanceRequestFixture(t *testing.T) IngestAcceptanceRequest {
	t.Helper()
	return IngestAcceptanceRequest{IngestReserveRequest: IngestReserveRequest{Scope: fixtureScope(t, 90), BatchID: fixtureID(t, 96), IdempotencyKey: "runtime-acceptance-request-0001", ContentDigest: sha256.Sum256([]byte("body")), Source: "tetragon", MediaType: "application/json", SchemaVersion: "runtime-event-v1", PayloadSize: 4, EventCount: 1}, EnrollmentBinding: strings.Repeat("a", 64), JobID: fixtureID(t, 97), OutboxID: fixtureID(t, 98)}
}

type acceptanceDatabaseFunc func(context.Context, string, ...any) (json.RawMessage, error)

func (call acceptanceDatabaseFunc) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	return call(ctx, sql, args...)
}
