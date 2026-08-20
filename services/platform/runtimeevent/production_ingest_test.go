package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestProductionIngestDerivesScopeAndCommitsArtifactBeforeAcceptance(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope := fixtureScope(t, 70)
	repository := &productionIngestRepositoryStub{authority: IngestAuthority{Scope: scope, SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 2, Source: "tetragon", Mode: "full"}}
	artifacts := &productionRawArtifactStub{}
	handler, err := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	body := productionEventBody(now)
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
	request.Header.Set("Idempotency-Key", "runtime-event-request-0001")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var response map[string]string
	if json.Unmarshal(recorder.Body.Bytes(), &response) != nil || len(response) != 1 || response["batch_id"] == "" {
		t.Fatalf("body=%s", recorder.Body.String())
	}
	if repository.authenticateCalls != 1 || repository.reserveCalls != 1 || repository.finalizeCalls != 1 || artifacts.putCalls != 1 {
		t.Fatalf("calls authenticate=%d reserve=%d put=%d finalize=%d", repository.authenticateCalls, repository.reserveCalls, artifacts.putCalls, repository.finalizeCalls)
	}
	digest := sha256.Sum256(body)
	if repository.reserved.BatchID.String() != response["batch_id"] || repository.reserved.Scope != scope || repository.reserved.ContentDigest != digest || repository.reserved.PayloadSize != int64(len(body)) || repository.reserved.EventCount != 1 || repository.reserved.Source != "tetragon" {
		t.Fatalf("reserve=%#v", repository.reserved)
	}
	if artifacts.put.Scope != scope || artifacts.put.Key != repository.reservation.ArtifactKey || artifacts.put.ContentDigest != digest || !bytes.Equal(artifacts.put.Body, body) {
		t.Fatalf("artifact=%#v", artifacts.put)
	}
	if repository.finalized.BatchID != repository.reserved.BatchID || repository.finalized.Artifact != artifacts.result {
		t.Fatalf("finalize=%#v", repository.finalized)
	}
}

func TestProductionIngestRejectsCallerScopeAndHostileTransportBeforeAuthority(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "caller scope", mutate: func(request *http.Request) { request.Header.Set("X-Zasp-Organization", fixtureID(t, 80).String()) }},
		{name: "duplicate authorization", mutate: func(request *http.Request) {
			request.Header["Authorization"] = append(request.Header["Authorization"], "Bearer "+productionSensorToken(t))
		}},
		{name: "wrong schema", mutate: func(request *http.Request) { request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v2") }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "scope=forged" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &productionIngestRepositoryStub{authority: IngestAuthority{Scope: fixtureScope(t, 70), SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 2, Source: "tetragon", Mode: "full"}}
			handler, err := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: &productionRawArtifactStub{}, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(productionEventBody(now)))
			request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
			request.Header.Set("Idempotency-Key", "runtime-event-request-0001")
			test.mutate(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || repository.authenticateCalls != 0 || repository.reserveCalls != 0 {
				t.Fatalf("response=%d auth=%d reserve=%d body=%s", recorder.Code, repository.authenticateCalls, repository.reserveCalls, recorder.Body.String())
			}
		})
	}
}

func TestProductionIngestRejectsDuplicateNestedJSONBeforeReservation(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repository := &productionIngestRepositoryStub{authority: IngestAuthority{Scope: fixtureScope(t, 70), SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 2, Source: "tetragon", Mode: "full"}}
	handler, _ := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: &productionRawArtifactStub{}, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	body := bytes.Replace(productionEventBody(now), []byte(`"content":{"binary":"agent"}`), []byte(`"content":{"binary":"agent","binary":"drift"}`), 1)
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
	request.Header.Set("Idempotency-Key", "runtime-event-request-0001")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || repository.authenticateCalls != 1 || repository.reserveCalls != 0 {
		t.Fatalf("response=%d auth=%d reserve=%d body=%s", recorder.Code, repository.authenticateCalls, repository.reserveCalls, recorder.Body.String())
	}
}

func TestDecodeArchivedBatchReturnsExactCanonicalRecords(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope := fixtureScope(t, 70)
	body := productionEventBody(now)

	batch, err := DecodeArchivedBatch(scope, body)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Source != "tetragon" || len(batch.Records) != 1 || batch.Records[0].Scope != scope || batch.Records[0].Source != "tetragon" || batch.Records[0].SourceEventID != "event-1" || batch.Records[0].EventTime != now || batch.Records[0].Content["binary"] != "agent" {
		t.Fatalf("batch=%#v", batch)
	}
	batch.Records[0].Content["binary"] = "mutated"
	again, err := DecodeArchivedBatch(scope, body)
	if err != nil || again.Records[0].Content["binary"] != "agent" {
		t.Fatalf("decoder retained mutable output: batch=%#v err=%v", again, err)
	}
}

func TestDecodeArchivedBatchRejectsHostileOrDriftedPayloads(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope := fixtureScope(t, 70)
	valid := productionEventBody(now)
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "invalid scope", body: valid},
		{name: "unknown field", body: bytes.Replace(valid, []byte(`"source":"tetragon"`), []byte(`"source":"tetragon","scope":"forged"`), 1)},
		{name: "duplicate nested key", body: bytes.Replace(valid, []byte(`"content":{"binary":"agent"}`), []byte(`"content":{"binary":"agent","binary":"drift"}`), 1)},
		{name: "trailing value", body: append(bytes.Clone(valid), []byte(` {}`)...)},
		{name: "unknown source", body: bytes.Replace(valid, []byte(`"source":"tetragon"`), []byte(`"source":"unknown"`), 1)},
		{name: "invalid utf8", body: append(bytes.Clone(valid), 0xff)},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputScope := scope
			if test.name == "invalid scope" {
				inputScope = domain.Scope{}
			}
			if batch, err := DecodeArchivedBatch(inputScope, test.body); !errors.Is(err, ErrProductionIngest) || batch.Source != "" || batch.Records != nil {
				t.Fatalf("batch=%#v err=%v", batch, err)
			}
		})
	}
}

func TestProductionIngestFailsClosedAcrossReserveArtifactAndFinalize(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name          string
		repositoryErr error
		artifactErr   error
		finalizeErr   error
		wantPuts      int
		wantFinalizes int
	}{
		{name: "reserve", repositoryErr: ErrProductionIngestUnavailable},
		{name: "artifact", artifactErr: ErrProductionIngestUnknown, wantPuts: 1},
		{name: "finalize", finalizeErr: ErrProductionIngestUnknown, wantPuts: 1, wantFinalizes: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &productionIngestRepositoryStub{authority: IngestAuthority{Scope: fixtureScope(t, 70), SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 2, Source: "tetragon", Mode: "full"}, reserveErr: test.repositoryErr, finalizeErr: test.finalizeErr}
			artifacts := &productionRawArtifactStub{err: test.artifactErr}
			handler, _ := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(productionEventBody(now)))
			request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
			request.Header.Set("Idempotency-Key", "runtime-event-request-0001")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusServiceUnavailable || artifacts.putCalls != test.wantPuts || repository.finalizeCalls != test.wantFinalizes || recorder.Body.String() == "" {
				t.Fatalf("response=%d put=%d finalize=%d body=%s", recorder.Code, artifacts.putCalls, repository.finalizeCalls, recorder.Body.String())
			}
		})
	}
}

type productionIngestRepositoryStub struct {
	authority         IngestAuthority
	reservation       IngestReservation
	reserved          IngestReserveRequest
	finalized         IngestFinalizeRequest
	authenticateCalls int
	reserveCalls      int
	finalizeCalls     int
	reserveErr        error
	finalizeErr       error
}

func (stub *productionIngestRepositoryStub) Ready(context.Context) error { return nil }
func (stub *productionIngestRepositoryStub) Authenticate(_ context.Context, _ *sensor.TokenCredential) (IngestAuthority, error) {
	stub.authenticateCalls++
	return stub.authority, nil
}
func (stub *productionIngestRepositoryStub) Reserve(_ context.Context, _ *sensor.TokenCredential, request IngestReserveRequest) (IngestReservation, error) {
	stub.reserveCalls++
	stub.reserved = request
	if stub.reserveErr != nil {
		return IngestReservation{}, stub.reserveErr
	}
	stub.reservation = IngestReservation{BatchID: request.BatchID, Generation: 1, ArtifactKey: "runtime/v15/" + request.BatchID.String() + ".json", RequestDigest: sha256.Sum256([]byte("request")), State: "uploading"}
	return stub.reservation, nil
}
func (stub *productionIngestRepositoryStub) Finalize(_ context.Context, _ *sensor.TokenCredential, request IngestFinalizeRequest) (IngestResult, error) {
	stub.finalizeCalls++
	stub.finalized = request
	if stub.finalizeErr != nil {
		return IngestResult{}, stub.finalizeErr
	}
	return IngestResult{BatchID: request.BatchID, Generation: 1, State: "queued"}, nil
}

type productionRawArtifactStub struct {
	put      RawArtifactPut
	result   RawArtifact
	putCalls int
	err      error
}

func (stub *productionRawArtifactStub) Put(_ context.Context, request RawArtifactPut) (RawArtifact, error) {
	stub.putCalls++
	stub.put = request
	stub.put.Body = bytes.Clone(request.Body)
	if stub.err != nil {
		return RawArtifact{}, stub.err
	}
	stub.result = RawArtifact{Scope: request.Scope, Key: request.Key, Reference: "s3://zasp-runtime/" + request.Key, VersionID: "version-runtime-v15-0001", ContentDigest: request.ContentDigest, Size: int64(len(request.Body)), MediaType: request.MediaType, KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}
	return stub.result, nil
}

func productionSensorToken(t *testing.T) string {
	t.Helper()
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	value, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func productionEventBody(now time.Time) []byte {
	return []byte(`{"source":"tetragon","events":[{"event_id":"event-1","class":"process","action":"exec","workload_id":"runtime-a","event_time":"` + now.Format(timestampLayout) + `","evidence_id":"pid_79000001-0000-4000-8000-000000000001","content":{"binary":"agent"}}]}`)
}

var _ ProductionIngestRepository = (*productionIngestRepositoryStub)(nil)
var _ RawArtifactAuthority = (*productionRawArtifactStub)(nil)
