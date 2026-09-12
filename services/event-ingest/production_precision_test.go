package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type precisionConfigDatabase struct {
	query string
	args  []any
}

func (database *precisionConfigDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	database.query, database.args = query, args
	return json.RawMessage(`{"ready":true}`), nil
}

func TestProductionConfiguredPrecisionRepositoryPinsRelease51(t *testing.T) {
	values := validProductionIngestEnvironment()
	values["ZASP_RUNTIME_INGEST_SCHEMA"] = "runtime-event-v2"
	config, err := loadProductionIngestConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	database := &precisionConfigDatabase{}
	repository, err := newConfiguredProductionIngestRepository(database, config.RuntimeSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(context.Background()); err != nil || !strings.Contains(database.query, "zasp_production_runtime_precision_readiness") || len(database.args) != 2 || database.args[0] != migrations.ProductionRuntimePrecision().Checksum() || database.args[1] != migrations.ProductionRuntimePrecisionSemanticFingerprint() {
		t.Fatal("configured repository lost compiled51 authority", err, database.query)
	}
	for _, schema := range []string{"", "runtime-event-v1"} {
		legacy, err := newConfiguredProductionIngestRepository(database, schema)
		if err != nil {
			t.Fatal(err)
		}
		if legacy.ReadyPrecision(context.Background()) == nil {
			t.Fatal("legacy config silently enabled precision")
		}
	}
}

func TestProductionPrecisionRouterChecksFreshAuthorityThroughCache(t *testing.T) {
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	wire, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	authority := &preciseIngestAuthorityStub{err: errors.New("release drift")}
	cached := cachedProductionIngestRepository{productionIngestRepository: authority, ready: func(context.Context) error { return nil }}
	for _, schema := range []string{"runtime-event-v2", "runtime-event-v1"} {
		handler, err := newVersionedProductionIngestRouter(cached, productionRawArtifactStub{}, 1<<20, func() time.Time { return time.Now().UTC() }, schema)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+wire)
		request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-enrollment-v2")
		request.Header.Set("X-Zasp-Expected-Enrollment", strings.Repeat("a", 64))
		request.Header.Set("Idempotency-Key", "runtime-v2:"+strings.Repeat("b", 64))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := http.StatusServiceUnavailable
		if schema == "runtime-event-v1" {
			want = http.StatusBadRequest
		}
		if response.Code != want || authority.checks != 1 {
			t.Fatal("precision router readiness/legacy fence", schema, response.Code, authority.checks)
		}
	}
}

func TestProductionIngestRejectsUnknownTransportConfiguration(t *testing.T) {
	for _, version := range []string{"runtime-event-v9", " runtime-event-v2", "true"} {
		values := validProductionIngestEnvironment()
		values["ZASP_RUNTIME_INGEST_SCHEMA"] = version
		if _, err := loadProductionIngestConfig(func(key string) string { return values[key] }); err == nil {
			t.Fatal("unsupported runtime intake schema accepted", version)
		}
	}
}

type preciseIngestAuthorityStub struct {
	productionIngestRepositoryStub
	err             error
	checks, lookups int
	request         runtimeevent.IngestAcceptanceRequest
}

func (authority *preciseIngestAuthorityStub) ReadyPrecision(context.Context) error {
	authority.checks++
	return authority.err
}

func (authority *preciseIngestAuthorityStub) LookupAcceptance(_ context.Context, _ *sensor.TokenCredential, request runtimeevent.IngestAcceptanceRequest) (runtimeevent.IngestAcceptance, error) {
	authority.lookups++
	authority.request = request
	return runtimeevent.IngestAcceptance{Found: true}, authority.err
}

func TestProductionCachePreservesFreshPrecisionAuthority(t *testing.T) {
	authority := &preciseIngestAuthorityStub{}
	cached := cachedProductionIngestRepository{productionIngestRepository: authority, ready: func(context.Context) error { return nil }}
	precision, ok := any(cached).(interface{ ReadyPrecision(context.Context) error })
	if !ok {
		t.Fatal("cache erased precision readiness capability")
	}
	if err := precision.ReadyPrecision(context.Background()); err != nil || authority.checks != 1 {
		t.Fatal("fresh readiness not forwarded", err)
	}
	authority.err = errors.New("release drift")
	if err := precision.ReadyPrecision(context.Background()); err == nil || authority.checks != 2 {
		t.Fatal("healthy cache concealed release drift", err)
	}
}

func TestProductionCachePreservesAcceptanceLookup(t *testing.T) {
	authority := &preciseIngestAuthorityStub{}
	cached := cachedProductionIngestRepository{productionIngestRepository: authority, ready: func(context.Context) error { return nil }}
	acceptance, ok := any(cached).(runtimeevent.ProductionAcceptanceRepository)
	if !ok {
		t.Fatal("cache erased accepted replay capability")
	}
	request := runtimeevent.IngestAcceptanceRequest{IngestReserveRequest: runtimeevent.IngestReserveRequest{SchemaVersion: "runtime-event-v2"}, EnrollmentBinding: "bound-request"}
	result, err := acceptance.LookupAcceptance(context.Background(), nil, request)
	if err != nil || !result.Found || authority.lookups != 1 || authority.request != request {
		t.Fatal("acceptance request not forwarded", err)
	}
	legacy := cachedProductionIngestRepository{productionIngestRepository: &productionIngestRepositoryStub{}, ready: func(context.Context) error { return nil }}
	if result, err := any(legacy).(runtimeevent.ProductionAcceptanceRepository).LookupAcceptance(context.Background(), nil, request); err == nil || result.Found {
		t.Fatal("missing authority invented acceptance")
	}
}
