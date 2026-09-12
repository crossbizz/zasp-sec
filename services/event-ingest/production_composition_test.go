package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type compositionDatabase struct {
	queries []string
	unready bool
}

func (database *compositionDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	database.queries = append(database.queries, query)
	if strings.Contains(query, "readiness") {
		return json.RawMessage(fmt.Sprintf(`{"ready":%t}`, !database.unready)), nil
	}
	if strings.Contains(query, "zasp_runtime_claim_reconciliation_v2") {
		return json.RawMessage(`[{"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","batch_id":"pid_10000004-0000-4000-8000-000000000004","generation":1,"attempt":1,"lease_expires_at":"2026-09-12T12:00:00Z","request_digest":"` + strings.Repeat("a", 64) + `","content_digest":"` + strings.Repeat("b", 64) + `","artifact_key":"runtime/v15/pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003/fixture.json","payload_size_bytes":42,"media_type":"application/json","schema_version":"runtime-event-v2"}]`), nil
	}
	if strings.Contains(query, "zasp_runtime_release_reconciliation") {
		return json.RawMessage(fmt.Sprintf(`{"batch_id":%q,"generation":1,"state":"retryable","replayed":false}`, args[3])), nil
	}
	return nil, errRuntimeUnavailable
}

type compositionArtifacts struct {
	productionRawArtifactStub
	inspections int
}

func (artifacts *compositionArtifacts) Inspect(context.Context, runtimeevent.RawArtifactInspect) (runtimeevent.RawArtifact, error) {
	artifacts.inspections++
	return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestArtifactNotFound
}

func TestProductionCompositionWiresPrecisionIntakeAndRecovery(t *testing.T) {
	values := validProductionIngestEnvironment()
	values["ZASP_RUNTIME_INGEST_SCHEMA"] = "runtime-event-v2"
	config, err := loadProductionIngestConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	database, artifacts := &compositionDatabase{}, &compositionArtifacts{}
	cloudChecks := 0
	now := time.Now().UTC()
	dependencies, err := composeProductionIngestDependencies(context.Background(), config, database, artifacts, func(context.Context) error { cloudChecks++; return nil }, func() time.Time { return now }, func() error { return nil })
	if err != nil || cloudChecks != 1 || len(database.queries) != 1 || !strings.Contains(database.queries[0], "zasp_production_runtime_precision_readiness") {
		t.Fatal("composition selected wrong startup authority", err, database.queries)
	}
	if err := dependencies.Reconcile(context.Background()); err != nil || artifacts.inspections != 1 || !strings.Contains(database.queries[len(database.queries)-1], "zasp_runtime_release_reconciliation") {
		t.Fatal("composition lost precise recovery", err, database.queries)
	}
	database.unready = true
	before := len(database.queries)
	if err := dependencies.Reconcile(context.Background()); err == nil || artifacts.inspections != 1 || len(database.queries) != before+1 {
		t.Fatal("cached health hid recovery drift", err)
	}
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	wire, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+wire)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-enrollment-v2")
	request.Header.Set("X-Zasp-Expected-Enrollment", strings.Repeat("a", 64))
	request.Header.Set("Idempotency-Key", "runtime-v2:"+strings.Repeat("b", 64))
	response := httptest.NewRecorder()
	dependencies.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || cloudChecks != 1 {
		t.Fatal("composition lost precise HTTP readiness", response.Code, cloudChecks)
	}
}
