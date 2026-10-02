package apiserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func assertCurrentRuntimeSemanticIntake(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *runtimeevent.PostgresProductionIngestRepository, wire, sensorID string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	artifacts := &postgresHTTPIngestArtifactStore{}
	handler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"source":"otlp","events":[{"event_time":"` + now.Format("2006-01-02T15:04:05.000Z") + `","evidence_id":"pid_f0800000-0000-4000-8000-000000009005","attributes":{"event.id":"current-semantic-1","event.class":"tool","event.action":"invoke","agent.id":"pid_f0800000-0000-4000-8000-000000009011","session.id":"pid_f0800000-0000-4000-8000-000000009012","task.id":"task-a","tool.id":"tool-a","sandbox.id":"sandbox-a","trace.id":"0123456789abcdef0123456789abcdef","span.id":"0123456789abcdef"},"content":{"binary":"agent"}}]}`)
	for i := 0; i < 2; i++ {
		operation, cancel := context.WithTimeout(ctx, 10*time.Second)
		started := time.Now()
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body)).WithContext(operation)
		request.Header.Set("Authorization", "Bearer "+wire)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
		request.Header.Set("Idempotency-Key", "current-runtime-semantic-0001")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		t.Logf("current semantic HTTP attempt=%d elapsed=%s deadline=%t", i, time.Since(started).Round(time.Millisecond), errors.Is(operation.Err(), context.DeadlineExceeded))
		cancel()
		if response.Code != http.StatusAccepted {
			t.Fatal("current semantic intake or accepted replay", i, response.Code)
		}
	}
	var count int
	var schema, stages string
	if err := owner.QueryRow(ctx, `SELECT count(*),min(payload_schema_version),min((SELECT string_agg(implementation_version,',' ORDER BY stage_order) FROM zasp_runtime_stage_work s WHERE s.batch_id=b.batch_id)) FROM zasp_runtime_batch_authorities b WHERE sensor_id=$1`, sensorID).Scan(&count, &schema, &stages); err != nil || count != 1 || schema != "runtime-event-v1" || stages != "runtime-archive-v1,runtime-index-v1,runtime-correlation-v3,runtime-projection-v2,runtime-complete-v2" {
		t.Fatal("current semantic durable source tuple", count, schema, stages, err)
	}
}

func assertCurrentRuntimePreciseRecovery(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *runtimeevent.PostgresProductionIngestRepository, wire, sensorID string, scope domain.Scope) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	artifacts := &preciseHTTPRecoveryArtifacts{loseResponse: true}
	handler, err := runtimeevent.NewPreciseProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sensor.EnrollmentBinding(scope, mustProductID(t, sensorID))
	if err != nil {
		t.Fatal(err)
	}
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Now: func() time.Time { return now },
		Token: func() ([]byte, error) { return []byte(wire), nil },
		Do: func(request *http.Request) (*http.Response, error) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			return response.Result(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := sensoradapter.PreciseRuntimeEvent{
		RuntimeEvent:    sensoradapter.RuntimeEvent{EventID: "tetragon:" + strings.Repeat("a", 64), Class: "process", Action: "exec", WorkloadID: "k8s:" + strings.Repeat("b", 64), EventTime: now.Format("2006-01-02T15:04:05.000Z"), EvidenceID: "pid_f0800000-0000-4000-8000-000000009006"},
		ObservedLineage: runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: now.Add(-time.Second).Format(time.RFC3339Nano), CgroupID: "12345"}, SourceEventTime: now.Format(time.RFC3339Nano)},
	}
	envelope, err := client.PreparePreciseEnvelope([]sensoradapter.PreciseRuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithTimeout(ctx, 10*time.Second)
	started := time.Now()
	err = client.IngestPreciseEnvelope(operation, envelope)
	t.Logf("current precise HTTP elapsed=%s deadline=%t", time.Since(started).Round(time.Millisecond), errors.Is(operation.Err(), context.DeadlineExceeded))
	cancel()
	if !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 1 {
		t.Fatal("current interrupted precise upload", err, artifacts.calls)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET available_at=clock_timestamp()-interval '1 second' WHERE batch_id=(SELECT batch_id FROM zasp_runtime_batch_authorities WHERE sensor_id=$1)`, sensorID); err != nil {
		t.Fatal(err)
	}
	reconciler, err := runtimeevent.NewPreciseProductionIngestReconciler(runtimeevent.ProductionIngestReconcilerConfig{Repository: repository, Artifacts: artifacts, WorkerID: "current-runtime-recovery", LeaseSeconds: 60, ClaimLimit: 1, OperationTimeout: 10 * time.Second, NewLeaseToken: func() (string, error) { return "current-runtime-recovery-token-0001", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.RunOnce(ctx); err != nil || artifacts.inspections != 1 || artifacts.calls != 1 {
		t.Fatal("current precise backlog recovery", err, artifacts.inspections, artifacts.calls)
	}
	var schema, stages, recovery string
	if err := owner.QueryRow(ctx, `SELECT payload_schema_version,(SELECT string_agg(implementation_version,',' ORDER BY stage_order) FROM zasp_runtime_stage_work s WHERE s.batch_id=b.batch_id),(SELECT state FROM zasp_runtime_ingest_reconciliation_work r WHERE r.batch_id=b.batch_id) FROM zasp_runtime_batch_authorities b WHERE sensor_id=$1`, sensorID).Scan(&schema, &stages, &recovery); err != nil || schema != "runtime-event-v2" || recovery != "succeeded" || stages != "runtime-archive-v2,runtime-index-v2,runtime-correlation-v4,runtime-projection-v3,runtime-complete-v3" {
		t.Fatal("current precise durable recovery tuple", schema, stages, recovery, err)
	}
}
