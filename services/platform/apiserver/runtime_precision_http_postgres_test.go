package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Real client, HTTP and registered PostgreSQL intake. Transport and artifact
// storage are local fixtures, not deployed TLS or object-store evidence.
func TestRuntimePrecisionHTTPRegisteredIntake(t *testing.T) {
	exercisePrecisionHTTPIntake(t, false)
}

func TestRuntimePrecisionHTTPRecoversInterruptedUpload(t *testing.T) {
	exercisePrecisionHTTPIntake(t, true)
}

type preciseHTTPRecoveryArtifacts struct {
	postgresHTTPIngestArtifactStore
	loseResponse bool
	artifact     runtimeevent.RawArtifact
	inspections  int
}

type preciseHTTPRecoveryDatabase struct {
	runtimeevent.ProductionIngestDatabase
	lastQuery   string
	lastPayload json.RawMessage
	lastError   error
}

func (database *preciseHTTPRecoveryDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	payload, err := database.ProductionIngestDatabase.QueryJSON(ctx, query, args...)
	database.lastQuery, database.lastPayload, database.lastError = query, payload, err
	return payload, err
}

func (store *preciseHTTPRecoveryArtifacts) Put(ctx context.Context, request runtimeevent.RawArtifactPut) (runtimeevent.RawArtifact, error) {
	artifact, err := store.postgresHTTPIngestArtifactStore.Put(ctx, request)
	if err != nil {
		return artifact, err
	}
	store.artifact = artifact
	if store.loseResponse {
		store.loseResponse = false
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestUnknown
	}
	return artifact, nil
}

func (store *preciseHTTPRecoveryArtifacts) Inspect(_ context.Context, request runtimeevent.RawArtifactInspect) (runtimeevent.RawArtifact, error) {
	store.inspections++
	if request.Scope != store.artifact.Scope || request.Key != store.artifact.Key || request.ContentDigest != store.artifact.ContentDigest || request.Size != store.artifact.Size || request.MediaType != store.artifact.MediaType {
		return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestArtifactDrift
	}
	return store.artifact, nil
}

func exercisePrecisionHTTPIntake(t *testing.T, interrupted bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	scope := fixtureRequestIdentity(t).Scope
	const sensorID = "pid_76000501-0000-4000-8000-000000000501"
	const tokenID = "pid_76000502-0000-4000-8000-000000000502"
	const nextTokenID = "pid_76000503-0000-4000-8000-000000000503"
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	if _, err := admin.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'precise-http-sensor','tetragon')`, org, workspace, environment, sensorID); err != nil {
		t.Fatal(err)
	}
	wire, locator, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, 0xe1)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, org, workspace, environment, sensorID, tokenID, locator, salt, hash); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_ingest"
	ingest, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer ingest.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: ingest})
	if err != nil {
		t.Fatal(err)
	}
	trace := &preciseHTTPRecoveryDatabase{ProductionIngestDatabase: database}
	repository, err := runtimeevent.NewPostgresPreciseProductionIngestRepository(trace)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	artifacts := &preciseHTTPRecoveryArtifacts{loseResponse: interrupted}
	handler, err := runtimeevent.NewPreciseProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sensor.EnrollmentBinding(scope, mustProductID(t, sensorID))
	if err != nil {
		t.Fatal(err)
	}
	credential, lostResponse, wrongBinding := wire, !interrupted, false
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Now: func() time.Time { return now },
		Token: func() ([]byte, error) { return []byte(credential), nil },
		Do: func(request *http.Request) (*http.Response, error) {
			if wrongBinding {
				request.Header.Set("X-Zasp-Expected-Enrollment", strings.Repeat("f", 64))
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if lostResponse {
				lostResponse = false
				if response.Code != http.StatusAccepted {
					t.Fatalf("first intake status=%d body=%s", response.Code, response.Body.String())
				}
				return nil, errors.New("response lost after durable acceptance")
			}
			return response.Result(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := sensoradapter.PreciseRuntimeEvent{
		RuntimeEvent:    sensoradapter.RuntimeEvent{EventID: "tetragon:" + strings.Repeat("a", 64), Class: "process", Action: "exec", WorkloadID: "k8s:" + strings.Repeat("b", 64), EventTime: "2026-08-20T12:00:00.123Z", EvidenceID: "pid_76000504-0000-4000-8000-000000000504"},
		ObservedLineage: runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: "2026-08-20T12:00:00.123456789Z", CgroupID: "12345"}, SourceEventTime: "2026-08-20T12:00:00.123999999Z"},
	}
	envelope, err := client.PreparePreciseEnvelope([]sensoradapter.PreciseRuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IngestPreciseEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 1 {
		t.Fatal("lost response", err, artifacts.calls)
	}
	if interrupted {
		// Fixture clock advancement, scoped to this upload. Do not disable any
		// release guard or grant a test-only execution capability.
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET available_at=clock_timestamp()-interval '1 second' WHERE batch_id=(SELECT batch_id FROM zasp_runtime_batch_authorities WHERE sensor_id=$1)`, sensorID); err != nil {
			t.Fatal(err)
		}
		reconciler, err := runtimeevent.NewPreciseProductionIngestReconciler(runtimeevent.ProductionIngestReconcilerConfig{Repository: repository, Artifacts: artifacts, WorkerID: "precise-http-recovery", LeaseSeconds: 60, ClaimLimit: 1, OperationTimeout: 10 * time.Second, NewLeaseToken: func() (string, error) { return "precision-http-recovery-token-0001", nil }})
		if err != nil {
			t.Fatal(err)
		}
		if err := reconciler.RunOnce(ctx); err != nil || artifacts.inspections != 1 || artifacts.calls != 1 {
			t.Fatal("interrupted upload recovery", err, artifacts.inspections, artifacts.calls, trace.lastQuery, string(trace.lastPayload), trace.lastError)
		}
		var state string
		if err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_ingest_reconciliation_work WHERE batch_id=(SELECT batch_id FROM zasp_runtime_batch_authorities WHERE sensor_id=$1)`, sensorID).Scan(&state); err != nil || state != "succeeded" {
			t.Fatal("recovery was not durable", state, err)
		}
	}
	archive, err := runtimeevent.DecodePreciseArchivedBatch(scope, artifacts.request.Body)
	if err != nil || len(archive.Records) != 1 || archive.Records[0].ObservedLineage != event.ObservedLineage {
		t.Fatal("source precision changed", err)
	}
	var schema, versions string
	if err := admin.QueryRow(ctx, `SELECT payload_schema_version,(SELECT string_agg(implementation_version,',' ORDER BY stage_order) FROM zasp_runtime_stage_work s WHERE s.batch_id=b.batch_id) FROM zasp_runtime_batch_authorities b WHERE sensor_id=$1`, sensorID).Scan(&schema, &versions); err != nil || schema != "runtime-event-v2" || versions != "runtime-archive-v2,runtime-index-v2,runtime-correlation-v4,runtime-projection-v3,runtime-complete-v3" {
		t.Fatal("persisted precision tuple", schema, versions, err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('batches',(SELECT jsonb_agg(to_jsonb(b) ORDER BY batch_id) FROM zasp_runtime_batch_authorities b),'stages',(SELECT jsonb_agg(to_jsonb(s) ORDER BY batch_id,stage) FROM zasp_runtime_stage_work s),'jobs',(SELECT jsonb_agg(to_jsonb(j) ORDER BY id) FROM zasp_discovery_jobs j),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM zasp_discovery_outbox o))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	rotated, nextLocator, nextSalt, nextHash := envelopeLifecycleCredential(t, nextTokenID, 2, 0xe2)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_rotate_sensor_token($1,$2,$3,$4,$5,$6,2,1,$7,$8,$9,$10)`, org, workspace, environment, sensorID, tokenID, nextTokenID, nextLocator, nextSalt, nextHash, time.Now().UTC().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	credential = rotated
	if err := client.IngestPreciseEnvelope(ctx, envelope); err != nil || artifacts.calls != 1 || snapshot() != before {
		t.Fatal("rotation replay changed durable intake", err)
	}
	wrongBinding = true
	if err := client.IngestPreciseEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientDenied) || artifacts.calls != 1 || snapshot() != before {
		t.Fatal("wrong enrollment accepted or wrote", err)
	}
	wrongBinding = false
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	if err := client.IngestPreciseEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 1 || snapshot() != before {
		t.Fatal("drifted release replay accepted or wrote", err)
	}
}
