package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// The artifact fixture stores the upload but loses its response. Reservations,
// credential rotation, reconciliation leases and receipt lookup use actual SQL
// through the registered ingest role. This is not deployed object-store proof.
func exerciseIncompleteAcceptanceRotation(t *testing.T, ctx context.Context, admin, ingest *pgx.Conn, scope domain.Scope, now time.Time) {
	t.Helper()
	const sensorID = "pid_76000401-0000-4000-8000-000000000401"
	const tokenID = "pid_76000402-0000-4000-8000-000000000402"
	const nextTokenID = "pid_76000403-0000-4000-8000-000000000403"
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	if _, err := admin.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'incomplete-envelope-sensor','tetragon')`, org, workspace, environment, sensorID); err != nil {
		t.Fatal(err)
	}
	wire, locator, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, 0xd1)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, org, workspace, environment, sensorID, tokenID, locator, salt, hash); err != nil {
		t.Fatal(err)
	}
	binding, err := sensor.EnrollmentBinding(scope, mustProductID(t, sensorID))
	if err != nil {
		t.Fatal(err)
	}
	driver := &envelopeDriverTrace{PostgresDriver: &integrationPostgresDriver{connection: ingest}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionIngestRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	trace := &envelopeRepositoryTrace{ProductionIngestRepository: repository}
	artifacts := &acceptanceLostArtifactResponse{}
	handler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: trace, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	credential := wire
	var bodies [][]byte
	var keys []string
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Now: func() time.Time { return now },
		Token: func() ([]byte, error) { return []byte(credential), nil },
		Do: func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			_ = request.Body.Close()
			bodies = append(bodies, bytes.Clone(body))
			keys = append(keys, request.Header.Get("Idempotency-Key"))
			request.Body = io.NopCloser(bytes.NewReader(body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			return response.Result(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := client.PrepareEnvelope([]sensoradapter.RuntimeEvent{{EventID: "tetragon:" + strings.Repeat("e", 64), Class: "process", Action: "exec", WorkloadID: "k8s:" + strings.Repeat("b", 64), EventTime: now.Format("2006-01-02T15:04:05.000Z"), EvidenceID: "pid_76000404-0000-4000-8000-000000000404", Content: map[string]string{"binary_digest": "sha256:" + strings.Repeat("c", 64)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 1 || trace.reserves != 1 || trace.finalizes != 0 {
		t.Fatal("lost upload response didn't preserve incomplete reservation", err)
	}
	request := trace.acceptanceRequest
	batch := request.BatchID.String()
	snapshot := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('authority',to_jsonb(a),'work',to_jsonb(w))::text FROM zasp_runtime_batch_authorities a JOIN zasp_runtime_ingest_reconciliation_work w USING(organization_id,workspace_id,environment_id,batch_id) WHERE (a.organization_id,a.workspace_id,a.environment_id,a.batch_id)=($1,$2,$3,$4)`, org, workspace, environment, batch).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	original := snapshot()
	nextWire, nextLocator, nextSalt, nextHash := envelopeLifecycleCredential(t, nextTokenID, 2, 0xd5)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_rotate_sensor_token($1,$2,$3,$4,$5,$6,2,1,$7,$8,$9,transaction_timestamp()+interval '1 day')`, org, workspace, environment, sensorID, tokenID, nextTokenID, nextLocator, nextSalt, nextHash); err != nil {
		t.Fatal(err)
	}
	credential = nextWire
	parsed, err := sensor.ParseTokenCredential(nextWire)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	for _, state := range []string{"uploading", "unknown"} {
		t.Run(state, func(t *testing.T) {
			if state == "unknown" {
				// Fixture-only alternate incomplete state, not a claimed worker transition.
				if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_batch_authorities SET state='unknown' WHERE (organization_id,workspace_id,environment_id,batch_id)=($1,$2,$3,$4)`, org, workspace, environment, batch); err != nil {
					t.Fatal(err)
				}
				original = snapshot()
			}
			acceptance, err := repository.LookupAcceptance(ctx, parsed, request)
			if err != nil || acceptance.Found {
				t.Fatal("incomplete upload returned acceptance", err)
			}
			driver.lastErrorCode = ""
			trace.authenticatedGeneration = 0
			reservesBefore := trace.reserves
			if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) || trace.authenticatedGeneration != 2 || driver.lastErrorCode != "23505" || trace.reserves != reservesBefore+1 || trace.finalizes != 0 || artifacts.calls != 1 || snapshot() != original {
				t.Fatal("replacement credential adopted or changed incomplete upload", err)
			}
		})
	}
	// Only advance this fixture's scheduling time. Claim/finish authority and
	// all durable finalization work still execute through the actual ingest role.
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET available_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,batch_id)=($1,$2,$3,$4)`, org, workspace, environment, batch); err != nil {
		t.Fatal(err)
	}
	const worker, lease = "acceptance-rotation-worker", "acceptance-rotation-lease-0001"
	var raw json.RawMessage
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation($1,$2,60,1)`, worker, lease).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claims []struct {
		BatchID    string `json:"batch_id"`
		Generation int64  `json:"generation"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 || claims[0].BatchID != batch || claims[0].Generation != 1 {
		t.Fatal("reconciler didn't claim exact incomplete upload", err)
	}
	artifact := artifacts.stored
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_finish_reconciliation($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, org, workspace, environment, batch, worker, lease, request.JobID.String(), request.OutboxID.String(), artifact.Reference, artifact.Key, artifact.VersionID, artifact.ContentDigest[:], artifact.Size, artifact.KMSKeyARN).Scan(&raw); err != nil {
		t.Fatal("reconcile uploaded artifact after rotation", err)
	}
	var state, provenanceToken string
	var generation int64
	var stages, outbox int
	if err := admin.QueryRow(ctx, `SELECT state,sensor_token_id,token_generation,(SELECT count(*) FROM zasp_runtime_stage_work WHERE (organization_id,workspace_id,environment_id,batch_id)=($1,$2,$3,$4)),(SELECT count(*) FROM zasp_discovery_outbox WHERE (organization_id,workspace_id,environment_id,deterministic_key)=($1,$2,$3,'runtime:'||$4)) FROM zasp_runtime_batch_authorities WHERE (organization_id,workspace_id,environment_id,batch_id)=($1,$2,$3,$4)`, org, workspace, environment, batch).Scan(&state, &provenanceToken, &generation, &stages, &outbox); err != nil || state != "queued" || provenanceToken != tokenID || generation != 1 || stages != 5 || outbox != 1 {
		t.Fatalf("reconciled state=%s provenance=%s/%d stages=%d outbox=%d err=%v", state, provenanceToken, generation, stages, outbox, err)
	}
	settled := snapshot()
	for attempt := 0; attempt < 2; attempt++ {
		if err := client.IngestEnvelope(ctx, envelope); err != nil || artifacts.calls != 1 || trace.finalizes != 0 || snapshot() != settled {
			t.Fatal("reconciled receipt failed or duplicated work", err)
		}
	}
	if len(bodies) != 5 {
		t.Fatalf("attempts=%d want=5", len(bodies))
	}
	for index, body := range bodies {
		if !bytes.Equal(body, envelope.Body) || keys[index] != envelope.IdempotencyKey {
			t.Fatal("rotation or reconciliation changed the frozen request")
		}
	}
}

type acceptanceLostArtifactResponse struct {
	postgresHTTPIngestArtifactStore
	stored runtimeevent.RawArtifact
}

func (store *acceptanceLostArtifactResponse) Put(ctx context.Context, request runtimeevent.RawArtifactPut) (runtimeevent.RawArtifact, error) {
	artifact, err := store.postgresHTTPIngestArtifactStore.Put(ctx, request)
	if err != nil {
		return runtimeevent.RawArtifact{}, err
	}
	store.stored = artifact
	return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngestUnknown
}
