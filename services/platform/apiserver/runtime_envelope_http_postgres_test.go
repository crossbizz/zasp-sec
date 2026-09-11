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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Composes the actual sensor client, HTTP handler, registered ingest principal
// and PostgreSQL credential lifecycle. Transport and artifact storage are local
// test doubles. This does not establish TLS, S3 or deployed sensor readiness.
func exerciseBoundRuntimeEnvelopeLifecycle(t *testing.T, ctx context.Context, admin, ingestConnection *pgx.Conn, scope domain.Scope, sensorID, tokenID, initialWire string, now time.Time) {
	t.Helper()
	binding, err := sensor.EnrollmentBinding(scope, mustProductID(t, sensorID))
	if err != nil {
		t.Fatal(err)
	}
	artifacts := &postgresHTTPIngestArtifactStore{}
	driverTrace := &envelopeDriverTrace{PostgresDriver: &integrationPostgresDriver{connection: ingestConnection}}
	database, err := NewPostgresJSONDatabase(driverTrace)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionIngestRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	trace := &envelopeRepositoryTrace{ProductionIngestRepository: repository}
	handler, err := runtimeevent.NewProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: trace, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	credential := initialWire
	tokenReads, calls, bodyReads := 0, 0, 0
	lostResponse := true
	var beforeBodyRead func()
	var acceptedBody string
	var sentBodies [][]byte
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: binding,
		Now:   func() time.Time { return now },
		Token: func() ([]byte, error) { tokenReads++; return []byte(credential), nil },
		Do: func(request *http.Request) (*http.Response, error) {
			calls++
			var captured bytes.Buffer
			request.Body = &envelopeObservedBody{ReadCloser: request.Body, read: func() {
				bodyReads++
				if beforeBodyRead != nil {
					action := beforeBodyRead
					beforeBodyRead = nil
					action()
				}
			}, captured: &captured}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			sentBodies = append(sentBodies, bytes.Clone(captured.Bytes()))
			if response.Code == http.StatusAccepted {
				if acceptedBody != "" && response.Body.String() != acceptedBody {
					t.Fatal("rotation changed accepted batch")
				}
				acceptedBody = response.Body.String()
			}
			if lostResponse {
				lostResponse = false
				if response.Code != http.StatusAccepted {
					t.Fatalf("first envelope status=%d", response.Code)
				}
				return nil, errors.New("test response lost after acceptance")
			}
			return response.Result(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := sensoradapter.RuntimeEvent{EventID: "tetragon:" + strings.Repeat("a", 64), Class: "process", Action: "exec", WorkloadID: "k8s:" + strings.Repeat("b", 64), EventTime: now.Format("2006-01-02T15:04:05.000Z"), EvidenceID: "pid_76000201-0000-4000-8000-000000000201", Content: map[string]string{"binary_digest": "sha256:" + strings.Repeat("c", 64)}}
	envelope, err := client.PrepareEnvelope([]sensoradapter.RuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 1 || tokenReads != 1 {
		t.Fatalf("lost response outcome=%v puts=%d reads=%d", err, artifacts.calls, tokenReads)
	}
	counts := func() [3]int {
		t.Helper()
		var result [3]int
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_batch_authorities),(SELECT count(*) FROM zasp_runtime_stage_work),(SELECT count(*) FROM zasp_discovery_outbox WHERE deterministic_key LIKE 'runtime:%')`).Scan(&result[0], &result[1], &result[2]); err != nil {
			t.Fatal(err)
		}
		return result
	}
	baseline := counts()
	provenance := func() string {
		t.Helper()
		var value string
		if err := admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(authority) ORDER BY batch_id)::text FROM zasp_runtime_batch_authorities authority`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	originalProvenance := provenance()
	replacementID := "pid_76000202-0000-4000-8000-000000000202"
	rotated, locator, salt, hash := envelopeLifecycleCredential(t, replacementID, 2, 0x91)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_rotate_sensor_token($1,$2,$3,$4,$5,$6,2,1,$7,$8,$9,$10)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, tokenID, replacementID, locator, salt, hash, time.Now().UTC().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	credential = rotated
	t.Run("same enrollment finalized receipt after rotation", func(t *testing.T) {
		if err := client.IngestEnvelope(ctx, envelope); err != nil || artifacts.calls != 1 || counts() != baseline || provenance() != originalProvenance || tokenReads != 2 || !bytes.Equal(sentBodies[0], envelope.Body) || !bytes.Equal(sentBodies[1], envelope.Body) {
			t.Fatalf("same enrollment rotation failed: %v; authenticated generation=%d reserve calls=%d finalize calls=%d reserve error=%v SQLSTATE=%s", err, trace.authenticatedGeneration, trace.reserves, trace.finalizes, trace.reserveError, driverTrace.lastErrorCode)
		}
	})
	t.Run("release checksum drift rejects accepted replay", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=48`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=48`, migrations.ProductionRuntimeAcceptance().Checksum()); err != nil {
				t.Error(err)
			}
		}()
		if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) || artifacts.calls != 1 || counts() != baseline || provenance() != originalProvenance {
			t.Fatalf("checksum drift accepted replay or changed durable work: %v", err)
		}
	})
	t.Run("authority changes while authentication waits", func(t *testing.T) {
		var accepted struct {
			BatchID string `json:"batch_id"`
		}
		if err := json.Unmarshal([]byte(acceptedBody), &accepted); err != nil {
			t.Fatal(err)
		}
		var jobID, outboxID string
		if err := admin.QueryRow(ctx, `SELECT j.id,o.id FROM zasp_discovery_jobs j JOIN zasp_discovery_outbox o ON (o.organization_id,o.workspace_id,o.environment_id,o.deterministic_key)=(j.organization_id,j.workspace_id,j.environment_id,'runtime:'||j.authority_id) WHERE j.kind='runtime' AND j.authority_id=$1`, accepted.BatchID).Scan(&jobID, &outboxID); err != nil {
			t.Fatal(err)
		}
		parsed, err := sensor.ParseTokenCredential(rotated)
		if err != nil {
			t.Fatal(err)
		}
		defer parsed.Destroy()
		partsLocator, partsSecret, err := parsed.Parts()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(partsLocator)
		defer clear(partsSecret)
		arguments := []any{partsLocator, partsSecret, binding, accepted.BatchID, envelope.IdempotencyKey, artifacts.request.ContentDigest[:], "tetragon", "application/json", "runtime-event-v1", int64(len(artifacts.request.Body)), 1, jobID, outboxID, migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint()}
		for _, scenario := range []string{"principal revoked", "release checksum drift", "credential expires"} {
			t.Run(scenario, func(t *testing.T) {
				exerciseAcceptanceAuthenticationWait(t, ctx, admin, ingestConnection, replacementID, arguments, scenario)
				if counts() != baseline || provenance() != originalProvenance || artifacts.calls != 1 {
					t.Fatal("denied acceptance after wait changed durable work")
				}
			})
		}
		t.Run("batch lock is an immediate retry", func(t *testing.T) {
			exerciseAcceptanceBatchLock(t, ctx, admin, ingestConnection, replacementID, arguments)
		})
		t.Run("damaged durable bindings cannot become acceptance", func(t *testing.T) {
			exerciseAcceptanceDamagedBindings(t, ctx, admin, ingestConnection, arguments)
		})
		t.Run("foreign scope reusing sensor ID", func(t *testing.T) {
			exerciseAcceptanceForeignScopes(t, ctx, admin, ingestConnection, scope, sensorID, handler, envelope, arguments, now)
		})
		if counts() != baseline || provenance() != originalProvenance || artifacts.calls != 1 {
			t.Fatal("acceptance boundary probes changed durable work")
		}
	})
	t.Run("previously accepted quarantined batch", func(t *testing.T) {
		var accepted struct {
			BatchID string `json:"batch_id"`
		}
		if err := json.Unmarshal([]byte(acceptedBody), &accepted); err != nil {
			t.Fatal(err)
		}
		// Fixture-only downstream state transition. Acceptance still requires the
		// original exact artifact, batch, job, outbox and stage bindings.
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_batch_authorities SET state='quarantined' WHERE batch_id=$1`, accepted.BatchID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_batch_authorities SET state='queued' WHERE batch_id=$1`, accepted.BatchID); err != nil {
				t.Error(err)
			}
		}()
		if err := client.IngestEnvelope(ctx, envelope); err != nil || artifacts.calls != 1 || counts() != baseline {
			t.Fatalf("accepted quarantine receipt rejected: %v", err)
		}
	})

	credential = initialWire
	readsBefore := bodyReads
	t.Run("revoked prior credential", func(t *testing.T) {
		if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientDenied) || bodyReads != readsBefore || artifacts.calls != 1 || counts() != baseline {
			t.Fatalf("revoked prior credential result=%v", err)
		}
	})

	otherSensor, otherToken := "pid_76000203-0000-4000-8000-000000000203", "pid_76000204-0000-4000-8000-000000000204"
	if _, err := admin.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'other-envelope-sensor','tetragon')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), otherSensor); err != nil {
		t.Fatal(err)
	}
	otherWire, otherLocator, otherSalt, otherHash := envelopeLifecycleCredential(t, otherToken, 1, 0xa1)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), otherSensor, otherToken, otherLocator, otherSalt, otherHash); err != nil {
		t.Fatal(err)
	}
	credential = otherWire
	t.Run("cross enrollment replacement denied before body", func(t *testing.T) {
		if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientDenied) || bodyReads != readsBefore || artifacts.calls != 1 || counts() != baseline {
			t.Fatalf("cross-enrollment credential result=%v", err)
		}
	})

	// The callback runs only when the handler starts reading the body, after
	// successful authentication/binding and before the real reservation SQL.
	credential = rotated
	event.EventID = "tetragon:" + strings.Repeat("d", 64)
	event.EvidenceID = "pid_76000205-0000-4000-8000-000000000205"
	fresh, err := client.PrepareEnvelope([]sensoradapter.RuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	revocations := 0
	beforeBodyRead = func() {
		if _, err := admin.Exec(ctx, `SELECT zasp_runtime_revoke_sensor_token($1,$2,$3,$4,$5)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, replacementID); err != nil {
			t.Fatal(err)
		}
		revocations++
	}
	t.Run("revoked after authentication before reservation", func(t *testing.T) {
		if err := client.IngestEnvelope(ctx, fresh); !errors.Is(err, sensoradapter.ErrClientRetryable) || revocations != 1 || bodyReads <= readsBefore || artifacts.calls != 1 || counts() != baseline || provenance() != originalProvenance {
			t.Fatalf("post-auth revocation result=%v count=%d", err, revocations)
		}
	})
	if tokenReads != calls || calls != 7 {
		t.Fatalf("credential reads=%d attempts=%d", tokenReads, calls)
	}
}

const acceptanceBoundaryLookupSQL = `SELECT zasp_runtime_lookup_acceptance($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

func exerciseAcceptanceForeignScopes(t *testing.T, ctx context.Context, admin, ingest *pgx.Conn, original domain.Scope, sensorID string, handler http.Handler, envelope sensoradapter.RuntimeEnvelope, arguments []any, now time.Time) {
	t.Helper()
	for index, dimension := range []string{"organization", "workspace", "environment"} {
		t.Run(dimension, func(t *testing.T) {
			ids := []domain.ProductID{original.OrganizationID(), original.WorkspaceID(), original.EnvironmentID()}
			ids[index] = mustProductID(t, "pid_76000301-0000-4000-8000-000000000301")
			foreign, err := domain.NewScope(ids[0], ids[1], ids[2])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,'foreign-envelope-sensor','tetragon')`, ids[0].String(), ids[1].String(), ids[2].String(), sensorID); err != nil {
				t.Fatal(err)
			}
			const tokenID = "pid_76000302-0000-4000-8000-000000000302"
			wire, locatorDigest, salt, hash := envelopeLifecycleCredential(t, tokenID, 1, byte(0xb1+index*4))
			if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, ids[0].String(), ids[1].String(), ids[2].String(), sensorID, tokenID, locatorDigest, salt, hash); err != nil {
				t.Fatal(err)
			}
			credential, err := sensor.ParseTokenCredential(wire)
			if err != nil {
				t.Fatal(err)
			}
			defer credential.Destroy()
			locator, secret, err := credential.Parts()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(locator)
			defer clear(secret)
			probe := append([]any(nil), arguments...)
			probe[0], probe[1] = locator, secret
			var raw json.RawMessage
			err = ingest.QueryRow(ctx, acceptanceBoundaryLookupSQL, probe...).Scan(&raw)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "28000" {
				t.Fatal("foreign scope authorized original enrollment", err)
			}
			// A valid credential under its own binding must also see no receipt
			// for the original scope's exact batch/key, despite the shared sensor ID.
			foreignBinding, err := sensor.EnrollmentBinding(foreign, mustProductID(t, sensorID))
			if err != nil {
				t.Fatal(err)
			}
			probe[2] = foreignBinding
			if err := ingest.QueryRow(ctx, acceptanceBoundaryLookupSQL, probe...).Scan(&raw); err != nil || string(raw) != `{"found": false}` {
				t.Fatal("foreign scope exposed acceptance", err)
			}
			bodyReads, calls := 0, 0
			client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
				BaseURL: "https://runtime.example.test", EnrollmentBinding: arguments[2].(string), Now: func() time.Time { return now },
				Token: func() ([]byte, error) { return []byte(wire), nil },
				Do: func(request *http.Request) (*http.Response, error) {
					calls++
					request.Body = &envelopeObservedBody{ReadCloser: request.Body, read: func() { bodyReads++ }, captured: &bytes.Buffer{}}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					return response.Result(), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientDenied) || calls != 1 || bodyReads != 0 {
				t.Fatalf("foreign scope HTTP denial=%v calls=%d body reads=%d", err, calls, bodyReads)
			}
		})
	}
}

func exerciseAcceptanceBatchLock(t *testing.T, ctx context.Context, admin, ingest *pgx.Conn, tokenID string, arguments []any) {
	t.Helper()
	locker, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close(context.Background())
	lock, err := locker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err := lock.Exec(ctx, `SELECT batch_id FROM zasp_runtime_batch_authorities WHERE batch_id=$1 FOR UPDATE`, arguments[3]); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var raw json.RawMessage
	err = ingest.QueryRow(bounded, acceptanceBoundaryLookupSQL, arguments...).Scan(&raw)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
		t.Fatal("batch contention wasn't rejected by NOWAIT", err)
	}
	// A failed lookup must release its authentication locks while the worker
	// still owns the batch. This checks the inverse lock-order escape itself.
	if _, err := lock.Exec(ctx, `SELECT id FROM zasp_sensor_tokens WHERE id=$1 FOR UPDATE NOWAIT`, tokenID); err != nil {
		t.Fatal("failed acceptance retained sensor authority", err)
	}
}

func exerciseAcceptanceDamagedBindings(t *testing.T, ctx context.Context, admin, ingest *pgx.Conn, arguments []any) {
	t.Helper()
	for _, scenario := range []struct {
		name, table, key, column, expression string
		id                                   any
	}{
		{"artifact checksum", "zasp_runtime_batch_authorities", "batch_id", "raw_artifact_checksum", "decode(repeat('f',64),'hex')", arguments[3]},
		{"batch event count", "zasp_runtime_batches", "id", "event_count", "event_count+1", arguments[3]},
		{"job request digest", "zasp_discovery_jobs", "id", "request_digest", "decode(repeat('f',64),'hex')", arguments[11]},
		{"outbox payload", "zasp_discovery_outbox", "id", "payload", "jsonb_set(payload,'{event_count}','999'::jsonb)", arguments[12]},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			// Every identifier/expression is a fixed fixture literal above. These
			// deliberate corruptions affect only this disposable PostgreSQL test.
			table, key, column := pgx.Identifier{scenario.table}.Sanitize(), pgx.Identifier{scenario.key}.Sanitize(), pgx.Identifier{scenario.column}.Sanitize()
			var saved json.RawMessage
			if err := admin.QueryRow(ctx, "SELECT to_jsonb(x) FROM "+table+" x WHERE "+key+"=$1", scenario.id).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, "UPDATE "+table+" SET "+column+"=(SELECT "+column+" FROM jsonb_populate_record(NULL::"+table+",$2::jsonb)) WHERE "+key+"=$1", scenario.id, saved); err != nil {
					t.Error("restore fixture binding", err)
				}
			}()
			if _, err := admin.Exec(ctx, "UPDATE "+table+" SET "+column+"="+scenario.expression+" WHERE "+key+"=$1", scenario.id); err != nil {
				t.Fatal("install corrupt fixture", err)
			}
			requireAcceptanceBindingDenied(t, ctx, ingest, arguments)
		})
	}
	t.Run("missing stage", func(t *testing.T) {
		var saved json.RawMessage
		if err := admin.QueryRow(ctx, `DELETE FROM zasp_runtime_stage_work x WHERE batch_id=$1 AND stage='complete' RETURNING to_jsonb(x)`, arguments[3]).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work SELECT * FROM jsonb_populate_record(NULL::zasp_runtime_stage_work,$1::jsonb)`, saved); err != nil {
				t.Error("restore fixture stage", err)
			}
		}()
		requireAcceptanceBindingDenied(t, ctx, ingest, arguments)
	})
	var restored struct {
		Found bool `json:"found"`
	}
	var raw json.RawMessage
	if err := ingest.QueryRow(ctx, acceptanceBoundaryLookupSQL, arguments...).Scan(&raw); err != nil || json.Unmarshal(raw, &restored) != nil || !restored.Found {
		t.Fatal("restored complete receipt not accepted", err)
	}
}

func requireAcceptanceBindingDenied(t *testing.T, ctx context.Context, ingest *pgx.Conn, arguments []any) {
	t.Helper()
	var raw json.RawMessage
	err := ingest.QueryRow(ctx, acceptanceBoundaryLookupSQL, arguments...).Scan(&raw)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
		t.Fatal("damaged durable binding accepted", err)
	}
}

func envelopeLifecycleCredential(t *testing.T, id string, generation uint64, seed byte) (string, []byte, []byte, []byte) {
	t.Helper()
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{seed}, 16), bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	locator, err := credential.LocatorDigest()
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{seed + 2}, 32)
	hash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, id), generation, salt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return wire, locator[:], salt, hash[:]
}

type envelopeObservedBody struct {
	io.ReadCloser
	read     func()
	captured *bytes.Buffer
}

func (body *envelopeObservedBody) Read(value []byte) (int, error) {
	body.read()
	n, err := body.ReadCloser.Read(value)
	_, _ = body.captured.Write(value[:n])
	return n, err
}

// Pass-through observations locate a failure without substituting authority or
// exposing credentials. All authentication, reservation and finalization are real.
type envelopeRepositoryTrace struct {
	runtimeevent.ProductionIngestRepository
	authenticatedGeneration int64
	reserves, finalizes     int
	reserveError            error
	acceptanceRequest       runtimeevent.IngestAcceptanceRequest
}

func (trace *envelopeRepositoryTrace) Authenticate(ctx context.Context, credential *sensor.TokenCredential) (runtimeevent.IngestAuthority, error) {
	authority, err := trace.ProductionIngestRepository.Authenticate(ctx, credential)
	if err == nil {
		trace.authenticatedGeneration = authority.TokenGeneration
	}
	return authority, err
}

func (trace *envelopeRepositoryTrace) Reserve(ctx context.Context, credential *sensor.TokenCredential, request runtimeevent.IngestReserveRequest) (runtimeevent.IngestReservation, error) {
	trace.reserves++
	result, err := trace.ProductionIngestRepository.Reserve(ctx, credential, request)
	trace.reserveError = err
	return result, err
}

func (trace *envelopeRepositoryTrace) Finalize(ctx context.Context, credential *sensor.TokenCredential, request runtimeevent.IngestFinalizeRequest) (runtimeevent.IngestResult, error) {
	trace.finalizes++
	return trace.ProductionIngestRepository.Finalize(ctx, credential, request)
}

func (trace *envelopeRepositoryTrace) LookupAcceptance(ctx context.Context, credential *sensor.TokenCredential, request runtimeevent.IngestAcceptanceRequest) (runtimeevent.IngestAcceptance, error) {
	trace.acceptanceRequest = request
	return trace.ProductionIngestRepository.(runtimeevent.ProductionAcceptanceRepository).LookupAcceptance(ctx, credential, request)
}

type envelopeDriverTrace struct {
	PostgresDriver
	lastErrorCode string
}

func (trace *envelopeDriverTrace) QueryRow(ctx context.Context, query string, arguments ...any) PostgresRow {
	row := trace.PostgresDriver.QueryRow(ctx, query, arguments...)
	return envelopeObservedRow(func(destinations ...any) error {
		err := row.Scan(destinations...)
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) {
			trace.lastErrorCode = postgresError.Code
		}
		return err
	})
}

type envelopeObservedRow func(...any) error

func (row envelopeObservedRow) Scan(destinations ...any) error { return row(destinations...) }

func exerciseAcceptanceAuthenticationWait(t *testing.T, ctx context.Context, admin, ingest *pgx.Conn, tokenID string, arguments []any, scenario string) {
	t.Helper()
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	if scenario == "credential expires" {
		var expires time.Time
		if err := observer.QueryRow(ctx, `SELECT expires_at FROM zasp_sensor_tokens WHERE id=$1`, tokenID).Scan(&expires); err != nil {
			t.Fatal(err)
		}
		if _, err := observer.Exec(ctx, `UPDATE zasp_sensor_tokens SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, tokenID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := observer.Exec(context.Background(), `UPDATE zasp_sensor_tokens SET expires_at=$2 WHERE id=$1`, tokenID, expires); err != nil {
				t.Error("restore fixture expiry", err)
			}
		}()
	}
	lock, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err := lock.Exec(ctx, `SELECT id FROM zasp_sensor_tokens WHERE id=$1 FOR UPDATE`, tokenID); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		defer close(completed)
		var result json.RawMessage
		completed <- ingest.QueryRow(ctx, `SELECT zasp_runtime_lookup_acceptance($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, arguments...).Scan(&result)
	}()
	defer func() {
		_ = lock.Rollback(context.Background())
		select {
		case <-completed:
		case <-time.After(5 * time.Second):
		}
	}()
	blocked := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, ingest.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-completed:
			t.Fatalf("lookup finished before controlled wait: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	if !blocked {
		t.Fatal("lookup did not reach authentication lock")
	}
	wantCode := "42501"
	switch scenario {
	case "principal revoked":
		principal := pgx.Identifier{ingest.Config().User}.Sanitize()
		if _, err := observer.Exec(ctx, `REVOKE zasp_runtime_ingest FROM `+principal+` GRANTED BY zasp_discovery_authority`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := observer.Exec(context.Background(), `GRANT zasp_runtime_ingest TO `+principal+` GRANTED BY zasp_discovery_authority`); err != nil {
				t.Error("restore fixture principal", err)
			}
		}()
		var member bool
		if err := observer.QueryRow(ctx, `SELECT pg_has_role($1,'zasp_runtime_ingest','MEMBER')`, ingest.Config().User).Scan(&member); err != nil || member {
			t.Fatal("principal revocation did not take effect", err)
		}
	case "release checksum drift":
		if _, err := observer.Exec(ctx, `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=48`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := observer.Exec(context.Background(), `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=48`, migrations.ProductionRuntimeAcceptance().Checksum()); err != nil {
				t.Error("restore fixture checksum", err)
			}
		}()
	case "credential expires":
		wantCode = "28000"
		var validAtStart bool
		if err := observer.QueryRow(ctx, `SELECT a.xact_start<t.expires_at AND clock_timestamp()<t.expires_at FROM pg_stat_activity a CROSS JOIN zasp_sensor_tokens t WHERE a.pid=$1 AND t.id=$2`, ingest.PgConn().PID(), tokenID).Scan(&validAtStart); err != nil || !validAtStart {
			t.Fatal("expiry fixture was not valid when authentication began waiting", err)
		}
		// The credential was valid at transaction start. Release authentication
		// only after database wall time exceeds its committed expiry.
		if _, err := observer.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::double precision)+0.025) FROM zasp_sensor_tokens WHERE id=$1`, tokenID); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown authentication wait scenario")
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != wantCode {
			t.Fatalf("lookup failed authority recheck after wait: scenario=%s error=%v", scenario, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not finish after release")
	}
}
