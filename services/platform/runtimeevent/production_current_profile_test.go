package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

// A current constructor reaching a public release gate or mutation is a bug:
// registered61 deliberately closes those gates. Exercise the repository calls,
// with only the external JSON transport recorded here.
func TestCurrentRuntimePipelineRoutesClosedProfile(t *testing.T) {
	for _, authority := range []ProductionPipelineAuthority{ProductionPipelineAuthorityArchive, ProductionPipelineAuthorityIndex, ProductionPipelineAuthorityCorrelation, ProductionPipelineAuthorityProjection, ProductionPipelineAuthorityCoordinator} {
		t.Run(string(authority), func(t *testing.T) {
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), json.RawMessage(`[]`)}}
			repository, err := NewPostgresCurrentRuntimePipelineRepository(db, authority)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = repository.ClaimStages(context.Background(), "current-worker", "current-worker-token", 30, 1); err != nil {
				t.Fatal(err)
			}
			if len(db.statements) != 2 || db.statements[0] != `SELECT jsonb_build_object('ready',zasp_authorization80_runtime.ready($1,$2))` || !strings.HasPrefix(db.statements[1], `SELECT zasp_authorization80_runtime.runtime_claim_`) {
				t.Fatal("current stage escaped its profile", db.statements)
			}
			if len(db.arguments[0]) != 2 || db.arguments[0][1] != string(authority) {
				t.Fatal("current stage lost own-role binding", db.arguments)
			}
		})
	}
	for _, operation := range []string{"ready", "projection", "claim", "heartbeat", "release", "ack"} {
		t.Run(operation+"/closed", func(t *testing.T) {
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":false}`), json.RawMessage(`{"ready":true}`)}}
			repository, err := NewPostgresCurrentRuntimePipelineRepository(db, ProductionPipelineAuthorityCoordinator)
			if err != nil {
				t.Fatal(err)
			}
			request := DeliveryClaimRequest{Scope: fixtureScope(t, 120), BatchID: fixtureID(t, 123), Generation: 2, MessageID: "sha256_" + strings.Repeat("a", 64), MessageDigest: sha256.Sum256([]byte("message")), ReceiveCount: 1, WorkerID: "runtime-coordinator-01", LeaseToken: "0123456789abcdef", LeaseSeconds: 30, VisibilitySeconds: 60}
			switch operation {
			case "ready":
				err = repository.Ready(context.Background())
			case "projection":
				err = repository.ReadySessionProjection(context.Background())
			case "claim":
				_, err = repository.ClaimDelivery(context.Background(), request)
			case "heartbeat":
				_, err = repository.HeartbeatDelivery(context.Background(), request)
			case "release":
				_, err = repository.ReleaseDelivery(context.Background(), request, DeliveryOutcomeRetryable, "retryable")
			case "ack":
				_, err = repository.AcknowledgeDelivery(context.Background(), request, sha256.Sum256([]byte("ack")))
			}
			if !errors.Is(err, ErrProductionPipelineUnavailable) || db.calls != 1 || db.statements[0] != `SELECT jsonb_build_object('ready',zasp_authorization80_runtime.ready($1,$2))` {
				t.Fatal("closed current authority fell back", err, db.statements)
			}
		})
	}
}

func TestCurrentRuntimeCandidateReadinessNeverFallsBack(t *testing.T) {
	for _, scenario := range []struct {
		name string
		body string
		err  error
	}{
		{"false", `{"ready":false}`, nil},
		{"missing", "", &pgconn.PgError{Code: "42883"}},
		{"denied", "", &pgconn.PgError{Code: "42501"}},
		{"unknown field", `{"ready":true,"other":true}`, nil},
		{"duplicate", `{"ready":false,"ready":true}`, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(scenario.body), json.RawMessage(`{"ready":true}`)}, errors: []error{scenario.err}}
			repository, err := NewPostgresCurrentRuntimePipelineRepository(db, ProductionPipelineAuthorityCorrelation)
			if err != nil {
				t.Fatal(err)
			}
			if repository.ReadyCandidates(context.Background()) != ErrProductionPipelineUnavailable || db.calls != 1 {
				t.Fatal("current candidate readiness used predecessor fallback", db.statements)
			}
			if db.arguments[0][0] != migrations.AuthorizationRuntimeProfileChecksum() || db.arguments[0][1] != string(ProductionPipelineAuthorityCorrelation) {
				t.Fatal("current candidate readiness lost profile or own-role binding")
			}
		})
	}
}

func TestCurrentRuntimeIngestRoutesSemanticAndPreciseSources(t *testing.T) {
	credential, err := sensor.ParseTokenCredential(productionSensorToken(t))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	for _, source := range []string{"otlp", "tetragon"} {
		t.Run(source, func(t *testing.T) {
			request := acceptanceRequestFixture(t).IngestReserveRequest
			request.Source = source
			request.SchemaVersion = "runtime-event-v1"
			if source == "tetragon" {
				request.SchemaVersion = "runtime-event-v2"
			}
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"matched":true}`)}}
			repository, err := NewPostgresCurrentRuntimeIngestRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = repository.Reserve(context.Background(), credential, request)
			if len(db.statements) != 2 || db.statements[0] != `SELECT jsonb_build_object('matched',zasp_authorization80_runtime.ingest_profile_identity($1))` || db.statements[1] != `SELECT zasp_authorization80_runtime.runtime_reserve_batch_v17($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9,$10)` {
				t.Fatal("ingest escaped current profile", db.statements)
			}
			if len(db.arguments[0]) != 1 || db.arguments[0][0] != migrations.AuthorizationRuntimeProfileChecksum() || db.arguments[1][7] != request.SchemaVersion {
				t.Fatal("ingest lost principal or schema", db.arguments)
			}
		})
	}
}

func TestCurrentRuntimeIntakeIdentityDoesNotReplaceHealth(t *testing.T) {
	for _, current := range []bool{true, false} {
		for _, health := range []bool{true, false} {
			body := `{"ready":true}`
			if current && !health {
				body = `{"matched":true}`
			}
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body)}}
			constructor := NewPostgresPreciseProductionIngestRepository
			if current {
				constructor = NewPostgresCurrentRuntimeIngestRepository
			}
			repository, err := constructor(db)
			if err != nil {
				t.Fatal(err)
			}
			if health {
				err = repository.Ready(context.Background())
			} else {
				err = safeProductionReady(context.Background(), repository)
			}
			if err != nil || db.calls != 1 {
				t.Fatal("profile dispatch failed", current, health, err, db.statements)
			}
			identity := strings.Contains(db.statements[0], "ingest_profile_identity")
			if identity != (current && !health) {
				t.Fatal("health or historical route used identity-only gate", current, health, db.statements)
			}
		}
	}
	for _, body := range []string{`{"matched":false}`, `{"matched":true,"other":1}`, `{"matched":true,"matched":false}`, `{}`} {
		db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body), json.RawMessage(`{"ready":true}`)}}
		repository, err := NewPostgresCurrentRuntimeIngestRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		if safeProductionReady(context.Background(), repository) != ErrProductionIngestUnavailable || db.calls != 1 {
			t.Fatal("identity failure used fallback", body, db.statements)
		}
	}
	for _, code := range []string{"42883", "42501", "55000"} {
		db := &productionIngestDatabaseStub{errors: []error{&pgconn.PgError{Code: code}}, responses: []json.RawMessage{nil, json.RawMessage(`{"matched":true}`)}}
		repository, err := NewPostgresCurrentRuntimeIngestRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		if safeProductionReady(context.Background(), repository) != ErrProductionIngestUnavailable || db.calls != 1 {
			t.Fatal("identity error used fallback", code, db.statements)
		}
	}
}

func TestCurrentRuntimeFinalizeIdentityPreservesHistoricalGate(t *testing.T) {
	credential, err := sensor.ParseTokenCredential(productionSensorToken(t))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	request := IngestFinalizeRequest{BatchID: fixtureID(t, 96), JobID: fixtureID(t, 97), OutboxID: fixtureID(t, 98), Artifact: RawArtifact{Scope: fixtureScope(t, 90), Key: "runtime/current.json", Reference: "s3://zasp-runtime/runtime/current.json", VersionID: "version-1", ContentDigest: sha256.Sum256([]byte("body")), Size: 4, MediaType: "application/json", KMSKeyARN: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111"}}
	for _, current := range []bool{false, true} {
		body := `{"ready":true}`
		constructor := NewPostgresPreciseProductionIngestRepository
		if current {
			body = `{"matched":true}`
			constructor = NewPostgresCurrentRuntimeIngestRepository
		}
		db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(body), json.RawMessage(`{"batch_id":"pid_00000096-0000-4000-8000-000000000096","generation":3,"state":"queued","replayed":false}`)}}
		repository, err := constructor(db)
		if err != nil {
			t.Fatal(err)
		}
		result, err := repository.Finalize(context.Background(), credential, request)
		if err != nil || result.BatchID != request.BatchID || result.Generation != 3 || result.State != "queued" || db.calls != 2 {
			t.Fatal("finalize dispatch", current, result, err, db.statements)
		}
		if strings.Contains(db.statements[0], "ingest_profile_identity") != current || strings.Contains(db.statements[1], "zasp_authorization80_runtime.") != current {
			t.Fatal("finalize crossed profile", current, db.statements)
		}
		if current && (len(db.arguments[0]) != 1 || db.arguments[0][0] != migrations.AuthorizationRuntimeProfileChecksum()) {
			t.Fatal("finalize lost compiled pin")
		}
	}
}

func TestCurrentRuntimeCompletionBacklogUsesCurrentAuthority(t *testing.T) {
	for _, version := range []string{"runtime-complete-v1", "runtime-complete-v2", "runtime-complete-v3"} {
		t.Run(version, func(t *testing.T) {
			request := sessionProjectionFinishFixture(t)
			request.Lease.ImplementationVersion = version
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), json.RawMessage(`{"ready":true}`)}}
			repository, err := NewPostgresCurrentRuntimePipelineRepository(db, ProductionPipelineAuthorityCoordinator)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = repository.FinishStage(context.Background(), request)
			if db.calls < 2 {
				t.Fatal("valid completion never reached profile", db.statements)
			}
			for _, q := range db.statements {
				if !strings.Contains(q, "zasp_authorization80_runtime.") {
					t.Fatal("backlog completion escaped current profile", q)
				}
			}
			if !strings.Contains(db.statements[len(db.statements)-1], "session_projection(") {
				t.Fatal("complete success skipped durable session receipt", db.statements)
			}
		})
	}
}
