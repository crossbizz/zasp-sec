package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRuntimeSessionProjectionReadinessRequiresExactSchemaAndCoordinatorWithoutFallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		err     error
		ready   bool
	}{
		{"ready", `{"ready":true}`, nil, true},
		{"drift", `{"ready":false}`, nil, false},
		{"malformed", `{"ready":true,"extra":true}`, nil, false},
		{"absent", "", &pgconn.PgError{Code: "42883"}, false},
		{"denied", "", &pgconn.PgError{Code: "42501"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(test.payload)}, errors: []error{test.err}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
			err := repository.ReadySessionProjection(context.Background())
			want := []any{migrations.ProductionRuntimeSessions().Checksum(), migrations.ProductionRuntimeSessionsSemanticFingerprint(), string(ProductionPipelineAuthorityCoordinator)}
			if (err == nil) != test.ready || database.calls != 1 || database.statements[0] != `SELECT jsonb_build_object('ready',zasp_production_runtime_sessions_readiness($1,$2) AND zasp_runtime_principal_ready($3))` || !reflect.DeepEqual(database.arguments[0], want) {
				t.Fatalf("readiness=%v calls=%d", err, database.calls)
			}
		})
	}
	database := &productionIngestDatabaseStub{}
	repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityProjection)
	if err := repository.ReadySessionProjection(context.Background()); !errors.Is(err, ErrProductionPipelineUnavailable) || database.calls != 0 {
		t.Fatal("non-coordinator queried session authority")
	}
}

func TestRuntimeCompleteRepositoryRequiresBoundedProjectionBeforeDatabase(t *testing.T) {
	for _, payload := range []string{"", "not-json", "null", `[]`} {
		database := &productionIngestDatabaseStub{}
		repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
		request := sessionProjectionFinishFixture(t)
		request.ProjectionReceipt = payload
		if _, err := repository.FinishStage(context.Background(), request); !errors.Is(err, ErrProductionPipeline) || database.calls != 0 {
			t.Fatalf("invalid projection reached database: calls=%d error=%v", database.calls, err)
		}
	}
}

func TestRuntimeCompleteRepositoryUsesAtomicProjectionFunctionWithoutLegacyFallback(t *testing.T) {
	database := &productionIngestDatabaseStub{responses: []json.RawMessage{nil}, errors: []error{errors.New("database unavailable")}}
	repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
	request := sessionProjectionFinishFixture(t)
	_, err := repository.FinishStage(context.Background(), request)
	if !errors.Is(err, ErrProductionPipelineUnknown) || database.calls != 1 || database.statements[0] != `SELECT zasp_runtime_finish_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)` || len(database.arguments[0]) != 18 || !reflect.DeepEqual(database.arguments[0][17], []byte(request.ProjectionReceipt)) {
		t.Fatal("completion did not bind exact receipt bytes to its sole atomic database call")
	}
}

func sessionProjectionFinishFixture(t *testing.T) StageFinishRequest {
	t.Helper()
	digest := sha256.Sum256([]byte("session-projection"))
	return StageFinishRequest{
		Lease:    StageLease{Scope: fixtureScope(t, 140), BatchID: fixtureID(t, 143), Generation: 1, Stage: RuntimeStageComplete, Attempt: 1, ImplementationVersion: "runtime-complete-v1", InputDigest: digest, InputReference: "s3://zasp-runtime/project.json", InputVersionID: "project-v1", LeaseExpiresAt: time.Now().UTC().Add(time.Minute)},
		WorkerID: "complete-worker", LeaseToken: "0123456789abcdef", Outcome: StageOutcomeSucceeded, EffectDigest: digest, ResultReference: "s3://zasp-runtime/complete.json", ResultVersionID: "complete-v1", ResultDigest: digest,
		ProjectionReceipt: `{"schema":"runtime-projection-receipt-v1","items":[]}`,
	}
}
