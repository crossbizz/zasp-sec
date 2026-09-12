package runtimeevent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPreciseCompletionPinsAuthorityBeforeMutation(t *testing.T) {
	const readySQL = `SELECT jsonb_build_object('ready',zasp_production_runtime_precision_readiness($1,$2) AND zasp_runtime_principal_ready($3))`
	for _, test := range []struct {
		name    string
		payload string
		err     error
		ready   bool
	}{
		{"ready", `{"ready":true}`, nil, true},
		{"drift", `{"ready":false}`, nil, false},
		{"unknown-field", `{"ready":true,"extra":true}`, nil, false},
		{"duplicate", `{"ready":false,"ready":true}`, nil, false},
		{"null", `{"ready":null}`, nil, false},
		{"absent", "", &pgconn.PgError{Code: "42883"}, false},
		{"denied", "", &pgconn.PgError{Code: "42501"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(test.payload), nil}, errors: []error{test.err, errors.New("finisher unavailable")}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
			request := sessionProjectionFinishFixture(t)
			request.Lease.ImplementationVersion = "runtime-complete-v3"
			request.ProjectionReceipt = `{"schema":"runtime-projection-receipt-v3","items":[]}`
			_, err := repository.FinishStage(context.Background(), request)
			wantCalls, wantError := 1, ErrProductionPipelineUnavailable
			if test.ready {
				wantCalls, wantError = 2, ErrProductionPipelineUnknown
			}
			if !errors.Is(err, wantError) || database.calls != wantCalls || database.statements[0] != readySQL {
				t.Fatalf("V3 authority/fallback: err=%v calls=%d statements=%v", err, database.calls, database.statements)
			}
			wantPins := []any{migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint(), string(ProductionPipelineAuthorityCoordinator)}
			if !reflect.DeepEqual(database.arguments[0], wantPins) {
				t.Fatal("completion did not bind compiled precision identity")
			}
			if test.ready && (database.statements[1] != `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)` || len(database.arguments[1]) != 18 || !reflect.DeepEqual(database.arguments[1][17], []byte(request.ProjectionReceipt))) {
				t.Fatal("precise completion lost receipt bytes or used historical authority")
			}
		})
	}
}

func TestPreciseCompletionReturnsOnlyMatchingAtomicResult(t *testing.T) {
	for _, mismatch := range []string{"", "batch_id", "generation", "attempt", "implementation_version", "input_digest", "effect_digest", "result_digest", "result_reference", "result_version_id"} {
		t.Run(mismatch, func(t *testing.T) {
			request := sessionProjectionFinishFixture(t)
			request.Lease.ImplementationVersion = "runtime-complete-v3"
			request.ProjectionReceipt = `{"schema":"runtime-projection-receipt-v3","padding":"` + strings.Repeat("a", 1<<20) + `"}`
			response := map[string]any{"batch_id": request.Lease.BatchID.String(), "generation": request.Lease.Generation, "stage": "complete", "state": "succeeded", "attempt": request.Lease.Attempt, "implementation_version": "runtime-complete-v3", "input_digest": hex.EncodeToString(request.Lease.InputDigest[:]), "effect_digest": hex.EncodeToString(request.EffectDigest[:]), "result_digest": hex.EncodeToString(request.ResultDigest[:]), "result_reference": request.ResultReference, "result_version_id": request.ResultVersionID, "error_class": nil}
			if mismatch != "" {
				switch mismatch {
				case "generation", "attempt":
					response[mismatch] = 2
				case "batch_id":
					response[mismatch] = fixtureID(t, 144).String()
				case "input_digest", "effect_digest", "result_digest":
					response[mismatch] = strings.Repeat("b", 64)
				case "implementation_version":
					response[mismatch] = "runtime-complete-v2"
				default:
					response[mismatch] = "altered"
				}
			}
			payload, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), payload}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
			result, err := repository.FinishStage(context.Background(), request)
			if mismatch == "" {
				if err != nil || result.State != StageOutcomeSucceeded || result.ImplementationVersion != "runtime-complete-v3" {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, ErrProductionPipelineUnknown) {
				t.Fatal("accepted altered atomic result", result, err)
			}
			if database.calls != 2 || !reflect.DeepEqual(database.arguments[1][17], []byte(request.ProjectionReceipt)) {
				t.Fatal("receipt altered or fallback attempted")
			}
		})
	}
}

func TestPreciseCompletionRequiresReadinessForFailureTransitions(t *testing.T) {
	for _, outcome := range []StageOutcome{StageOutcomeRetryable, StageOutcomeFailed, StageOutcomeUnknown, StageOutcomeQuarantined} {
		t.Run(string(outcome), func(t *testing.T) {
			request := sessionProjectionFinishFixture(t)
			request.Lease.ImplementationVersion = "runtime-complete-v3"
			request.Outcome = outcome
			request.ProjectionReceipt = ""
			request.EffectDigest = [32]byte{}
			request.ResultDigest = [32]byte{}
			request.ResultReference = ""
			request.ResultVersionID = ""
			request.ErrorClass = "malformed"
			if outcome == StageOutcomeRetryable {
				request.ErrorClass = "retryable"
				request.RetryAfter = time.Second
			}
			if outcome == StageOutcomeUnknown {
				request.ErrorClass = "outcome_unknown"
			}
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":false}`)}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCoordinator)
			if _, err := repository.FinishStage(context.Background(), request); !errors.Is(err, ErrProductionPipelineUnavailable) || database.calls != 1 {
				t.Fatal("failure transition bypassed precision readiness", err, database.calls)
			}
		})
	}
}
