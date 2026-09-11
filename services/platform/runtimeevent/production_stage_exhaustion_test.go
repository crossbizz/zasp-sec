package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestProductionStageFinishBindsExhaustionOutcome(t *testing.T) {
	for _, scenario := range []struct {
		name                             string
		attempt                          int
		outcome                          StageOutcome
		requestError, state, resultError string
		valid                            bool
	}{
		{"retry99", 99, StageOutcomeRetryable, "retryable", "retryable", "retryable", true},
		{"retry100-terminal", 100, StageOutcomeRetryable, "retryable", "failed", "exhausted", true},
		{"failed100-terminal", 100, StageOutcomeFailed, "malformed", "failed", "exhausted", true},
		{"retry100-not-terminal", 100, StageOutcomeRetryable, "retryable", "retryable", "retryable", false},
		{"retry99-premature-exhaustion", 99, StageOutcomeRetryable, "retryable", "failed", "exhausted", false},
		{"retry100-wrong-error", 100, StageOutcomeRetryable, "retryable", "failed", "malformed", false},
		{"failed100-wrong-error", 100, StageOutcomeFailed, "malformed", "failed", "malformed", false},
		{"failed99-wrong-error", 99, StageOutcomeFailed, "denied", "failed", "malformed", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			digest := sha256.Sum256([]byte("index-receipt"))
			lease := StageLease{Scope: fixtureScope(t, 130), BatchID: fixtureID(t, 133), Generation: 4, Stage: RuntimeStageCorrelate, Attempt: scenario.attempt, ImplementationVersion: "runtime-correlation-v2", InputDigest: digest, InputReference: "s3://zasp-runtime/results/index.json", InputVersionID: "index-v1", LeaseExpiresAt: time.Now().Add(time.Hour)}
			body, _ := json.Marshal(map[string]any{"batch_id": lease.BatchID.String(), "generation": lease.Generation, "stage": "correlate", "state": scenario.state, "attempt": scenario.attempt, "input_digest": hex.EncodeToString(digest[:]), "implementation_version": lease.ImplementationVersion, "effect_digest": nil, "result_reference": nil, "result_version_id": nil, "result_digest": nil, "error_class": scenario.resultError})
			database := &productionIngestDatabaseStub{responses: []json.RawMessage{body}}
			repository, _ := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
			request := StageFinishRequest{Lease: lease, WorkerID: "final-worker", LeaseToken: "final-lease-token-01", Outcome: scenario.outcome, ErrorClass: scenario.requestError}
			if request.Outcome == StageOutcomeRetryable {
				request.RetryAfter = time.Second
			}
			result, err := repository.FinishStage(context.Background(), request)
			if (err == nil) != scenario.valid || database.calls != 1 || !scenario.valid && err != ErrProductionPipelineUnknown || scenario.valid && (result.State != StageOutcome(scenario.state) || result.ErrorClass != scenario.resultError) {
				t.Fatal("finish didn't bind server exhaustion contract", result, err, database.calls)
			}
		})
	}
}
