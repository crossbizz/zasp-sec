package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeSandboxReaderPrestage49Activation50AndMissingAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, worker := runtimeSandboxPredecessor(t, ctx)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresSandboxCorrelationPipelineRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"runtime-correlation-v2", "runtime-correlation-v3"} {
		ordinal := 1
		if version == "runtime-correlation-v3" {
			installRuntimeSandboxDraft(t, ctx, admin)
			ordinal = 2
		}
		args := seedRuntimeCandidateBatchVersion(t, ctx, admin, ordinal, sandboxAnchor, "tetragon", 0, 1, version, nil)
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET state='pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
			t.Fatal(err)
		}
		if err := repository.Ready(ctx); err != nil {
			t.Fatal("same binary rejected compatible database", version, err)
		}
		leases, err := repository.ClaimStages(ctx, "sandbox-reader", "sandbox-reader-token", 60, 10)
		if err != nil || len(leases) != 1 || leases[0].ImplementationVersion != version || leases[0].BatchID.String() != args[3] {
			t.Fatal("same binary failed version-bound SQL claim", version, leases, err)
		}
		if version == "runtime-correlation-v2" {
			finished, err := repository.FinishStage(ctx, runtimeevent.StageFinishRequest{Lease: leases[0], WorkerID: "sandbox-reader", LeaseToken: "sandbox-reader-token", Outcome: runtimeevent.StageOutcomeRetryable, ErrorClass: "retryable", RetryAfter: 5 * time.Minute})
			if err != nil || finished.State != runtimeevent.StageOutcomeRetryable || finished.ImplementationVersion != version || finished.InputDigest != leases[0].InputDigest {
				t.Fatal("old attempt did not release tenant slot through version-bound finish", finished, err)
			}
		}
	}
	// Removing50 readiness must not allow the missing-function fallback to claim
	// through49 on an installed50 database. The predecessor wrapper fails closed.
	var before, after string
	const state = `SELECT jsonb_agg(to_jsonb(w) ORDER BY batch_id,stage)::text FROM zasp_runtime_stage_work w`
	if err := admin.QueryRow(ctx, state).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DROP FUNCTION zasp_production_runtime_sandbox_binding_readiness(text,text)`); err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); !errors.Is(err, runtimeevent.ErrProductionPipelineUnavailable) {
		t.Fatal("missing50 readiness was accepted", err)
	}
	if leases, err := repository.ClaimStages(ctx, "sandbox-reader", "sandbox-reader-token", 60, 10); !errors.Is(err, runtimeevent.ErrProductionPipelineUnavailable) || leases != nil {
		t.Fatal("missing50 authority downgraded", leases, err)
	}
	if err := admin.QueryRow(ctx, state).Scan(&after); err != nil || after != before {
		t.Fatal("failed negotiation changed work", err)
	}
}
