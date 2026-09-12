package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSandboxSessionWorkerPrestageAndActivation(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			worker := sandboxStageWorker(t, ctx, admin, stage)
			authority, version := runtimeevent.ProductionPipelineAuthorityProjection, "runtime-projection-v2"
			if stage == "complete" {
				authority, version = runtimeevent.ProductionPipelineAuthorityCoordinator, "runtime-complete-v2"
			}
			database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
			if err != nil {
				t.Fatal(err)
			}
			repository, err := runtimeevent.NewPostgresSandboxSessionPipelineRepository(database, authority)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := runtimeevent.NewPostgresProductionPipelineRepository(database, authority)
			if err != nil {
				t.Fatal(err)
			}
			if err := legacy.Ready(ctx); err != nil {
				t.Fatal("49 v1 pre-stage readiness", err)
			}
			oldArgs := seedSandboxStageClaim(t, ctx, admin, stage, strings.TrimSuffix(version, "2")+"1", "pending")
			oldLeases, err := legacy.ClaimStages(ctx, "session-worker", "session-worker-lease", 60, 1)
			if leases := oldLeases; err != nil || len(leases) != 1 || leases[0].BatchID.String() != oldArgs[3] || leases[0].ImplementationVersion != strings.TrimSuffix(version, "2")+"1" {
				t.Fatal("49 v1 pre-stage claim", leases, err)
			}
			// Settle the old attempt through the actual authority to release its
			// tenant fairness slot before testing admission of the second job.
			if result, err := legacy.FinishStage(ctx, runtimeevent.StageFinishRequest{Lease: oldLeases[0], WorkerID: "session-worker", LeaseToken: "session-worker-lease", Outcome: runtimeevent.StageOutcomeRetryable, ErrorClass: "retryable", RetryAfter: 5 * time.Minute}); err != nil || result.ImplementationVersion != oldLeases[0].ImplementationVersion {
				t.Fatal("49 old attempt completion", result, err)
			}
			if err := repository.Ready(ctx); err != runtimeevent.ErrProductionPipelineUnavailable {
				t.Fatal("v2 ready on49", err)
			}
			if leases, err := repository.ClaimStages(ctx, "session-worker", "session-worker-lease", 60, 1); err != runtimeevent.ErrProductionPipelineUnavailable || leases != nil {
				t.Fatal("v2 claim on49", leases, err)
			}
			installRuntimeSandboxDraft(t, ctx, admin)
			args := seedSandboxStageClaimNumber(t, ctx, admin, stage, version, "pending", 2)
			if err := repository.Ready(ctx); err != nil {
				t.Fatal("50 readiness", err)
			}
			leases, err := repository.ClaimStages(ctx, "session-worker", "session-worker-lease", 60, 1)
			if err != nil || len(leases) != 1 || leases[0].ImplementationVersion != version || leases[0].BatchID.String() != args[3] {
				t.Fatal("50 actual claim", leases, err)
			}
			before := sandboxStageState(t, ctx, admin)
			if _, err := admin.Exec(ctx, `DROP FUNCTION zasp_production_runtime_sandbox_binding_readiness(text,text)`); err != nil {
				t.Fatal(err)
			}
			if err := repository.Ready(ctx); err != runtimeevent.ErrProductionPipelineUnavailable {
				t.Fatal("missing50 authority accepted", err)
			}
			if leases, err := repository.ClaimStages(ctx, "session-worker", "session-worker-lease", 60, 1); err != runtimeevent.ErrProductionPipelineUnavailable || leases != nil {
				t.Fatal("missing50 authority downgraded", leases, err)
			}
			if sandboxStageState(t, ctx, admin) != before {
				t.Fatal("failed authority changed stage state")
			}
		})
	}
}
