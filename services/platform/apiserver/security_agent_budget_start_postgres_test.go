package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A valid lease/approval must not substitute for a still-valid run budget.
// These cases reach the real prepare/dispatch SQL through the worker adapter.
// The approval state is fixture-owned; no fresh-auth UI or external effect is
// claimed by this test.
func TestProductionSecurityAgentBudgetStopsNewPreparationAndDispatch(t *testing.T) {
	for _, phase := range []string{"prepare", "dispatch"} {
		for _, expired := range []bool{false, true} {
			if (os.Getenv("ZASP_EXISTING_TEST_FINAL_WRITE_EXPIRY") == "true" || os.Getenv("ZASP_EXISTING_TEST_FINAL_READINESS_EXPIRY") != "") && (phase != "dispatch" || expired) {
				continue
			}
			name := phase + "/fresh"
			if expired {
				name = phase + "/expired"
			}
			t.Run(name, func(t *testing.T) {
				runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
					if os.Getenv("ZASP_EXISTING_TEST_LEGACY_EXECUTION") == "true" {
						runner := precisionMigrationRunner(t, owner)
						if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
							t.Fatal(err)
						}
						if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
							t.Fatal(err)
						}
					}
					const organization = "pid_6a000001-0000-4000-8000-000000000001"
					const workerID = "budget-start-worker"
					const leaseToken = "budget-start-lease-token"
					if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					config, err := pgx.ParseConfig(dsn)
					if err != nil {
						t.Fatal(err)
					}
					config.User = "security_agent_v33_worker_login"
					worker, err := pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer worker.Close(context.Background())
					database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
					if err != nil {
						t.Fatal(err)
					}
					repository, err := NewSecurityAgentWorkerRepository(database)
					if err != nil {
						var readiness json.RawMessage
						readinessErr := worker.QueryRow(ctx, postgresSecurityAgentWorkerReadyV33SQL, migrations.ProductionSecurityAgentAttackPath().Checksum(), migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&readiness)
						var fingerprintMatches bool
						fingerprintErr := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_attack_path_live_fingerprint()=$1`, migrations.ProductionSecurityAgentAttackPathSemanticFingerprint()).Scan(&fingerprintMatches)
						t.Fatalf("%v; readiness=%s fingerprint_matches=%t diagnostic_errors=%v/%v", err, readiness, fingerprintMatches, readinessErr, fingerprintErr)
					}
					if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 1); err != nil || count != 1 {
						t.Fatalf("schedule count=%d err=%v", count, err)
					}
					claim := func() SecurityAgentRunClaim {
						t.Helper()
						claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, leaseToken, 60, 1)
						if err != nil || len(claims) != 1 {
							t.Fatalf("claim count=%d err=%v", len(claims), err)
						}
						return claims[0]
					}
					currentClaim := claim()
					prepare := func() (SecurityAgentPrepareResult, error) {
						return repository.PrepareSecurityAgentRun(ctx, currentClaim, workerID, leaseToken,
							"pid_6a000030-0000-4000-8000-000000000030", time.Now().UTC().Add(10*time.Minute),
							"pid_6a000031-0000-4000-8000-000000000031", "pid_6a000032-0000-4000-8000-000000000032")
					}
					if phase == "dispatch" {
						if result, err := prepare(); err != nil || result.State != "waiting_approval" {
							t.Fatalf("prepare before approval state=%s err=%v", result.State, err)
						}
						// A fixture-owned approved state isolates the budget boundary.
						// It does not bypass approval in product code or prove the API.
						for _, statement := range []string{
							`UPDATE zasp_security_agent_approvals SET state='approved',approver_id='pid_6a000033-0000-4000-8000-000000000033',fresh_auth_at=clock_timestamp(),decided_at=clock_timestamp(),version=version+1 WHERE organization_id=$1`,
							`UPDATE zasp_security_agent_steps SET state='authorized',version=version+1 WHERE organization_id=$1`,
							`UPDATE zasp_security_agent_runs SET state='queued',version=version+1 WHERE organization_id=$1`,
						} {
							if _, err := owner.Exec(ctx, statement, organization); err != nil {
								t.Fatal(err)
							}
						}
						currentClaim = claim()
						if !currentClaim.Prepared {
							t.Fatal("approved run did not reclaim its persisted plan")
						}
					}
					if expired {
						// Leave the lease and approval valid while expiring only the
						// authoritative run clock after claim, before the new start.
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
					}
					var resultState string
					if mode := os.Getenv("ZASP_EXISTING_TEST_FINAL_READINESS_EXPIRY"); mode != "" {
						assertExistingTestFinalReadinessExpiry(t, ctx, owner, worker, currentClaim, workerID, leaseToken, mode)
						return
					}
					if os.Getenv("ZASP_EXISTING_TEST_FINAL_WRITE_EXPIRY") == "true" {
						if phase == "dispatch" && !expired {
							assertExistingTestFinalWriteExpiry(t, ctx, owner, worker, currentClaim, workerID, leaseToken)
						}
						return
					}
					var operationErr error
					if phase == "prepare" {
						result, err := prepare()
						resultState, operationErr = result.State, err
					} else {
						result, err := repository.ExecuteSecurityAgentRun(ctx, currentClaim, workerID, leaseToken,
							"pid_6a000034-0000-4000-8000-000000000034", "pid_6a000035-0000-4000-8000-000000000035")
						resultState, operationErr = result.State, err
					}
					wantState, wantPlans, wantEffects := "waiting_approval", 1, 0
					if phase == "dispatch" {
						wantState, wantEffects = "running", 1
					}
					if expired {
						wantState, wantEffects = "needs_human", 0
						if phase == "prepare" {
							wantPlans = 0
						}
					}
					var state string
					var plans, steps, approvals, effects int
					if err := owner.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_security_agent_plans),
(SELECT count(*) FROM zasp_security_agent_steps),(SELECT count(*) FROM zasp_security_agent_approvals),(SELECT count(*) FROM zasp_security_agent_effects)
FROM zasp_security_agent_runs WHERE organization_id=$1`, organization).Scan(&state, &plans, &steps, &approvals, &effects); err != nil {
						t.Fatal(err)
					}
					if operationErr != nil || resultState != wantState || state != wantState || plans != wantPlans || steps != wantPlans || approvals != wantPlans || effects != wantEffects {
						t.Fatalf("budget start boundary: returned=%s persisted=%s plans=%d steps=%d approvals=%d effects=%d err=%v; want state=%s plans=%d effects=%d", resultState, state, plans, steps, approvals, effects, operationErr, wantState, wantPlans, wantEffects)
					}
				})
			})
		}
	}
}
