package apiserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This is an already-initialized worker crossing a staged upgrade, not proof
// that a fresh runtime passes v53 readiness. Hold a real prerequisite lock,
// observe the worker waiting, and release it only after the database deadline.
func TestProductionSecurityAgentBudgetLegacyWorkerDeadlineDuringLock(t *testing.T) {
	for _, test := range []struct {
		phase  string
		expire bool
	}{
		{"prepare", true}, {"dispatch", true},
		{"prepare", false}, {"dispatch", false},
		{"finding", true}, {"finding", false},
		{"finding_base", false},
		{"planner", true}, {"planner", false},
		{"planner_order", false},
		{"context", true}, {"context", false},
		{"planner_failure", true}, {"planner_failure", false},
		{"planner_failure_output", true},
	} {
		phase := test.phase
		failureCase := strings.HasPrefix(phase, "planner_failure")
		plannerCase := phase == "planner" || phase == "planner_order" || failureCase
		name := phase + "/fresh"
		if test.expire {
			name = phase + "/expired"
		}
		t.Run(name, func(t *testing.T) {
			runSecurityAgentAttackPathFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				const workerID, lease = "budget-lock-worker", "budget-lock-worker-lease"
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
					t.Fatal(err)
				}
				installSecurityAgentBudgetFragment(t, ctx, owner)
				// Do not weaken or bypass readiness for newly initialized workers.
				if _, err := NewSecurityAgentWorkerRepository(database); err == nil {
					t.Fatal("staged functions unexpectedly passed predecessor readiness")
				}
				findingCase := phase == "finding" || phase == "finding_base"
				if findingCase {
					for _, statement := range []string{
						`UPDATE zasp_security_agent_definitions SET body=body||'{"trigger_kind":"finding","trigger_source":"credential","allowed_actions":["update_finding_response"],"verification_kind":"finding_state"}'::jsonb WHERE organization_id=$1`,
						`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) SELECT organization_id,workspace_id,environment_id,'pid_6a000050-0000-4000-8000-000000000050','posture','credential','Budget target lock regression','high','open' FROM zasp_security_agent_definitions WHERE organization_id=$1`,
						`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) SELECT organization_id,workspace_id,environment_id,'update_finding_response',true,updated_by FROM zasp_security_agent_kill_switches WHERE organization_id=$1 AND action_key='*'`,
					} {
						if _, err := owner.Exec(ctx, statement, organization); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 1); err != nil || count != 1 {
					t.Fatalf("schedule=%d err=%v", count, err)
				}
				claim := func() SecurityAgentRunClaim {
					t.Helper()
					claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 1)
					if err != nil || len(claims) != 1 {
						t.Fatalf("claims=%d err=%v", len(claims), err)
					}
					return claims[0]
				}
				current := claim()
				var plannerContext SecurityAgentPlannerContext
				if plannerCase {
					plannerContext, err = repository.LoadSecurityAgentPlannerContext(ctx, current, workerID, lease)
					if err != nil {
						t.Fatal(err)
					}
				}
				prepare := func(callContext context.Context) (SecurityAgentPrepareResult, error) {
					if failureCase {
						outputDigest := ""
						if phase == "planner_failure_output" {
							outputDigest = "sha256:" + strings.Repeat("b", 64)
						}
						result, err := repository.FailSecurityAgentPlanner(callContext, current, workerID, lease,
							SecurityAgentPlannerFailure{InputDigest: plannerContext.InputDigest, OutputDigest: outputDigest, Model: "fixture/planner", PolicyVersion: "security-agent-planner-v1", ErrorCode: "planner_unavailable"},
							"pid_6a000041-0000-4000-8000-000000000041", "pid_6a000042-0000-4000-8000-000000000042")
						if errors.Is(err, ErrSecurityAgentBudgetStopped) {
							return SecurityAgentPrepareResult{State: "needs_human", Version: current.Version + 1}, nil
						}
						return SecurityAgentPrepareResult{State: result.State, Version: result.Version}, err
					}
					if plannerCase {
						return repository.AcceptSecurityAgentPlannerCandidate(callContext, current, workerID, lease,
							SecurityAgentPlannerSubmission{InputDigest: plannerContext.InputDigest, OutputDigest: "sha256:" + strings.Repeat("b", 64), Model: "fixture/planner", PolicyVersion: "security-agent-planner-v1", Summary: "Bounded response", Action: plannerContext.AllowedActions[0], TargetID: plannerContext.AllowedTargets[0]},
							"pid_6a000040-0000-4000-8000-000000000040", time.Now().UTC().Add(10*time.Minute),
							"pid_6a000041-0000-4000-8000-000000000041", "pid_6a000042-0000-4000-8000-000000000042")
					}
					return repository.PrepareSecurityAgentRun(callContext, current, workerID, lease,
						"pid_6a000040-0000-4000-8000-000000000040", time.Now().UTC().Add(10*time.Minute),
						"pid_6a000041-0000-4000-8000-000000000041", "pid_6a000042-0000-4000-8000-000000000042")
				}
				lockSQL := `SELECT 1 FROM zasp_security_agent_definitions WHERE organization_id=$1 FOR UPDATE`
				if phase != "prepare" && phase != "context" && !plannerCase {
					if result, err := prepare(ctx); err != nil || result.State != "waiting_approval" {
						t.Fatalf("prepare=%#v err=%v", result, err)
					}
					// Fixture-owned approval isolates the SQL dispatch boundary.
					for _, statement := range []string{
						`UPDATE zasp_security_agent_approvals SET state='approved',approver_id='pid_6a000043-0000-4000-8000-000000000043',fresh_auth_at=clock_timestamp(),decided_at=clock_timestamp(),version=version+1 WHERE organization_id=$1`,
						`UPDATE zasp_security_agent_steps SET state='authorized',version=version+1 WHERE organization_id=$1`,
						`UPDATE zasp_security_agent_runs SET state='queued',version=version+1 WHERE organization_id=$1`,
					} {
						if _, err := owner.Exec(ctx, statement, organization); err != nil {
							t.Fatal(err)
						}
					}
					current = claim()
					if !current.Prepared {
						t.Fatal("approved plan not reclaimed")
					}
					lockSQL = `SELECT 1 FROM zasp_security_agent_steps WHERE organization_id=$1 FOR UPDATE`
					if findingCase {
						lockSQL = `SELECT 1 FROM zasp_risk_findings WHERE organization_id=$1 FOR UPDATE`
					}
				}
				if phase == "finding_base" {
					// v21 revoked this predecessor entry point. Preserve that denial;
					// never grant it back just to manufacture a lock-wait test.
					_, err := worker.Exec(ctx, `SELECT zasp_security_agent_execute_run($1,$2,$3,$4,$5,$6,$7,$8)`, current.OrganizationID, current.WorkspaceID, current.EnvironmentID, current.RunID, workerID, lease,
						"pid_6a000044-0000-4000-8000-000000000044", "pid_6a000045-0000-4000-8000-000000000045")
					var pgError *pgconn.PgError
					if !errors.As(err, &pgError) || pgError.Code != "42501" {
						t.Fatalf("revoked predecessor accepted: %v", err)
					}
					var unchanged bool
					if err := owner.QueryRow(ctx, `SELECT (SELECT state='planning' FROM zasp_security_agent_runs WHERE organization_id=$1) AND (SELECT status='open' AND version=1 FROM zasp_risk_findings WHERE organization_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects)`, organization).Scan(&unchanged); err != nil || !unchanged {
						t.Fatalf("revoked predecessor mutated state: unchanged=%t err=%v", unchanged, err)
					}
					return
				}
				observer, err := pgx.Connect(ctx, dsn)
				if err != nil {
					t.Fatal(err)
				}
				defer observer.Close(context.Background())
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if phase == "planner_order" {
					lockSQL = `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1::text,0))`
				}
				if _, err := tx.Exec(ctx, lockSQL, organization); err != nil {
					t.Fatal(err)
				}
				if test.expire {
					if _, err := observer.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '295 seconds',deadline_at=clock_timestamp()+interval '5 seconds' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				callContext, cancel := context.WithTimeout(ctx, 12*time.Second)
				type outcome struct {
					state string
					err   error
				}
				done := make(chan outcome, 1)
				joined := false
				defer func() {
					cancel()
					_ = tx.Rollback(context.Background())
					if !joined {
						<-done
					}
				}()
				go func() {
					if phase == "context" {
						result, err := repository.LoadSecurityAgentPlannerContext(callContext, current, workerID, lease)
						if test.expire {
							if !errors.Is(err, ErrSecurityAgentBudgetStopped) || !reflect.DeepEqual(result, SecurityAgentPlannerContext{}) {
								done <- outcome{"usable_context_after_deadline", err}
							} else {
								done <- outcome{"needs_human", nil}
							}
						} else {
							state := "planning"
							if !securityAgentPlanHashPattern.MatchString(result.InputDigest) || len(result.AllowedActions) != 1 || result.AllowedActions[0] != "create_temporary_policy" || len(result.AllowedTargets) != 1 || result.AllowedTargets[0] != current.EnvironmentID {
								state = "unusable_fresh_context"
							}
							done <- outcome{state, err}
						}
					} else if phase == "prepare" || plannerCase {
						result, err := prepare(callContext)
						done <- outcome{result.State, err}
					} else {
						result, err := repository.ExecuteSecurityAgentRun(callContext, current, workerID, lease,
							"pid_6a000044-0000-4000-8000-000000000044", "pid_6a000045-0000-4000-8000-000000000045")
						done <- outcome{result.State, err}
					}
				}()
				observedLock := false
				for {
					var waiting, expired bool
					if err := observer.QueryRow(callContext, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer)),
(SELECT deadline_at<=clock_timestamp() FROM zasp_security_agent_run_budgets WHERE organization_id=$3)`, worker.PgConn().PID(), owner.PgConn().PID(), organization).Scan(&waiting, &expired); err != nil {
						t.Fatal(err)
					}
					observedLock = observedLock || waiting
					if observedLock && (expired || !test.expire) {
						break
					}
					select {
					case result := <-done:
						joined = true
						t.Fatalf("worker never crossed the held deadline: state=%s err=%v", result.state, result.err)
					case <-callContext.Done():
						t.Fatal("required lock/deadline condition was not observed")
					case <-time.After(10 * time.Millisecond):
					}
				}
				if phase == "planner_order" {
					// While acceptance waits for our org guard, it must not own the
					// run row needed by admission. NOWAIT makes the inversion explicit.
					probe, err := observer.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					_, lockErr := probe.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE organization_id=$1 FOR UPDATE NOWAIT`, organization)
					rollbackErr := probe.Rollback(ctx)
					if lockErr != nil || rollbackErr != nil {
						t.Fatalf("planner locked run before organization: lock=%v rollback=%v", lockErr, rollbackErr)
					}
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				result := <-done
				joined = true
				var state, stop string
				var plans, effects int
				if err := observer.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),(SELECT count(*) FROM zasp_security_agent_plans),(SELECT count(*) FROM zasp_security_agent_effects)
FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &stop, &plans, &effects); err != nil {
					t.Fatal(err)
				}
				wantPlans := 0
				wantEffects := 0
				wantState, wantStop := "needs_human", "budget_deadline_exceeded"
				if phase != "prepare" && phase != "context" && !plannerCase {
					wantPlans = 1
				}
				if !test.expire {
					wantPlans, wantState, wantStop = 1, "waiting_approval", ""
					if failureCase {
						wantPlans, wantState = 0, "failed"
					}
					if phase == "context" {
						wantPlans, wantState = 0, "planning"
					}
					if phase != "prepare" && phase != "context" && !plannerCase {
						wantEffects, wantState = 1, "running"
						if findingCase {
							wantState = "remediated"
						}
					}
				}
				if result.err != nil || result.state != wantState || state != wantState || stop != wantStop || plans != wantPlans || effects != wantEffects {
					t.Fatalf("mutation crossed expired budget: returned=%s persisted=%s stop=%s plans=%d effects=%d err=%v", result.state, state, stop, plans, effects, result.err)
				}
				if findingCase {
					var status string
					var version int
					if err := observer.QueryRow(ctx, `SELECT status,version FROM zasp_risk_findings WHERE organization_id=$1`, organization).Scan(&status, &version); err != nil {
						t.Fatal(err)
					}
					wantStatus, wantVersion := "open", 1
					if !test.expire {
						wantStatus, wantVersion = "under_review", 2
					}
					if status != wantStatus || version != wantVersion {
						t.Fatalf("finding changed across deadline: status=%s version=%d", status, version)
					}
				}
				if plannerCase {
					var accepted int
					if err := observer.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_planner_receipts WHERE outcome='accepted'`).Scan(&accepted); err != nil {
						t.Fatal(err)
					}
					wantAccepted := 1
					if test.expire || failureCase {
						wantAccepted = 0
					}
					if accepted != wantAccepted {
						t.Fatalf("planner recorded accepted after stop: count=%d", accepted)
					}
					if replay, err := prepare(ctx); err != nil || replay.State != wantState || replay.Version != current.Version+1 {
						t.Fatalf("planner result not replayable: result=%#v err=%v", replay, err)
					}
					if test.expire {
						var crossErr error
						if failureCase {
							_, crossErr = repository.AcceptSecurityAgentPlannerCandidate(ctx, current, workerID, lease, SecurityAgentPlannerSubmission{InputDigest: plannerContext.InputDigest, OutputDigest: "sha256:" + strings.Repeat("b", 64), Model: "fixture/planner", PolicyVersion: "security-agent-planner-v1", Summary: "Bounded response", Action: plannerContext.AllowedActions[0], TargetID: plannerContext.AllowedTargets[0]}, "pid_6a000040-0000-4000-8000-000000000040", time.Now().UTC().Add(10*time.Minute), "pid_6a000041-0000-4000-8000-000000000041", "pid_6a000042-0000-4000-8000-000000000042")
						} else {
							_, crossErr = repository.FailSecurityAgentPlanner(ctx, current, workerID, lease, SecurityAgentPlannerFailure{InputDigest: plannerContext.InputDigest, OutputDigest: "sha256:" + strings.Repeat("b", 64), Model: "fixture/planner", PolicyVersion: "security-agent-planner-v1", ErrorCode: "planner_unavailable"}, "pid_6a000041-0000-4000-8000-000000000041", "pid_6a000042-0000-4000-8000-000000000042")
						}
						// The repository maps PostgreSQL conflicts to its public sentinel.
						if !errors.Is(crossErr, ErrRepositoryConflict) {
							t.Fatalf("cross-method stopped receipt was not a replay conflict: %v", crossErr)
						}
					}
				}
			})
		})
	}
}
