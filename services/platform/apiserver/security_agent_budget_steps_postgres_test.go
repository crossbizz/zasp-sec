package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Removing dispatch reservation must fail exact_limit. Ignoring prior usage
// must let over_limit create a forbidden effect. Recounting the same step must
// fail reserved_replay. Approval and historical usage here are owner fixtures,
// not proof of an approval API or a multi-step planner lifecycle.
func TestProductionSecurityAgentBudgetStepReservation(t *testing.T) {
	for _, name := range []string{"exact_limit", "reserved_replay", "over_limit", "conflicting_digest", "conflicting_action", "contended_delivery", "finding_exact_limit", "finding_over_limit"} {
		finding := strings.HasPrefix(name, "finding_")
		mode := strings.TrimPrefix(name, "finding_")
		t.Run(name, func(t *testing.T) {
			runSecurityAgentAttackPathFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				const workerID, lease = "budget-step-worker", "budget-step-worker-lease"
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
				var peer *SecurityAgentWorkerRepository
				var peerConnection *pgx.Conn
				if mode == "contended_delivery" {
					peerConnection, err = pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer peerConnection.Close(context.Background())
					peerDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: peerConnection})
					if err != nil {
						t.Fatal(err)
					}
					peer, err = NewSecurityAgentWorkerRepository(peerDatabase)
					if err != nil {
						t.Fatal(err)
					}
				}
				installSecurityAgentBudgetFragment(t, ctx, owner)
				if _, err := NewSecurityAgentWorkerRepository(database); err == nil {
					t.Fatal("staged upgrade passed predecessor readiness")
				}
				if finding {
					for _, statement := range []string{
						`UPDATE zasp_security_agent_definitions SET body=body||'{"trigger_kind":"finding","trigger_source":"credential","allowed_actions":["update_finding_response"],"verification_kind":"finding_state"}'::jsonb WHERE organization_id=$1`,
						`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) SELECT organization_id,workspace_id,environment_id,'pid_6a000050-0000-4000-8000-000000000050','posture','credential','Step budget target','high','open' FROM zasp_security_agent_definitions WHERE organization_id=$1`,
						`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) SELECT organization_id,workspace_id,environment_id,'update_finding_response',true,updated_by FROM zasp_security_agent_kill_switches WHERE organization_id=$1 AND action_key='*'`,
					} {
						if _, err := owner.Exec(ctx, statement, organization); err != nil {
							t.Fatal(err)
						}
					}
				}
				for _, statement := range []string{
					`UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`,
					`UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{max_steps}','1'::jsonb) WHERE organization_id=$1`,
				} {
					if _, err := owner.Exec(ctx, statement, organization); err != nil {
						t.Fatal(err)
					}
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 1); err != nil || count != 1 {
					t.Fatalf("schedule=%d error=%v", count, err)
				}
				claim := func() SecurityAgentRunClaim {
					t.Helper()
					claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 1)
					if err != nil || len(claims) != 1 {
						t.Fatalf("claims=%d error=%v", len(claims), err)
					}
					return claims[0]
				}
				current := claim()
				if result, err := repository.PrepareSecurityAgentRun(ctx, current, workerID, lease,
					"pid_6a000030-0000-4000-8000-000000000030", time.Now().UTC().Add(10*time.Minute),
					"pid_6a000031-0000-4000-8000-000000000031", "pid_6a000032-0000-4000-8000-000000000032"); err != nil || result.State != "waiting_approval" {
					t.Fatalf("prepare=%+v error=%v", result, err)
				}
				for _, statement := range []string{
					`UPDATE zasp_security_agent_approvals SET state='approved',approver_id='pid_6a000033-0000-4000-8000-000000000033',fresh_auth_at=clock_timestamp(),decided_at=clock_timestamp(),version=version+1 WHERE organization_id=$1`,
					`UPDATE zasp_security_agent_steps SET state='authorized',version=version+1 WHERE organization_id=$1`,
					`UPDATE zasp_security_agent_runs SET state='queued',version=version+1 WHERE organization_id=$1`,
				} {
					if _, err := owner.Exec(ctx, statement, organization); err != nil {
						t.Fatal(err)
					}
				}
				current = claim()
				if mode == "over_limit" {
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
 SELECT organization_id,workspace_id,environment_id,run_id,'pid_6a000040-0000-4000-8000-000000000040',1,action_key,input_digest,authorization_result,'succeeded' FROM zasp_security_agent_steps WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				preseeded := mode != "exact_limit" && mode != "contended_delivery"
				if preseeded {
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,reserved_at)
 SELECT organization_id,workspace_id,environment_id,run_id,step_id,CASE WHEN $2='conflicting_action' THEN 'isolate_session' ELSE action_key END,CASE WHEN $2='conflicting_digest' THEN decode(repeat('ff',32),'hex') ELSE input_digest END,'2026-01-01T00:00:00Z'::timestamptz
 FROM zasp_security_agent_steps WHERE organization_id=$1 AND state=CASE WHEN $2='over_limit' THEN 'succeeded' ELSE 'authorized' END`, organization, mode); err != nil {
						t.Fatal(err)
					}
				}
				var result SecurityAgentExecuteResult
				var operationErr error
				if mode == "contended_delivery" {
					result = contendedBudgetStepDispatch(t, ctx, owner, dsn, []*SecurityAgentWorkerRepository{repository, peer}, []uint32{worker.PgConn().PID(), peerConnection.PgConn().PID()}, current, workerID, lease)
				} else {
					result, operationErr = repository.ExecuteSecurityAgentRun(ctx, current, workerID, lease,
						"pid_6a000034-0000-4000-8000-000000000034", "pid_6a000035-0000-4000-8000-000000000035")
				}
				wantState, wantReason, wantEffects := "running", "", 1
				if finding {
					wantState = "remediated"
				}
				if mode == "over_limit" {
					wantState, wantReason, wantEffects = "needs_human", "budget_steps_exceeded", 0
				}
				conflicting := mode == "conflicting_digest" || mode == "conflicting_action"
				if conflicting {
					wantState, wantEffects = "planning", 0
					if !errors.Is(operationErr, ErrRepositoryConflict) {
						t.Fatalf("conflicting reservation error=%v", operationErr)
					}
				} else if operationErr != nil || result.State != wantState {
					t.Fatalf("dispatch=%+v error=%v want=%s", result, operationErr, wantState)
				}
				var exists bool
				if err := owner.QueryRow(ctx, `SELECT to_regclass('public.zasp_security_agent_step_reservations') IS NOT NULL`).Scan(&exists); err != nil {
					t.Fatal(err)
				}
				if !exists {
					t.Fatal("effect authorized without a durable step reservation")
				}
				var state, reason string
				var effects, reservations int
				if err := owner.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),(SELECT count(*) FROM zasp_security_agent_effects),(SELECT count(*) FROM zasp_security_agent_step_reservations)
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &reason, &effects, &reservations); err != nil {
					t.Fatal(err)
				}
				if state != wantState || reason != wantReason || effects != wantEffects || reservations != 1 {
					t.Fatalf("state=%s reason=%s effects=%d reservations=%d", state, reason, effects, reservations)
				}
				if finding {
					var status string
					var version int
					if err := owner.QueryRow(ctx, `SELECT status,version FROM zasp_risk_findings WHERE organization_id=$1 AND id='pid_6a000050-0000-4000-8000-000000000050'`, organization).Scan(&status, &version); err != nil {
						t.Fatal(err)
					}
					wantStatus, wantVersion := "under_review", 2
					if mode == "over_limit" {
						wantStatus, wantVersion = "open", 1
					}
					if status != wantStatus || version != wantVersion {
						t.Fatalf("finding status=%s version=%d; want %s/%d", status, version, wantStatus, wantVersion)
					}
				}
				var leaseCleared bool
				if err := owner.QueryRow(ctx, `SELECT lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL FROM zasp_security_agent_runs WHERE organization_id=$1`, organization).Scan(&leaseCleared); err != nil || leaseCleared == conflicting {
					t.Fatalf("lease cleared=%v conflicting=%v error=%v", leaseCleared, conflicting, err)
				}
				if preseeded {
					var preserved bool
					if err := owner.QueryRow(ctx, `SELECT reserved_at='2026-01-01T00:00:00Z'::timestamptz FROM zasp_security_agent_step_reservations WHERE organization_id=$1`, organization).Scan(&preserved); err != nil || !preserved {
						t.Fatalf("original reservation changed=%v error=%v", !preserved, err)
					}
				}
				if mode == "exact_limit" {
					var protected bool
					if err := owner.QueryRow(ctx, `SELECT relrowsecurity AND relforcerowsecurity AND relowner='zasp_discovery_authority'::regrole FROM pg_class WHERE oid='public.zasp_security_agent_step_reservations'::regclass`).Scan(&protected); err != nil || !protected {
						t.Fatalf("reservation owner/RLS protection=%v error=%v", protected, err)
					}
					for _, statement := range []string{
						`SELECT * FROM public.zasp_security_agent_step_reservations`,
						`DELETE FROM public.zasp_security_agent_step_reservations WHERE false`,
					} {
						_, err := worker.Exec(ctx, statement)
						var pgError *pgconn.PgError
						if !errors.As(err, &pgError) || pgError.Code != "42501" {
							t.Fatalf("worker direct reservation access error=%v", err)
						}
					}
					// Valid scoped arguments distinguish EXECUTE denial from the
					// helper's own malformed-principal/scope rejection (also42501).
					_, err := worker.Exec(ctx, `SELECT public.zasp_security_agent_budget_reserve_step($1,$2,$3,$4,$5,$6,$7)`,
						current.OrganizationID, current.WorkspaceID, current.EnvironmentID, current.RunID, workerID, lease, result.StepID)
					var pgError *pgconn.PgError
					if !errors.As(err, &pgError) || pgError.Code != "42501" {
						t.Fatalf("worker direct helper access error=%v", err)
					}
				}
			})
		})
	}
}

// Duplicate delivery of one valid claim is sent through two independent worker
// connections. Observe both blocked in PostgreSQL before releasing the guard;
// issuing two goroutines alone would not establish contention.
func contendedBudgetStepDispatch(t *testing.T, ctx context.Context, owner *pgx.Conn, dsn string, repositories []*SecurityAgentWorkerRepository, pids []uint32, claim SecurityAgentRunClaim, workerID, lease string) SecurityAgentExecuteResult {
	t.Helper()
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1::text,0))`, claim.OrganizationID); err != nil {
		t.Fatal(err)
	}
	callContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	type outcome struct {
		result SecurityAgentExecuteResult
		err    error
	}
	done := make(chan outcome, 2)
	joined := 0
	defer func() {
		cancel()
		_ = tx.Rollback(context.Background())
		for joined < 2 {
			<-done
			joined++
		}
	}()
	for index, repository := range repositories {
		go func(index int, repository *SecurityAgentWorkerRepository) {
			result, err := repository.ExecuteSecurityAgentRun(callContext, claim, workerID, lease,
				fmt.Sprintf("pid_6a000034-0000-4000-8000-%012d", index+100), fmt.Sprintf("pid_6a000035-0000-4000-8000-%012d", index+100))
			done <- outcome{result, err}
		}(index, repository)
	}
	for {
		var bothWaiting bool
		if err := observer.QueryRow(callContext, `SELECT $3::integer=ANY(pg_blocking_pids($1::integer)) AND $3::integer=ANY(pg_blocking_pids($2::integer))`, pids[0], pids[1], owner.PgConn().PID()).Scan(&bothWaiting); err != nil {
			t.Fatal(err)
		}
		if bothWaiting {
			break
		}
		select {
		case early := <-done:
			joined++
			t.Fatalf("dispatch escaped held organization guard: result=%+v error=%v", early.result, early.err)
		case <-callContext.Done():
			t.Fatal("both worker lock waits were not observed")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var winner SecurityAgentExecuteResult
	succeeded, conflicted := 0, 0
	for joined < 2 {
		result := <-done
		joined++
		if result.err == nil && result.result.State == "running" {
			succeeded++
			winner = result.result
		} else if errors.Is(result.err, ErrRepositoryConflict) {
			conflicted++
		} else {
			t.Errorf("unexpected contended dispatch: result=%+v error=%v", result.result, result.err)
		}
	}
	if succeeded != 1 || conflicted != 1 || callContext.Err() != nil {
		t.Fatalf("successes=%d conflicts=%d context=%v", succeeded, conflicted, callContext.Err())
	}
	t.Log("observed both worker organization-lock waits; joined two dispatches with one success and one lease conflict")
	return winner
}
