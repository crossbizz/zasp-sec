package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const settlePlannerBudgetTestSQL = `SELECT zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

func TestProductionSecurityAgentPlannerBudgetSettlement(t *testing.T) {
	for _, mode := range []string{"exact", "zero", "replay", "old_replay_during_new", "two_settlements", "terminal", "concurrent_replay", "concurrent_conflict", "conflict_digest", "conflict_usage", "missing_usage", "inconsistent_usage", "overflow_usage", "negative_usage", "missing_output", "tokens_over", "cost_over", "expired_lease", "after_reclaim", "after_stop", "unknown_then_known", "deadline", "wrong_worker", "wrong_lease", "wrong_attempt", "wrong_scope", "unauthorized_api"} {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const org = "pid_6a000001-0000-4000-8000-000000000001"
				const workerID, lease = "settle-planner-worker", "settle-planner-worker-lease"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, org); err != nil {
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
					t.Fatal(err)
				}
				if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 1); err != nil || count != 1 {
					t.Fatalf("schedule=%d %v", count, err)
				}
				claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 1)
				if err != nil || len(claims) != 1 {
					t.Fatalf("claims=%d %v", len(claims), err)
				}
				claim := claims[0]
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET max_tokens=100,max_cost_nano_credits=200 WHERE organization_id=$1`, org); err != nil {
					t.Fatal(err)
				}
				planner, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
				if err != nil {
					t.Fatal(err)
				}
				input, ok := decodeSecurityAgentDigest(planner.InputDigest)
				if !ok {
					t.Fatal("invalid context digest")
				}
				reserveArgs := []any{org, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, lease, claim.Attempt, "new-reservation", input, "fixture-model", "fixture-policy", "openrouter_credit", int64(100), int64(200)}
				var permit json.RawMessage
				if err := worker.QueryRow(ctx, reservePlannerBudgetTestSQL, reserveArgs...).Scan(&permit); err != nil || !validReservationTestPermit(permit, claim, planner.InputDigest, 100, 200) {
					t.Fatalf("reserve=%s %v", permit, err)
				}
				wantReason := ""
				if mode == "terminal" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='contained',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1 WHERE organization_id=$1`, org); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "expired_lease" || mode == "after_reclaim" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, org); err != nil {
						t.Fatal(err)
					}
					if mode == "after_reclaim" {
						claims, err := repository.ClaimSecurityAgentRuns(ctx, "replacement-worker", "replacement-worker-lease", 60, 1)
						if err != nil || len(claims) != 1 || claims[0].Attempt != 2 {
							t.Fatalf("reclaim=%v %v", claims, err)
						}
					}
				}
				if mode == "after_stop" {
					if err := worker.QueryRow(ctx, reservePlannerBudgetTestSQL, reserveArgs...).Scan(&permit); err != nil || !validSecurityAgentBudgetStop(permit, claim) {
						t.Fatalf("stop=%s %v", permit, err)
					}
					wantReason = "budget_usage_unknown"
				}
				if mode == "deadline" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, org); err != nil {
						t.Fatal(err)
					}
					wantReason = "budget_deadline_exceeded"
				}
				output := make([]byte, 32)
				for i := range output {
					output[i] = 0x33
				}
				prompt, completion, total, cost := int64(80), int64(20), int64(100), any(int64(200))
				known := true
				switch mode {
				case "zero":
					prompt, completion, total, cost = 0, 0, 0, int64(0)
				case "old_replay_during_new", "two_settlements":
					prompt, completion, total, cost = 50, 10, 60, int64(100)
				case "missing_usage", "unknown_then_known":
					cost = nil
					known = false
					wantReason = "budget_usage_unknown"
				case "inconsistent_usage":
					total = 99
					known = false
					wantReason = "budget_usage_unknown"
				case "overflow_usage":
					prompt, completion, total = 9223372036854775807, 1, 0
					known = false
					wantReason = "budget_usage_unknown"
				case "negative_usage":
					prompt, completion, total = -1, 1, 0
					known = false
					wantReason = "budget_usage_unknown"
				case "missing_output":
					output = nil
					known = false
					wantReason = "budget_usage_unknown"
				case "tokens_over":
					completion, total = 21, 101
					wantReason = "budget_tokens_exceeded"
				case "cost_over":
					cost = int64(201)
					wantReason = "budget_cost_exceeded"
				}
				args := []any{org, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, lease, claim.Attempt, "new-reservation", output, prompt, completion, total, cost}
				if mode == "wrong_worker" {
					args[4] = "another-worker"
				}
				if mode == "wrong_lease" {
					args[5] = "another-worker-lease"
				}
				if mode == "wrong_attempt" {
					args[6] = claim.Attempt + 1
				}
				if mode == "wrong_scope" {
					args[0] = "pid_9a000001-0000-4000-8000-000000000001"
				}
				if mode == "unauthorized_api" {
					apiConfig := worker.Config().Copy()
					apiConfig.User = "security_agent_v33_api_login"
					worker, err = pgx.ConnectConfig(ctx, apiConfig)
					if err != nil {
						t.Fatal(err)
					}
					defer worker.Close(context.Background())
				}
				readRun := func() string {
					t.Helper()
					var value string
					if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(state,version,lease_owner,lease_token,lease_expires_at)::text FROM zasp_security_agent_runs WHERE organization_id=$1`, org).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				readReservation := func() string {
					t.Helper()
					var value string
					if err := owner.QueryRow(ctx, `SELECT to_jsonb(p)::text FROM zasp_security_agent_provider_reservations p WHERE organization_id=$1 AND reservation_id='new-reservation'`, org).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				beforeRun, beforeReservation := readRun(), readReservation()
				var payload json.RawMessage
				if strings.HasPrefix(mode, "concurrent_") {
					payload, cost = settlePlannerBudgetConcurrently(t, ctx, owner, worker, args, mode == "concurrent_conflict")
				} else {
					err = worker.QueryRow(ctx, settlePlannerBudgetTestSQL, args...).Scan(&payload)
				}
				invalid := strings.HasPrefix(mode, "wrong_") || mode == "unauthorized_api"
				if invalid {
					var pgError *pgconn.PgError
					wantCode := "40001"
					if mode == "unauthorized_api" {
						wantCode = "42501"
					}
					if !errors.As(err, &pgError) || pgError.Code != wantCode {
						t.Fatalf("wrong settlement issuer accepted: %s %v", payload, err)
					}
					if readRun() != beforeRun || readReservation() != beforeReservation {
						t.Fatal("rejected settlement changed authority")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if mode == "old_replay_during_new" || mode == "two_settlements" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, org); err != nil {
						t.Fatal(err)
					}
					newClaims, err := repository.ClaimSecurityAgentRuns(ctx, "second-worker", "second-worker-lease", 60, 1)
					if err != nil || len(newClaims) != 1 || newClaims[0].Attempt != 2 {
						t.Fatalf("second claim=%v %v", newClaims, err)
					}
					secondClaim := newClaims[0]
					secondContext, err := repository.LoadSecurityAgentPlannerContext(ctx, secondClaim, "second-worker", "second-worker-lease")
					if err != nil {
						t.Fatal(err)
					}
					secondInput, ok := decodeSecurityAgentDigest(secondContext.InputDigest)
					if !ok {
						t.Fatal("second context invalid")
					}
					secondArgs := []any{org, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, "second-worker", "second-worker-lease", secondClaim.Attempt, "second-reservation", secondInput, "fixture-model", "fixture-policy", "openrouter_credit", int64(40), int64(100)}
					var secondPermit json.RawMessage
					if err := worker.QueryRow(ctx, reservePlannerBudgetTestSQL, secondArgs...).Scan(&secondPermit); err != nil || !validReservationTestPermit(secondPermit, secondClaim, secondContext.InputDigest, 40, 100, "second-reservation") {
						t.Fatalf("second request not permitted: %s %v", secondPermit, err)
					}
					beforeRun, beforeReservation = readRun(), readReservation()
					if mode == "two_settlements" {
						var secondSettlement json.RawMessage
						if err := worker.QueryRow(ctx, settlePlannerBudgetTestSQL, org, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, "second-worker", "second-worker-lease", secondClaim.Attempt, "second-reservation", output, int64(30), int64(10), int64(40), int64(100)).Scan(&secondSettlement); err != nil {
							t.Fatal(err)
						}
						var exactTotal bool
						if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND count(settled_at)=2 AND sum(total_tokens)=100 AND sum(cost_nano_credits)=200 FROM zasp_security_agent_provider_reservations WHERE organization_id=$1`, org).Scan(&exactTotal); err != nil || !exactTotal {
							t.Fatalf("two actual settlements lost accounting: %v %v", exactTotal, err)
						}
					} else if err := worker.QueryRow(ctx, settlePlannerBudgetTestSQL, args...).Scan(&payload); err != nil {
						t.Fatal(err)
					}
					if readRun() != beforeRun || readReservation() != beforeReservation {
						t.Fatal("old settlement replay changed newer in-flight authority")
					}
					var pending bool
					if err := owner.QueryRow(ctx, `SELECT (settled_at IS NULL)=$2 AND maximum_tokens=40 AND maximum_cost_nano_credits=100 FROM zasp_security_agent_provider_reservations WHERE organization_id=$1 AND reservation_id='second-reservation'`, org, mode != "two_settlements").Scan(&pending); err != nil || !pending {
						t.Fatalf("new reservation changed: %v %v", pending, err)
					}
				}
				if mode == "replay" || mode == "conflict_digest" || mode == "conflict_usage" {
					beforeRun, beforeReservation = readRun(), readReservation()
					if mode == "conflict_digest" {
						changed := append([]byte(nil), output...)
						changed[0] ^= 1
						args[8] = changed
					}
					if mode == "conflict_usage" {
						args[12] = int64(199)
					}
					var second json.RawMessage
					err = worker.QueryRow(ctx, settlePlannerBudgetTestSQL, args...).Scan(&second)
					if mode == "replay" {
						if err != nil || string(second) != string(payload) {
							t.Fatalf("replay changed settlement: %s %s %v", payload, second, err)
						}
					} else {
						var pgError *pgconn.PgError
						if !errors.As(err, &pgError) || pgError.Code != "23505" {
							t.Fatalf("conflicting settlement accepted: %s %v", second, err)
						}
					}
					if readRun() != beforeRun || readReservation() != beforeReservation {
						t.Fatal("replay mutated durable authority")
					}
				}
				if mode == "unknown_then_known" {
					beforeRun = readRun()
					args[12] = int64(200)
					cost = int64(200)
					known = true
					if err := worker.QueryRow(ctx, settlePlannerBudgetTestSQL, args...).Scan(&payload); err != nil {
						t.Fatal(err)
					}
					if readRun() != beforeRun {
						t.Fatal("late known usage renewed stopped run")
					}
				}
				var envelope struct {
					Settlement struct {
						OrganizationID string `json:"organization_id"`
						WorkspaceID    string `json:"workspace_id"`
						EnvironmentID  string `json:"environment_id"`
						RunID          string `json:"run_id"`
						Attempt        int    `json:"attempt"`
						ReservationID  string `json:"reservation_id"`
						Known          bool   `json:"known"`
						Reason         string `json:"stop_reason"`
					} `json:"budget_settlement"`
				}
				if json.Unmarshal(payload, &envelope) != nil {
					t.Fatalf("bad response %s", payload)
				}
				s := envelope.Settlement
				if !exactJSONFields(payload, "budget_settlement") || s.OrganizationID != org || s.WorkspaceID != claim.WorkspaceID || s.EnvironmentID != claim.EnvironmentID || s.RunID != claim.RunID || s.Attempt != claim.Attempt || s.ReservationID != "new-reservation" || s.Known != known || s.Reason != wantReason {
					t.Fatalf("unbound settlement: %s", payload)
				}
				var reason, state string
				var cleared, usageMatches bool
				if err := owner.QueryRow(ctx, `SELECT coalesce(b.stop_reason,''),r.state,r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, org).Scan(&reason, &state, &cleared); err != nil {
					t.Fatal(err)
				}
				if reason != wantReason || (wantReason != "" && (state != "needs_human" || !cleared)) {
					t.Fatalf("settlement stop not durable: %s %s %v", reason, state, cleared)
				}
				if wantReason == "" || mode == "after_stop" {
					if readRun() != beforeRun {
						t.Fatal("settlement changed lease/version without a new stop")
					}
				}
				if known {
					if err := owner.QueryRow(ctx, `SELECT settled_at IS NOT NULL AND output_digest=$2 AND prompt_tokens=$3 AND completion_tokens=$4 AND total_tokens=$5 AND cost_nano_credits=$6 AND maximum_tokens=100 AND maximum_cost_nano_credits=200 FROM zasp_security_agent_provider_reservations WHERE organization_id=$1 AND reservation_id='new-reservation'`, org, output, prompt, completion, total, cost).Scan(&usageMatches); err != nil || !usageMatches {
						t.Fatalf("known usage not persisted exactly: %v %v", usageMatches, err)
					}
				} else {
					if err := owner.QueryRow(ctx, `SELECT settled_at IS NULL AND output_digest IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL AND maximum_tokens=100 AND maximum_cost_nano_credits=200 FROM zasp_security_agent_provider_reservations WHERE organization_id=$1`, org).Scan(&usageMatches); err != nil || !usageMatches {
						t.Fatalf("unknown usage released allowance: %v %v", usageMatches, err)
					}
				}
				if mode == "exact" {
					var private bool
					if err := owner.QueryRow(ctx, `SELECT has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE') AND NOT EXISTS(
 SELECT 1 FROM unnest(ARRAY['zasp_discovery_api','zasp_discovery_worker','zasp_security_agent_api','zasp_security_agent_action_worker']) role_name WHERE has_function_privilege(role_name,p.oid,'EXECUTE'))
 FROM pg_proc p WHERE p.oid='zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint)'::regprocedure`).Scan(&private); err != nil || !private {
						t.Fatalf("settlement grants leaked: %v %v", private, err)
					}
				}
			})
		})
	}
}

func settlePlannerBudgetConcurrently(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, args []any, conflict bool) (json.RawMessage, int64) {
	t.Helper()
	callContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	observer, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	second, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, args[0]); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		payload json.RawMessage
		cost    int64
		err     error
	}
	results := make(chan outcome, 2)
	for index, connection := range []*pgx.Conn{worker, second} {
		request := append([]any(nil), args...)
		if index == 1 && conflict {
			request[12] = int64(199)
		}
		go func(connection *pgx.Conn, request []any) {
			result := outcome{cost: request[12].(int64)}
			result.err = connection.QueryRow(callContext, settlePlannerBudgetTestSQL, request...).Scan(&result.payload)
			results <- result
		}(connection, request)
	}
	joined := 0
	defer func() {
		cancel()
		tx.Rollback(context.Background())
		for joined < 2 {
			<-results
			joined++
		}
	}()
	for {
		var blocked bool
		if err := observer.QueryRow(callContext, `SELECT $3::integer=ANY(pg_blocking_pids($1::integer)) AND $3::integer=ANY(pg_blocking_pids($2::integer))`, worker.PgConn().PID(), second.PgConn().PID(), owner.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-callContext.Done():
			t.Fatal("both settlements did not reach organization lock")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	successes, conflicts := 0, 0
	var payload json.RawMessage
	var cost int64
	for joined < 2 {
		result := <-results
		joined++
		if result.err == nil {
			successes++
			payload = result.payload
			cost = result.cost
		} else {
			var pgError *pgconn.PgError
			if !errors.As(result.err, &pgError) || pgError.Code != "23505" {
				t.Fatal(result.err)
			}
			conflicts++
		}
	}
	if conflict {
		if successes != 1 || conflicts != 1 {
			t.Fatalf("conflicting settlements successes=%d conflicts=%d", successes, conflicts)
		}
	} else if successes != 2 || conflicts != 0 {
		t.Fatalf("identical settlements successes=%d conflicts=%d", successes, conflicts)
	}
	return payload, cost
}
