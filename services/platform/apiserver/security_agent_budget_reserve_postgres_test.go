package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const reservePlannerBudgetTestSQL = `SELECT zasp_security_agent_budget_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`

// These calls use a real registered worker and commit before owner readback.
// The configured request bounds are fixtures, not verified live model prices.
func TestProductionSecurityAgentPlannerBudgetReservation(t *testing.T) {
	for _, mode := range []string{"exact", "missing_cost", "missing_bound", "wrong_unit", "expired", "tokens_exceeded", "cost_exceeded", "replay", "concurrent", "wait_fresh", "wait_expired", "prior_unknown", "summed_exact", "summed_tokens_exceeded", "summed_cost_exceeded", "wrong_input", "wrong_attempt", "wrong_lease", "wrong_scope", "unauthorized_api"} {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				const workerID, lease = "reserve-planner-worker", "reserve-planner-worker-lease"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1;
`, organization); err != nil {
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
					t.Fatalf("schedule=%d: %v", count, err)
				}
				claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 1)
				if err != nil || len(claims) != 1 {
					t.Fatalf("claims=%d: %v", len(claims), err)
				}
				claim := claims[0]
				// Limits are owner fixtures here. Product configuration/activation
				// and verifiable provider request bounds retain separate gates.
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET max_tokens=100,max_cost_nano_credits=200 WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				prior := mode == "prior_unknown" || mode == "summed_exact" || mode == "summed_tokens_exceeded" || mode == "summed_cost_exceeded"
				if prior {
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_provider_reservations
 (organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest)
 SELECT organization_id,workspace_id,environment_id,run_id,1,'prior-reservation',decode(repeat('11',32),'hex'),'fixture-model','fixture-policy','openrouter_credit',60,100,'prior-worker',decode(repeat('22',32),'hex') FROM zasp_security_agent_run_budgets WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					if mode != "prior_unknown" {
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_provider_reservations SET settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=50,completion_tokens=10,total_tokens=60,cost_nano_credits=100 WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET attempt=2 WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					claim.Attempt = 2
				}
				plannerContext, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
				if err != nil {
					t.Fatal(err)
				}
				digest, ok := decodeSecurityAgentDigest(plannerContext.InputDigest)
				if !ok {
					t.Fatal("fixture context digest invalid")
				}
				tokens, cost := int64(100), any(int64(200))
				wantReason := ""
				switch mode {
				case "missing_cost":
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET max_cost_nano_credits=NULL WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					wantReason = "budget_usage_unknown"
				case "missing_bound":
					cost, wantReason = nil, "budget_usage_unknown"
				case "wrong_unit":
					wantReason = "budget_usage_unknown"
				case "expired":
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					wantReason = "budget_deadline_exceeded"
				case "tokens_exceeded":
					tokens, wantReason = 101, "budget_tokens_exceeded"
				case "cost_exceeded":
					cost, wantReason = int64(201), "budget_cost_exceeded"
				case "wait_expired":
					wantReason = "budget_deadline_exceeded"
				case "replay", "concurrent", "prior_unknown":
					wantReason = "budget_usage_unknown"
				case "summed_exact":
					tokens, cost = 40, int64(100)
				case "summed_tokens_exceeded":
					tokens, cost, wantReason = 41, int64(100), "budget_tokens_exceeded"
				case "summed_cost_exceeded":
					tokens, cost, wantReason = 40, int64(101), "budget_cost_exceeded"
				case "wrong_input":
					digest[0] ^= 1
				}
				attempt, leaseArg := claim.Attempt, lease
				if mode == "wrong_attempt" {
					attempt++
				}
				if mode == "wrong_lease" {
					leaseArg = "wrong-reserve-planner-lease"
				}
				args := []any{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, leaseArg, attempt, "new-reservation", digest, "fixture-model", "fixture-policy", "openrouter_credit", tokens, cost}
				if mode == "wrong_unit" {
					args[11] = "USD"
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
				var payload json.RawMessage
				if mode == "concurrent" || mode == "wait_fresh" || mode == "wait_expired" {
					payload = reservePlannerBudgetWithWait(t, ctx, owner, worker, args, mode, claim, plannerContext.InputDigest)
				} else {
					err = worker.QueryRow(ctx, reservePlannerBudgetTestSQL, args...).Scan(&payload)
				}
				invalid := mode == "wrong_input" || mode == "wrong_attempt" || mode == "wrong_lease" || mode == "wrong_scope" || mode == "unauthorized_api"
				if invalid {
					var pgError *pgconn.PgError
					wantCode := "40001"
					if mode == "unauthorized_api" {
						wantCode = "42501"
					}
					if !errors.As(err, &pgError) || pgError.Code != wantCode {
						t.Fatalf("invalid bound authority accepted: %s %v", payload, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if mode == "replay" {
					if !validReservationTestPermit(payload, claim, plannerContext.InputDigest, tokens, 200) {
						t.Fatalf("first call did not issue bound permit: %s", payload)
					}
					if err := worker.QueryRow(ctx, reservePlannerBudgetTestSQL, args...).Scan(&payload); err != nil {
						t.Fatal(err)
					}
				}
				if wantReason != "" {
					if !validSecurityAgentBudgetStop(payload, claim) {
						t.Fatalf("missing bound durable stop: %s", payload)
					}
				} else if !invalid && !validReservationTestPermit(payload, claim, plannerContext.InputDigest, tokens, cost.(int64)) {
					t.Fatalf("invalid permit: %s", payload)
				}
				var state, reason string
				var count int
				var leaseCleared bool
				if err := owner.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL,
 (SELECT count(*) FROM zasp_security_agent_provider_reservations p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id))
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &reason, &leaseCleared, &count); err != nil {
					t.Fatal(err)
				}
				wantCount := 0
				if prior {
					wantCount++
				}
				if !invalid && wantReason == "" || mode == "replay" || mode == "concurrent" {
					wantCount++
				}
				if count != wantCount || reason != wantReason || (wantReason != "" && (state != "needs_human" || !leaseCleared)) || (wantReason == "" && (state != "planning" || leaseCleared)) {
					t.Fatalf("committed state=%s reason=%s cleared=%v reservations=%d want=%d", state, reason, leaseCleared, count, wantCount)
				}
				if !invalid && wantReason == "" || mode == "replay" || mode == "concurrent" {
					var bound bool
					if err := owner.QueryRow(ctx, `SELECT attempt=$2 AND input_digest=$3 AND model='fixture-model' AND cost_policy_version='fixture-policy' AND cost_unit='openrouter_credit'
 AND maximum_tokens=$4 AND maximum_cost_nano_credits=$5 AND worker_id=$6 AND lease_token_digest=digest(convert_to($7::text,'UTF8'),'sha256') AND settled_at IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL
 FROM zasp_security_agent_provider_reservations WHERE organization_id=$1 AND reservation_id='new-reservation'`, organization, claim.Attempt, digest, tokens, cost, workerID, lease).Scan(&bound); err != nil || !bound {
						t.Fatalf("committed permit identity mismatch: %v %v", bound, err)
					}
				}
				if !invalid && wantReason == "" {
					var expiryMatches bool
					if err := owner.QueryRow(ctx, `SELECT ($2::jsonb->'budget_permit'->>'expires_at')::timestamptz=least(r.lease_expires_at,b.deadline_at)
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization, string(payload)).Scan(&expiryMatches); err != nil || !expiryMatches {
						t.Fatalf("permit expiry not bound to lease/deadline: %v %v", expiryMatches, err)
					}
				}
				if mode == "exact" {
					var private bool
					if err := owner.QueryRow(ctx, `SELECT has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE') AND NOT EXISTS(
 SELECT 1 FROM unnest(ARRAY['zasp_discovery_api','zasp_discovery_worker','zasp_security_agent_api','zasp_security_agent_action_worker']) role_name WHERE has_function_privilege(role_name,p.oid,'EXECUTE'))
 FROM pg_proc p WHERE p.oid='zasp_security_agent_budget_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)'::regprocedure`).Scan(&private); err != nil || !private {
						t.Fatalf("reservation grant leaked: %v %v", private, err)
					}
				}
			})
		})
	}
}

// Observe real backend blockers, then release. Both in-flight calls are joined
// even when a timing assertion fails; no arbitrary sleep is acceptance evidence.
func reservePlannerBudgetWithWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, args []any, mode string, claim SecurityAgentRunClaim, digest string) json.RawMessage {
	t.Helper()
	callContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	observer, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	connections := []*pgx.Conn{worker}
	if mode == "concurrent" {
		second, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close(context.Background())
		connections = append(connections, second)
	}
	if mode == "wait_expired" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE organization_id=$1`, claim.OrganizationID); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	lockSQL := `SELECT 1 FROM zasp_security_agent_definitions WHERE organization_id=$1 FOR UPDATE`
	if mode == "concurrent" {
		lockSQL = `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`
	}
	if _, err := tx.Exec(ctx, lockSQL, claim.OrganizationID); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		payload json.RawMessage
		err     error
	}
	results := make(chan outcome, len(connections))
	for _, connection := range connections {
		go func(connection *pgx.Conn) {
			var result outcome
			result.err = connection.QueryRow(callContext, reservePlannerBudgetTestSQL, args...).Scan(&result.payload)
			results <- result
		}(connection)
	}
	joined := 0
	defer func() {
		cancel()
		tx.Rollback(context.Background())
		for joined < len(connections) {
			<-results
			joined++
		}
	}()
	observedFresh := false
	for {
		allWaiting, expired := true, false
		for _, connection := range connections {
			var waiting bool
			if err := observer.QueryRow(callContext, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer)),(SELECT deadline_at<=clock_timestamp() FROM zasp_security_agent_run_budgets WHERE organization_id=$3)`, connection.PgConn().PID(), owner.PgConn().PID(), claim.OrganizationID).Scan(&waiting, &expired); err != nil {
				t.Fatal(err)
			}
			allWaiting = allWaiting && waiting
		}
		if allWaiting && !expired {
			observedFresh = true
		}
		if allWaiting && (mode != "wait_expired" || expired) {
			break
		}
		select {
		case <-callContext.Done():
			t.Fatal("reservation never reached expected lock schedule")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !observedFresh {
		t.Fatal("did not observe reservation blocked before deadline")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	permits, stops := 0, 0
	var last, stopped json.RawMessage
	for joined < len(connections) {
		result := <-results
		joined++
		if result.err != nil {
			t.Fatal(result.err)
		}
		last = result.payload
		if validReservationTestPermit(last, claim, digest, 100, 200) {
			permits++
		}
		if validSecurityAgentBudgetStop(last, claim) {
			stops++
			stopped = last
		}
	}
	if mode == "concurrent" {
		if permits != 1 || stops != 1 {
			t.Fatalf("concurrent permits=%d stops=%d", permits, stops)
		}
		return stopped
	}
	return last
}

func validReservationTestPermit(payload json.RawMessage, claim SecurityAgentRunClaim, digest string, tokens, cost int64, reservationIDs ...string) bool {
	reservationID := "new-reservation"
	if len(reservationIDs) == 1 {
		reservationID = reservationIDs[0]
	}
	var envelope struct {
		Permit struct {
			OrganizationID string    `json:"organization_id"`
			WorkspaceID    string    `json:"workspace_id"`
			EnvironmentID  string    `json:"environment_id"`
			RunID          string    `json:"run_id"`
			Attempt        int       `json:"attempt"`
			Version        int64     `json:"version"`
			ExpiresAt      time.Time `json:"expires_at"`
			ReservationID  string    `json:"reservation_id"`
			InputDigest    string    `json:"input_digest"`
			Model          string    `json:"model"`
			Policy         string    `json:"cost_policy_version"`
			Unit           string    `json:"cost_unit"`
			Tokens         int64     `json:"maximum_tokens"`
			Cost           int64     `json:"maximum_cost_nano_credits"`
		} `json:"budget_permit"`
	}
	if json.Unmarshal(payload, &envelope) != nil {
		return false
	}
	p := envelope.Permit
	return p.OrganizationID == claim.OrganizationID && p.WorkspaceID == claim.WorkspaceID && p.EnvironmentID == claim.EnvironmentID && p.RunID == claim.RunID && p.Attempt == claim.Attempt && p.Version == claim.Version && !p.ExpiresAt.IsZero() && p.ReservationID == reservationID && p.InputDigest == digest && p.Model == "fixture-model" && p.Policy == "fixture-policy" && p.Unit == "openrouter_credit" && p.Tokens == tokens && p.Cost == cost
}
