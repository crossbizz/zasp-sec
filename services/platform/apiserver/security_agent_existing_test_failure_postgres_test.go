package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const existingTestFailureSQL = `SELECT public.zasp_production_security_agent_existing_tests_fail_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

// Real registered-worker failure settlement over owner-seeded admission.
// A late failure receipt must never overwrite a lease or a durable budget stop.
func TestSecurityAgentExistingTestFailurePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		const workerID, lease = "existing-test-failure-worker", "existing-test-failure-lease"
		for i, mode := range []string{"unavailable", "rejected", "rerun_test", "replay", "wrong_digest", "missing_output", "unauthorized_api", "audit_wait_lease", "audit_wait_budget", "audit_wait_target", "receipt_wait_lease", "receipt_wait_budget", "receipt_wait_target", "legacy"} {
			t.Run(mode, func(t *testing.T) {
				run := fmt.Sprintf("pid_89a001%02d-0000-4000-8000-000000000001", i)
				finding := fmt.Sprintf("pid_89a002%02d-0000-4000-8000-000000000002", i)
				action := "run_test"
				if mode == "rerun_test" {
					action = mode
				}
				seedExistingTestPreparation(t, ctx, owner, org, ws, env, testID, actor, run, finding, action, workerID, lease)
				if mode == "legacy" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||'{"allowed_actions":["update_finding_response"],"verification_kind":"finding_state"}'::jsonb WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, org, ws, env); err != nil {
						t.Fatal(err)
					}
				}
				var raw json.RawMessage
				if err := worker.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, env, run, workerID, lease).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var envelope struct {
					Digest string `json:"input_digest"`
				}
				if err := json.Unmarshal(raw, &envelope); err != nil {
					t.Fatal(err)
				}
				input, ok := decodeSecurityAgentDigest(envelope.Digest)
				if !ok {
					t.Fatal("missing input digest")
				}
				errorCode, wantCode := "planner_unavailable", ""
				var output []byte
				caller := worker
				switch mode {
				case "rejected":
					errorCode, output = "planner_rejected", make([]byte, 32)
				case "missing_output":
					errorCode, wantCode = "planner_rejected", "22023"
				case "wrong_digest":
					input[0] ^= 1
					wantCode = "40001"
				case "unauthorized_api":
					caller, wantCode = api, "42501"
				case "audit_wait_lease", "audit_wait_target", "receipt_wait_lease", "receipt_wait_target":
					wantCode = "40001"
				}
				args := []any{org, ws, env, run, workerID, lease, input, output, "fixture-model", "fixture-policy", errorCode, fmt.Sprintf("pid_89a003%02d-0000-4000-8000-000000000001", i), "pid_89a00400-0000-4000-8000-000000000001"}
				invoke := func() error { return caller.QueryRow(ctx, existingTestFailureSQL, args...).Scan(&raw) }
				if strings.Contains(mode, "_wait_") {
					err = existingTestAcceptanceWait(t, ctx, owner, worker, run, mode, invoke)
				} else {
					err = invoke()
				}
				if wantCode != "" {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != wantCode {
						t.Fatalf("failure refusal=%v want=%s", err, wantCode)
					}
				} else if err != nil {
					t.Fatal(err)
				} else if strings.HasSuffix(mode, "_budget") {
					claim := SecurityAgentRunClaim{OrganizationID: org, WorkspaceID: ws, EnvironmentID: env, RunID: run, Attempt: 1, Version: 2}
					if !validSecurityAgentBudgetStop(raw, claim) {
						t.Fatalf("late stop overwritten: %s", raw)
					}
					before := string(raw)
					if err := invoke(); err != nil || string(raw) != before {
						t.Fatalf("stopped receipt replay changed: %s %v", raw, err)
					}
				} else {
					var result SecurityAgentPlannerFailureResult
					if err := json.Unmarshal(raw, &result); err != nil || result.RunID != run || result.State != "failed" || result.Version != 3 || result.ErrorCode != errorCode {
						t.Fatalf("failure envelope=%s %v", raw, err)
					}
				}
				var state, lastError string
				var receipts, audits int
				var noWork bool
				if err := owner.QueryRow(ctx, `SELECT r.state,COALESCE(r.last_error_code,''),
 (SELECT count(*) FROM zasp_security_agent_planner_receipts WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1),
 NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_steps)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_approvals) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs)
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_outbox) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations)
 FROM zasp_security_agent_runs r WHERE r.run_id=$1`, run).Scan(&state, &lastError, &receipts, &audits, &noWork); err != nil {
					t.Fatal(err)
				}
				wantState, wantError, wantReceipts, wantAudits := "failed", errorCode, 1, 1
				if wantCode != "" {
					wantState, wantError, wantReceipts, wantAudits = "planning", "", 0, 0
				} else if strings.HasSuffix(mode, "_budget") {
					wantState, wantError, wantAudits = "needs_human", "budget_deadline_exceeded", 0
				}
				if !noWork || state != wantState || lastError != wantError || receipts != wantReceipts || audits != wantAudits {
					t.Fatalf("failure authority state=%s error=%s receipts=%d audits=%d noWork=%t", state, lastError, receipts, audits, noWork)
				}
				wantVersion := 3
				if wantCode != "" {
					wantVersion = 2
				}
				var leaseExact bool
				if err := owner.QueryRow(ctx, `SELECT version=$5 AND CASE WHEN $2::boolean THEN
 lease_owner=$3 AND lease_token=$4 AND lease_expires_at IS NOT NULL ELSE
 lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL END
 FROM zasp_security_agent_runs WHERE run_id=$1`, run, wantCode != "", workerID, lease, wantVersion).Scan(&leaseExact); err != nil || !leaseExact {
					t.Fatalf("failure changed the wrong lease/version: %t %v", leaseExact, err)
				}
				if mode == "replay" {
					before := existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run)
					var first, replay map[string]any
					if err := json.Unmarshal(raw, &first); err != nil {
						t.Fatal(err)
					}
					if err := invoke(); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(raw, &replay); err != nil {
						t.Fatal(err)
					}
					first["replayed"] = true
					if !reflect.DeepEqual(first, replay) || before != existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) {
						t.Fatal("failure replay rewrote authority")
					}
					args[8] = "conflicting-model"
					var pg *pgconn.PgError
					if err := invoke(); !errors.As(err, &pg) || pg.Code != "23505" || before != existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) {
						t.Fatalf("failure conflict changed authority: %v", err)
					}
				}
			})
		}
	})
}

func TestSecurityAgentExistingTestFailureRepositoryPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		const workerID, lease = "failure-repository-worker", "failure-repository-lease"
		for i, mode := range []string{"unavailable", "rejected", "rerun_test", "budget_stopped"} {
			t.Run(mode, func(t *testing.T) {
				run := fmt.Sprintf("pid_89b001%02d-0000-4000-8000-000000000001", i)
				finding := fmt.Sprintf("pid_89b002%02d-0000-4000-8000-000000000002", i)
				action := "run_test"
				if mode == "rerun_test" {
					action = mode
				}
				seedExistingTestPreparation(t, ctx, owner, org, ws, env, testID, actor, run, finding, action, workerID, lease)
				claim := SecurityAgentRunClaim{OrganizationID: org, WorkspaceID: ws, EnvironmentID: env, RunID: run, TriggerID: finding, State: "planning", Version: 2, Attempt: 1}
				if err := owner.QueryRow(ctx, `SELECT definition_id,definition_version,lease_expires_at FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&claim.DefinitionID, &claim.DefinitionVersion, &claim.LeaseExpiresAt); err != nil {
					t.Fatal(err)
				}
				claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
				planner, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
				if err != nil || planner.ExistingTest == nil || planner.ExistingTest.DefinitionID != testID || planner.ExistingTest.DefinitionVersion != 1 {
					t.Fatalf("repository context=%+v %v", planner, err)
				}
				failure := SecurityAgentPlannerFailure{InputDigest: planner.InputDigest, Model: "fixture-model", PolicyVersion: "fixture-policy", ErrorCode: "planner_unavailable"}
				if mode == "rejected" {
					failure.ErrorCode, failure.OutputDigest = "planner_rejected", "sha256:"+strings.Repeat("a", 64)
				}
				if mode == "budget_stopped" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '1 minute',deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, run); err != nil {
						t.Fatal(err)
					}
				}
				result, err := repository.FailSecurityAgentPlanner(ctx, claim, workerID, lease, failure, fmt.Sprintf("pid_89b003%02d-0000-4000-8000-000000000001", i), "pid_89b00400-0000-4000-8000-000000000001")
				wantState := "failed"
				if mode == "budget_stopped" {
					wantState = "needs_human"
					if !errors.Is(err, ErrSecurityAgentBudgetStopped) {
						t.Fatalf("repository lost stop: %+v %v", result, err)
					}
				} else if err != nil || result.RunID != run || result.State != "failed" || result.Version != 3 || result.ErrorCode != failure.ErrorCode {
					t.Fatalf("repository failure=%+v %v", result, err)
				}
				var exact bool
				if err := owner.QueryRow(ctx, `SELECT r.state=$2 AND r.lease_token IS NULL AND r.version=3 AND p.input_digest=decode(substring($3::text FROM 8),'hex') FROM zasp_security_agent_runs r JOIN zasp_security_agent_planner_receipts p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run, wantState, planner.InputDigest).Scan(&exact); err != nil || !exact {
					t.Fatalf("repository database transition=%t %v", exact, err)
				}
			})
		}
	})
}
