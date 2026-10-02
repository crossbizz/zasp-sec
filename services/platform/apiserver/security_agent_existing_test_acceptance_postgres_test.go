package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const existingTestAcceptSQL = `SELECT public.zasp_production_security_agent_existing_tests_accept_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

// Real worker acceptance must bind the candidate to freshly recomputed context,
// not caller-selected versions or targets. A replay must not create a new plan.
func TestSecurityAgentExistingTestAcceptancePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		const workerID, lease = "existing-test-accept-worker", "existing-test-accept-lease"
		for i, mode := range []string{"run_test", "rerun_test", "replay", "substituted_target", "caller_version", "wrong_digest", "changed_version", "unauthorized_api", "audit_wait_lease", "audit_wait_budget", "audit_wait_target", "receipt_wait_lease", "receipt_wait_budget", "receipt_wait_target"} {
			t.Run(mode, func(t *testing.T) {
				run := fmt.Sprintf("pid_899001%02d-0000-4000-8000-000000000001", i)
				finding := fmt.Sprintf("pid_899002%02d-0000-4000-8000-000000000002", i)
				action := "run_test"
				if mode == "rerun_test" {
					action = mode
				}
				seedExistingTestPreparation(t, ctx, owner, org, ws, env, testID, actor, run, finding, action, workerID, lease)
				var raw json.RawMessage
				if err := worker.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, env, run, workerID, lease).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var contextEnvelope struct {
					InputDigest string `json:"input_digest"`
				}
				if err := json.Unmarshal(raw, &contextEnvelope); err != nil {
					t.Fatal(err)
				}
				input, ok := decodeSecurityAgentDigest(contextEnvelope.InputDigest)
				if !ok {
					t.Fatal("missing authoritative input digest")
				}
				step := map[string]any{"index": 0, "action": action, "target_id": testID}
				wantCode := ""
				caller := worker
				switch mode {
				case "substituted_target":
					step["target_id"], wantCode = env, "40001"
				case "caller_version":
					step["test_definition_version"], wantCode = 2, "22023"
				case "wrong_digest":
					input[0] ^= 1
					wantCode = "40001"
				case "changed_version":
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=2 WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{existing_test,definition_version}','2') WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, testID); err != nil {
						t.Fatal(err)
					}
					wantCode = "40001"
				case "unauthorized_api":
					caller, wantCode = api, "42501"
				case "audit_wait_lease", "audit_wait_target", "receipt_wait_lease", "receipt_wait_target":
					wantCode = "40001"
				}
				candidate, err := json.Marshal(map[string]any{"version": 1, "summary": "Execute the pinned test", "steps": []any{step}})
				if err != nil {
					t.Fatal(err)
				}
				output := sha256.Sum256(candidate)
				args := []any{org, ws, env, run, workerID, lease, input, output[:], "fixture-model", "fixture-policy", json.RawMessage(candidate), fmt.Sprintf("pid_899003%02d-0000-4000-8000-000000000001", i), time.Now().UTC().Add(10 * time.Minute), fmt.Sprintf("pid_899004%02d-0000-4000-8000-000000000001", i), "pid_89900500-0000-4000-8000-000000000001"}
				invoke := func() error { return caller.QueryRow(ctx, existingTestAcceptSQL, args...).Scan(&raw) }
				if strings.Contains(mode, "_wait_") {
					err = existingTestAcceptanceWait(t, ctx, owner, worker, run, mode, invoke)
				} else {
					err = invoke()
				}
				if wantCode != "" {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != wantCode {
						t.Fatalf("accept refusal=%v want=%s", err, wantCode)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if mode == "replay" {
						var first map[string]any
						if err := json.Unmarshal(raw, &first); err != nil {
							t.Fatal(err)
						}
						before := existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run)
						if err := invoke(); err != nil {
							t.Fatal(err)
						}
						var replay map[string]any
						if err := json.Unmarshal(raw, &replay); err != nil {
							t.Fatal(err)
						}
						first["replayed"] = true
						if !reflect.DeepEqual(first, replay) || before != existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) {
							t.Fatal("replay changed response or persisted authority")
						}
					}
					var result struct {
						SecurityAgentPrepareResult
						Outcome  string `json:"planner_outcome"`
						Replayed bool   `json:"replayed"`
					}
					wantState, wantOutcome := "waiting_approval", "accepted"
					if strings.HasSuffix(mode, "_budget") {
						wantState, wantOutcome = "needs_human", "budget_stopped"
					}
					if err := json.Unmarshal(raw, &result); err != nil || result.RunID != run || result.State != wantState || result.Outcome != wantOutcome || result.Replayed != (mode == "replay") {
						t.Fatalf("accept envelope=%s err=%v", raw, err)
					}
				}
				var plans, receipts, approvals, effects, links, steps, audits int
				if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_planner_receipts WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_test_links WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_steps WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1)`, run).Scan(&plans, &receipts, &approvals, &effects, &links, &steps, &audits); err != nil {
					t.Fatal(err)
				}
				want := 0
				if wantCode == "" {
					want = 1
				}
				wantReceipt := want
				if strings.HasSuffix(mode, "_budget") {
					want = 0
					var stopped bool
					if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.lease_token IS NULL AND b.stop_reason='budget_deadline_exceeded' FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&stopped); err != nil || !stopped {
						t.Fatalf("late budget stop lost: %t %v", stopped, err)
					}
				}
				if plans != want || receipts != wantReceipt || approvals != want || steps != want || audits != want || effects+links != 0 {
					t.Fatalf("unexpected acceptance writes: plans=%d receipts=%d approvals=%d effects=%d links=%d steps=%d audits=%d", plans, receipts, approvals, effects, links, steps, audits)
				}
				var noExecution bool
				if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_red_team_runs)
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_outbox)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations)`).Scan(&noExecution); err != nil || !noExecution {
					t.Fatalf("acceptance executed or reserved external work: %t %v", noExecution, err)
				}
				if mode == "replay" {
					before := existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run)
					args[8] = "substituted-model"
					var pg *pgconn.PgError
					if err := invoke(); !errors.As(err, &pg) || pg.Code != "23505" || before != existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) {
						t.Fatalf("conflicting replay changed authority: %v", err)
					}
					args[8] = "fixture-model"
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='planning',attempt=attempt+1,version=version+1,lease_owner='new-worker',lease_token='new-worker-lease-token',lease_expires_at=clock_timestamp()+interval '1 minute' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
						t.Fatal(err)
					}
					before = existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run)
					if err := invoke(); !errors.As(err, &pg) || pg.Code != "40001" || before != existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) {
						t.Fatalf("old attempt disturbed newer lease: %v", err)
					}
				}
			})
		}
	})
}

func existingTestAcceptanceWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, run, mode string, invoke func() error, deadlines ...time.Time) error {
	t.Helper()
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	table := "zasp_security_agent_audit"
	if strings.HasPrefix(mode, "receipt_") {
		table = "zasp_security_agent_planner_receipts"
	}
	if strings.HasPrefix(mode, "enqueue_") {
		table = "zasp_red_team_outbox"
	}
	if strings.HasPrefix(mode, "link_") {
		table = "zasp_security_agent_test_links"
	}
	if strings.HasPrefix(mode, "invocation_") {
		table = "zasp_security_agent_test_invocations"
	}
	if strings.HasPrefix(mode, "claim_") {
		table = "zasp_red_team_runs"
	}
	if strings.HasPrefix(mode, "finish_") {
		table = "zasp_red_team_attempts"
	}
	if strings.HasPrefix(mode, "dispatch_final_") {
		table = "zasp_security_agent_runs"
	}
	if _, err := blocker.Exec(ctx, "BEGIN; LOCK TABLE "+table+" IN SHARE MODE"); err != nil {
		t.Fatal(err)
	}
	defer blocker.Exec(context.Background(), "ROLLBACK")
	deadlineSQL := `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
	id := run
	if strings.HasSuffix(mode, "_budget") {
		deadlineSQL = `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING deadline_at`
	}
	if strings.HasSuffix(mode, "_approval") {
		deadlineSQL = `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING expires_at`
	}
	if strings.HasSuffix(mode, "_target") {
		deadlineSQL = `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING fresh_until`
		id = "pid_89000011-0000-4000-8000-000000000001"
		defer owner.Exec(context.Background(), `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, id)
	}
	var deadline time.Time
	if len(deadlines) == 1 {
		deadline = deadlines[0]
	} else {
		if err := owner.QueryRow(ctx, deadlineSQL, id).Scan(&deadline); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- invoke() }()
	joined := false
	defer func() {
		if !joined {
			blocker.Exec(context.Background(), "ROLLBACK")
			<-done
		}
	}()
	observed := false
	for time.Now().Before(deadline) {
		if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND clock_timestamp()<$2::timestamptz AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation=$3::regclass AND mode='RowExclusiveLock' AND NOT granted)`, worker.PgConn().PID(), deadline, table).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("acceptance INSERT blocker not observed before expiry")
	}
	for {
		var expired bool
		if err := blocker.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := blocker.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	return err
}

func existingTestAcceptanceSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, run string) string {
	t.Helper()
	var snapshot string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'run',(SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'plan',(SELECT to_jsonb(p) FROM zasp_security_agent_plans p WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'steps',(SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM zasp_security_agent_steps s WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'approvals',(SELECT jsonb_agg(to_jsonb(a) ORDER BY approval_id) FROM zasp_security_agent_approvals a WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'receipts',(SELECT jsonb_agg(to_jsonb(p) ORDER BY attempt) FROM zasp_security_agent_planner_receipts p WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)))::text`, org, ws, env, run).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
