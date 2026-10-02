package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepProgressionWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for i, mode := range []string{"version_wait", "stop_wait", "control_wait", "fresh_auth_write_wait", "deadline_write_wait", "readiness_write_wait", "schema_wait", "concurrent_progress", "cancel_wins", "approval_after_progress"} {
			t.Run(mode, func(t *testing.T) {
				req := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 200+i)
				r := req["run_id"].(string)
				admitted, err := orderedProgressionCall(ctx, worker, "admit", req)
				if err != nil {
					t.Fatal(err)
				}
				steps := admitted["step_ids"].([]any)
				s0, s1 := steps[0].(string), steps[1].(string)
				approve := orderedProgressionRequest(o, w, e, r, s0, "approve", orderedProgressionApprover, 3)
				request := orderedProgressionRequest(o, w, e, r, s1, "progress", "ordered-progress-worker", 4)
				connection := worker
				if mode == "fresh_auth_write_wait" {
					request = approve
					request["fresh_auth_at"] = time.Now().Add(-5*time.Minute + 2*time.Second).UTC().Format(time.RFC3339Nano)
					connection = api
				} else {
					if _, err = orderedProgressionCall(ctx, api, "transition", approve); err != nil {
						t.Fatal(err)
					}
					seedOrderedApplicationAuthority(t, ctx, owner, o, w, e, r, s0)
				}
				blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Close(ctx)
				if _, err = blocker.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer blocker.Exec(ctx, `ROLLBACK`)
				gate := `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`
				args := []any{o}
				if mode == "schema_wait" {
					gate = `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`
					args = nil
				}
				if mode == "fresh_auth_write_wait" || mode == "deadline_write_wait" || mode == "readiness_write_wait" {
					gate = `LOCK TABLE zasp_security_agent_audit IN SHARE MODE`
					args = nil
				}
				if _, err = blocker.Exec(ctx, gate, args...); err != nil {
					t.Fatal(err)
				}
				if mode == "deadline_write_wait" {
					if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1`, r); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				go func() { _, err := orderedProgressionCall(ctx, connection, "transition", request); done <- err }()
				joined := false
				defer func() {
					if !joined {
						blocker.Exec(ctx, `ROLLBACK`)
						<-done
					}
				}()
				waitOrderedProgressionBlocked(t, ctx, blocker, connection)
				if mode == "schema_wait" {
					var reads bool
					if err = blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_schema_versions'::regclass AND granted)`, connection.PgConn().PID()).Scan(&reads); err != nil || reads {
						t.Fatal("schema waiter retained readiness reads", reads, err)
					}
				}
				var second chan error
				var replacement *pgx.Conn
				if mode == "concurrent_progress" || mode == "approval_after_progress" {
					config := worker.Config().Copy()
					secondRequest := request
					if mode == "approval_after_progress" {
						config = api.Config().Copy()
						secondRequest = orderedProgressionRequest(o, w, e, r, s1, "approve", orderedProgressionApprover, 5)
					}
					replacement, err = pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer replacement.Close(ctx)
					second = make(chan error, 1)
					go func() { _, err := orderedProgressionCall(ctx, replacement, "transition", secondRequest); second <- err }()
					waitOrderedProgressionBlocked(t, ctx, blocker, replacement)
				}
				switch mode {
				case "version_wait":
					_, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_runs SET version=version+1 WHERE run_id=$1`, r)
				case "stop_wait":
					_, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`, r)
				case "control_wait":
					_, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_controls SET state='disabled' WHERE run_id=$1`, r)
				case "fresh_auth_write_wait", "deadline_write_wait":
					time.Sleep(2100 * time.Millisecond)
				case "schema_wait", "readiness_write_wait":
					_, err = blocker.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`)
				case "cancel_wins":
					// A real cancellation takes the same Organization lock before the
					// waiting progress call, using an independent API session.
					if _, err = blocker.Exec(ctx, `SET SESSION AUTHORIZATION security_agent_v33_api_login`); err == nil {
						_, err = orderedProgressionCall(ctx, blocker, "transition", orderedProgressionRequest(o, w, e, r, s1, "cancel", orderedProgressionApprover, 4))
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				callErr := <-done
				joined = true
				if mode == "schema_wait" || mode == "readiness_write_wait" {
					if _, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_multistep_checksum'`, migrations.ProductionSecurityAgentMultistep().Checksum()); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "concurrent_progress" || mode == "approval_after_progress" || mode == "stop_wait" {
					if callErr != nil {
						t.Fatal(callErr)
					}
				} else if callErr == nil {
					t.Fatal("post-wait authority loss accepted")
				}
				if second != nil {
					if err = <-second; err != nil {
						t.Fatal("serialized second transition", err)
					}
				}
				var count int
				var state string
				if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1 AND step_id=$2),(SELECT state FROM zasp_security_agent_steps WHERE run_id=$1 AND step_id=$2)`, r, s1).Scan(&count, &state); err != nil {
					t.Fatal(err)
				}
				if mode == "concurrent_progress" {
					if count != 1 || state != "waiting_approval" {
						t.Fatal("progress duplicated readiness", count, state)
					}
				} else if mode == "approval_after_progress" {
					if count != 1 || state != "authorized" {
						t.Fatal("ready approval did not serialize", count, state)
					}
				} else if count != 0 {
					t.Fatal("refusal created successor approval", count)
				}
			})
		}
	})
}

func waitOrderedProgressionBlocked(t *testing.T, ctx context.Context, blocker, waiter *pgx.Conn) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		var waiting bool
		if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, waiter.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
	}
	t.Fatal("transition did not reach the held lock")
}
