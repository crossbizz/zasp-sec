package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepPlanningWaitPostgres(t *testing.T) {
	for _, mode := range []string{"lease", "deadline", "readiness"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, selection map[string]any, _ string) {
				if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
					t.Fatal(err)
				}
				q["operation"] = "prepare"
				q["payload"] = map[string]any{"pricing": selection, "input_version": "controlled-input-version"}
				if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
					t.Fatal(err)
				}
				var expires time.Time
				if mode == "deadline" {
					if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '1 second' WHERE run_id=$1 RETURNING deadline_at`, q["run_id"]).Scan(&expires); err != nil {
						t.Fatal(err)
					}
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
				if _, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_runs SET updated_at=updated_at WHERE run_id=$1`, q["run_id"]); err != nil {
					t.Fatal(err)
				}
				q["operation"] = "start"
				q["payload"] = map[string]any{}
				done := make(chan error, 1)
				go func() { _, err := orderedPlanningCall(ctx, worker, q); done <- err }()
				joined := false
				defer func() {
					if !joined {
						blocker.Exec(ctx, `ROLLBACK`)
						<-done
					}
				}()
				waiting := false
				for until := time.Now().Add(2 * time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
					if err = owner.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) FROM (SELECT $2::integer) ignored`, worker.PgConn().PID(), blocker.PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if !waiting {
						if err = owner.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1))`, worker.PgConn().PID(), blocker.PgConn().PID()).Scan(&waiting); err != nil {
							t.Fatal(err)
						}
					}
					if waiting {
						break
					}
				}
				if !waiting {
					t.Fatal("planner did not reach controlled run-row wait")
				}
				switch mode {
				case "lease":
					_, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_token='replacement-worker-lease' WHERE run_id=$1`, q["run_id"])
				case "readiness":
					_, err = blocker.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`)
				case "deadline":
					for time.Now().Before(expires.Add(10 * time.Millisecond)) {
						time.Sleep(5 * time.Millisecond)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				result := <-done
				joined = true
				if result == nil {
					t.Fatal("post-wait authority drift issued send permit")
				}
				var state string
				if err = owner.QueryRow(ctx, `SELECT state FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, q["run_id"]).Scan(&state); err != nil || state != "prepared" {
					t.Fatal("post-wait refusal mutated intent", state, err)
				}
			})
		})
	}
}
