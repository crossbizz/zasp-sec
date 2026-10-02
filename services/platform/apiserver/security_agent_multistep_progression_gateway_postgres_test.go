package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Owner-seeded receipts are authority fixtures, not adapter production proof.
func TestSecurityAgentMultistepProgressionGatewaySafetyWriterPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for i, source := range []string{"device_revocation", "credential_rotation"} {
			t.Run(source, func(t *testing.T) {
				request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 420+i)
				r := request["run_id"].(string)
				admitted, err := orderedProgressionCall(ctx, worker, "admit", request)
				if err != nil {
					t.Fatal(err)
				}
				steps := admitted["step_ids"].([]any)
				if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0].(string), "approve", orderedProgressionApprover, 3)); err != nil {
					t.Fatal(err)
				}
				seedOrderedApplicationAuthority(t, ctx, owner, o, w, e, r, steps[0].(string))
				before := orderedAdmissionSnapshot(t, ctx, owner, r)
				writer, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close(ctx)
				if _, err = writer.Exec(ctx, `BEGIN; SET LOCAL deadlock_timeout='50ms'; SET LOCAL statement_timeout='3s'`); err != nil {
					t.Fatal(err)
				}
				defer writer.Exec(ctx, `ROLLBACK`)
				table := "zasp_gateway_devices"
				if source == "credential_rotation" {
					table = "zasp_gateway_credentials"
				}
				// The real safety writer owns the source row before its AFTER trigger
				// reaches deployment work. Progress must not wait while holding work.
				if _, err = writer.Exec(ctx, `SELECT 1 FROM `+table+` WHERE id=$1 FOR UPDATE`, r); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					_, callErr := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1].(string), "progress", "ordered-progress-worker", 4))
					done <- callErr
				}()
				joined := false
				defer func() {
					writer.Exec(ctx, `ROLLBACK`)
					if !joined {
						<-done
					}
				}()
				// Both valid implementations are accepted: refuse without waiting,
				// or source-first ordering that lets the writer finish without a cycle.
				var callErr error
				reached := false
				for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
					select {
					case callErr = <-done:
						joined = true
					default:
					}
					var waiting bool
					if err = writer.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, worker.PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if joined || waiting {
						reached = true
						break
					}
				}
				if !reached {
					t.Fatal("progression did not reach the held gateway source")
				}
				if source == "device_revocation" {
					_, err = writer.Exec(ctx, `UPDATE zasp_gateway_devices SET state='revoked',revoked_at=clock_timestamp(),version=version+1 WHERE id=$1`, r)
				} else {
					_, err = writer.Exec(ctx, `SELECT zasp_discovery_gateway_rotate($1,$2,$3,$4,$4,$5,'ref:gateway/public/rotated-key',decode(repeat('05',32),'hex'),clock_timestamp()+interval '1 hour')`, o, w, e, r, request["definition_id"])
				}
				if err != nil {
					t.Fatal("progression aborted the gateway safety writer", err)
				}
				if _, err = writer.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				if !joined {
					callErr = <-done
					joined = true
				}
				if callErr == nil {
					t.Fatal("progress accepted changing gateway authority")
				}
				if orderedAdmissionSnapshot(t, ctx, owner, r) != before {
					t.Fatal("gateway refusal mutated ordered authority")
				}
				if _, err = orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1].(string), "progress", "ordered-progress-worker", 4)); err == nil {
					t.Fatal("restart accepted revoked or rotated application")
				}
			})
		}
	})
}
