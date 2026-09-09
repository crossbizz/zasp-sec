package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These privileged source-row fixtures isolate trigger interleavings. Production
// insertion remains covered by the coordinator receipt and combined worker tests.
func testRuntimeSessionSummaryConcurrency(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	const first = "pid_97000101-0000-4000-8000-000000000101"
	const second = "pid_97000102-0000-4000-8000-000000000102"
	const insert = `INSERT INTO zasp_runtime_session_events SELECT organization_id,workspace_id,environment_id,$1,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time+interval '1 hour',projected_at FROM zasp_runtime_session_events WHERE session_id IS NOT NULL ORDER BY event_id LIMIT 1`
	assertSummary := func(t *testing.T) {
		t.Helper()
		var equal bool
		err := admin.QueryRow(ctx, `WITH actual AS (SELECT organization_id,workspace_id,environment_id,COALESCE(session_id,'unattributed') id,min(event_time) first_event_at,max(event_time) last_event_at,max(projected_at) projected_at,count(*) event_count,count(*) FILTER(WHERE confidence='exact') exact_count,count(*) FILTER(WHERE confidence='strong') strong_count,count(*) FILTER(WHERE confidence='probable') probable_count,count(*) FILTER(WHERE confidence='unattributed') unattributed_count,min(agent_id) minimum_agent_id,max(agent_id) maximum_agent_id FROM zasp_runtime_session_events GROUP BY organization_id,workspace_id,environment_id,COALESCE(session_id,'unattributed')) SELECT NOT EXISTS((SELECT * FROM actual EXCEPT SELECT * FROM zasp_runtime_session_summaries) UNION ALL (SELECT * FROM zasp_runtime_session_summaries EXCEPT SELECT * FROM actual))`).Scan(&equal)
		if err != nil || !equal {
			t.Fatalf("summary differs from committed source events: equal=%v err=%v", equal, err)
		}
	}
	for _, mode := range []string{"insert_insert", "insert_delete", "delete_insert"} {
		t.Run(mode, func(t *testing.T) {
			connection, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close(context.Background())
			if mode != "insert_insert" {
				if _, err := admin.Exec(ctx, insert, second); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			firstSQL, firstID, secondSQL, secondID := insert, first, insert, second
			if mode == "insert_delete" {
				secondSQL = `DELETE FROM zasp_runtime_session_events WHERE event_id=$1`
			}
			if mode == "delete_insert" {
				firstSQL, firstID, secondID = `DELETE FROM zasp_runtime_session_events WHERE event_id=$1`, second, first
			}
			if _, err := tx.Exec(ctx, firstSQL, firstID); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { _, err := connection.Exec(ctx, secondSQL, secondID); finished <- err }()
			// Observe a real lock wait, rather than relying on scheduler timing.
			deadline := time.Now().Add(5 * time.Second)
			for {
				var blocked bool
				if err := tx.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, connection.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case err := <-finished:
					t.Fatalf("concurrent writer did not serialize: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("concurrent writer never reached summary lock")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			assertSummary(t)
			if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_session_events WHERE event_id IN($1,$2)`, first, second); err != nil {
				t.Fatal(err)
			}
			assertSummary(t)
		})
	}
	t.Run("immutable_update_and_last_event_delete", func(t *testing.T) {
		_, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_events SET title='changed' WHERE session_id IS NOT NULL`)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "22023" {
			t.Fatalf("immutable update error=%v", err)
		}
		assertSummary(t)
		if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_session_events WHERE session_id IS NULL`); err != nil {
			t.Fatal(err)
		}
		assertSummary(t)
	})
}
