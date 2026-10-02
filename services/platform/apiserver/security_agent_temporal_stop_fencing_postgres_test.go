package apiserver

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

func TestTemporalWorkflowStopSendFencingPostgres(t *testing.T) {
	for _, sendFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop_wins", true: "started_stays_unknown"}[sendFirst], func(t *testing.T) {
			runTemporalExecutorPlanningFixture(t, nil, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string, selection map[string]any) {
				if err := precisionMigrationRunner(t, owner).UpProductionTemporalWorkflow(ctx); err != nil {
					t.Fatal(err)
				}
				cfg := owner.Config().Copy()
				cfg.User = "temporal_compensation_test_login"
				comp, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer comp.Close(ctx)
				identity := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2}
				prepare := map[string]any{}
				for k, v := range identity {
					prepare[k] = v
				}
				prepare["operation"], prepare["payload"] = "prepare", map[string]any{"pricing": selection, "input_version": "p3c-owned-input-version"}
				raw, _ := json.Marshal(prepare)
				var result []byte
				if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, raw).Scan(&result); err != nil {
					t.Fatal(err)
				}
				prepare["operation"], prepare["payload"] = "start", map[string]any{}
				start, _ := json.Marshal(prepare)
				var digest string
				if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start'`, run).Scan(&digest); err != nil {
					t.Fatal(err)
				}
				identity["input_digest"], identity["reason"] = digest, "workflow_cancelled"
				stop, _ := json.Marshal(identity)
				if sendFirst {
					if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, start).Scan(&result); err != nil {
						t.Fatal(err)
					}
					if err := comp.QueryRow(ctx, `SELECT zasp_temporal69.stop($1::jsonb)`, stop).Scan(&result); err != nil {
						t.Fatal(err)
					}
				} else {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(context.Background())
					if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
						t.Fatal(err)
					}
					raceCtx, cancelRace := context.WithCancel(ctx)
					defer cancelRace()
					stopped := make(chan error, 1)
					go func() {
						var v []byte
						stopped <- comp.QueryRow(raceCtx, `SELECT zasp_temporal69.stop($1::jsonb)`, stop).Scan(&v)
					}()
					waitLock := func(pid uint32) error {
						bounded, done := context.WithTimeout(ctx, 5*time.Second)
						defer done()
						ticker := time.NewTicker(10 * time.Millisecond)
						defer ticker.Stop()
						for {
							var waiting bool
							if err := owner.QueryRow(bounded, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
								return err
							}
							if waiting {
								return nil
							}
							select {
							case <-bounded.Done():
								return bounded.Err()
							case <-ticker.C:
							}
						}
					}
					if err := waitLock(comp.PgConn().PID()); err != nil {
						cancelRace()
						tx.Rollback(context.Background())
						<-stopped
						t.Fatal("stop lock barrier", err)
					}
					sent := make(chan error, 1)
					go func() {
						var v []byte
						sent <- executor.QueryRow(raceCtx, `SELECT zasp_temporal68.plan($1::jsonb)`, start).Scan(&v)
					}()
					if err := waitLock(executor.PgConn().PID()); err != nil {
						cancelRace()
						tx.Rollback(context.Background())
						<-stopped
						<-sent
						t.Fatal("send lock barrier", err)
					}
					if err := tx.Commit(ctx); err != nil {
						cancelRace()
						<-stopped
						<-sent
						t.Fatal(err)
					}
					if err := <-stopped; err != nil {
						t.Fatal("serialized stop", err)
					}
					if err := <-sent; err == nil {
						t.Fatal("send passed committed stop")
					}
				}
				if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, start).Scan(&result); err == nil {
					t.Fatal("stopped effect resent")
				}
				var honest bool
				if err := owner.QueryRow(ctx, `SELECT j.state='needs_human' AND j.raw_result IS NULL AND p.settled_at IS NULL AND (p.released_at IS NULL)=$2 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1) AND (SELECT count(*) FROM zasp_temporal69.stops WHERE run_id=$1)=1 FROM zasp_temporal68.planning_jobs j JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, run, sendFirst).Scan(&honest); err != nil || !honest {
					t.Fatal("stop fabricated usage or admission", honest, err)
				}
			})
		})
	}
}
