package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Exercise the granted metadata entries, not a migration-owner call to context.
// While their org wait is observed, neither the parent nor device source rows
// nor the native budget advisory may already be held by that session.
func assertWorkerRuntimeMetadataLockOrder(t *testing.T, ctx context.Context, owner *pgx.Conn, run string, request json.RawMessage) {
	t.Helper()
	var reference json.RawMessage
	var organization string
	if err := owner.QueryRow(ctx, `SELECT organization_id,jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&organization, &reference); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		name, statement string
		request         json.RawMessage
	}{
		{"prepare", `SELECT zasp_authorization80_worker.prepare_test74($1::jsonb)`, reference},
		{"source", `SELECT zasp_authorization80_worker.planning74_source('load',$1::jsonb)`, request},
	} {
		t.Run("metadata organization lock/"+entry.name, func(t *testing.T) {
			call, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			cfg := owner.Config().Copy()
			cfg.User = "worker_test_executor"
			executor, err := pgx.ConnectConfig(call, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer executor.Close(context.Background())
			lock, err := owner.Begin(call)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback(context.Background())
			var ignored string
			if err := lock.QueryRow(call, `SELECT organization_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, organization).Scan(&ignored); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				tx, err := executor.BeginTx(call, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					done <- err
					return
				}
				_, err = tx.Exec(call, entry.statement, entry.request)
				if rollbackErr := tx.Rollback(context.Background()); err == nil {
					err = rollbackErr
				}
				done <- err
			}()
			joined := false
			defer func() {
				cancel()
				_ = lock.Rollback(context.Background())
				if !joined {
					<-done
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			var blocked bool
			for !blocked && time.Now().Before(deadline) {
				select {
				case err := <-done:
					joined = true
					t.Fatal("metadata entry crossed organization holder", err)
				default:
				}
				if err := lock.QueryRow(call, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, owner.PgConn().PID(), executor.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if !blocked {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if !blocked {
				t.Fatal("metadata entry did not reach real organization wait")
			}
			var free bool
			if err := lock.QueryRow(call, `SELECT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, organization).Scan(&free); err != nil || !free {
				t.Fatal("metadata held budget before organization", err)
			}
			if err := lock.QueryRow(call, `SELECT run_id FROM public.zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE NOWAIT`, run).Scan(&ignored); err != nil {
				t.Fatal("metadata held parent before organization", err)
			}
			if _, err := lock.Exec(call, `SELECT id FROM public.zasp_gateway_devices WHERE organization_id=$1 FOR UPDATE NOWAIT`, organization); err != nil {
				t.Fatal("metadata held device before organization", err)
			}
			if _, err := lock.Exec(call, `SELECT id FROM public.zasp_gateway_credentials WHERE organization_id=$1 FOR UPDATE NOWAIT`, organization); err != nil {
				t.Fatal("metadata held credential before organization", err)
			}
			if err := lock.Rollback(call); err != nil {
				t.Fatal(err)
			}
			err = <-done
			joined = true
			if err != nil {
				t.Fatal("metadata read after organization release", err)
			}
		})
		if t.Failed() {
			return
		}
	}
}
