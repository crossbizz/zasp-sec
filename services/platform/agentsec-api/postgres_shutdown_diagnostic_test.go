package main

import (
	"context"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func TestRuntimePostgresCancellationShutdownDiagnostic(t *testing.T) {
	dsn := os.Getenv("ZASP_POSTGRES_SHUTDOWN_DIAGNOSTIC_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL shutdown diagnostic only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, pool, err := openRuntimePostgres(ctx, dsn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	queryCtx, queryCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer queryCancel()
	if _, err = pool.Exec(queryCtx, "SELECT pg_sleep(10)"); err == nil {
		t.Fatal("expected cancelled query")
	}
	t.Logf("query cancelled; acquired=%d idle=%d", pool.Stat().AcquiredConns(), pool.Stat().IdleConns())
	done := make(chan error, 1)
	go func() { done <- db.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
		t.Fatal("database close did not join within two seconds after query cancellation")
	}
}
