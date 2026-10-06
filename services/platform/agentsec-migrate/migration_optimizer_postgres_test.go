package main

import (
	"context"
	"testing"
	"time"
)

func TestMigrationOptimizerDedicatedNativeSession(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection := connectMigrationPostgres(t, ctx, dsn)
	defer connection.Close(context.Background())
	if _, err := connection.Exec(ctx, `SET jit=on`); err != nil {
		t.Fatal("owned optimizer positive setup failed")
	}
	if err := configureMigrationOptimizer(ctx, connection); err != nil {
		t.Fatal("dedicated optimizer setup failed")
	}
	check := func() {
		t.Helper()
		var mode string
		if err := connection.QueryRow(ctx, `SHOW jit`).Scan(&mode); err != nil || mode != "off" {
			t.Fatal("dedicated connection retained JIT", mode)
		}
	}
	check()
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal("owned transaction unavailable")
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal("owned transaction rollback failed")
	}
	check()
	tx, err = connection.Begin(ctx)
	if err != nil {
		t.Fatal("owned transaction unavailable")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("owned transaction commit failed")
	}
	check()
	// A separate session on the unchanged server must retain its configured mode.
	other := connectMigrationPostgres(t, ctx, dsn)
	defer other.Close(context.Background())
	var mode string
	if err = other.QueryRow(ctx, `SHOW jit`).Scan(&mode); err != nil || mode != "on" {
		t.Fatal("optimizer setup changed another session", mode)
	}
}
