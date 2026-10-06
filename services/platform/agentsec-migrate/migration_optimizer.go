package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var errMigrationOptimizerConfiguration = errors.New("migration optimizer configuration rejected")

type migrationOptimizerConnection interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Catalog readiness is short-lived and statement-heavy. Disable JIT on the
// dedicated CLI connection and verify its effective setting before any write.
// This neither changes the server default nor any stored SQL/security frame.
func configureMigrationOptimizer(ctx context.Context, connection migrationOptimizerConnection) error {
	if ctx == nil || ctx.Err() != nil || connection == nil {
		return errMigrationOptimizerConfiguration
	}
	if _, err := connection.Exec(ctx, `SET jit=off`); err != nil {
		return errMigrationOptimizerConfiguration
	}
	var mode string
	if err := connection.QueryRow(ctx, `SHOW jit`).Scan(&mode); err != nil || mode != "off" {
		return errMigrationOptimizerConfiguration
	}
	return nil
}
