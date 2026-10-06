package main

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
)

type optimizerPrivateFailure struct{}

func (optimizerPrivateFailure) Error() string { panic("private cause must never be formatted") }

type optimizerObservedRow struct {
	mode    string
	failure error
}

func (r optimizerObservedRow) Scan(dst ...any) error {
	if r.failure != nil {
		return r.failure
	}
	*(dst[0].(*string)) = r.mode
	return nil
}

type optimizerObservedConnection struct {
	failure           error
	row               optimizerObservedRow
	executed, queried int
}

func (c *optimizerObservedConnection) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	c.executed++
	return pgconn.CommandTag{}, c.failure
}
func (c *optimizerObservedConnection) QueryRow(context.Context, string, ...any) pgx.Row {
	c.queried++
	return c.row
}
func TestMigrationOptimizerRefusesUnverifiedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		execFailure, rowFailure error
		mode                    string
		queries                 int
	}{
		{"setting failure", optimizerPrivateFailure{}, nil, "off", 0},
		{"observation failure", nil, optimizerPrivateFailure{}, "", 1},
		{"still enabled", nil, nil, "on", 1},
		{"empty observation", nil, nil, "", 1},
		{"unexpected observation", nil, nil, "OFF", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &optimizerObservedConnection{failure: tc.execFailure, row: optimizerObservedRow{mode: tc.mode, failure: tc.rowFailure}}
			if configureMigrationOptimizer(context.Background(), c) != errMigrationOptimizerConfiguration {
				t.Fatal("unverified mode was admitted")
			}
			if c.executed != 1 || c.queried != tc.queries {
				t.Fatal("configuration refusal did not stop at its failing stage")
			}
		})
	}
}
