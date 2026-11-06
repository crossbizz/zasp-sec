package main

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are explicit test-only capabilities. QueryRow delegates to the same
// original recorder, preserving its SQL/arguments/counts/failure slots/events.
// No alternate production connection adapter is defined.
type principalRecorderTransaction struct{ recorder principalQueryer }

func (x *principalRecorderTransaction) QueryRow(c context.Context, s string, a ...any) pgx.Row {
	return x.recorder.QueryRow(c, s, a...)
}
func (x *principalRecorderTransaction) Exec(_ context.Context, s string, _ ...any) (pgconn.CommandTag, error) {
	if s != "SET LOCAL ROLE zasp_discovery_authority" {
		return pgconn.CommandTag{}, errors.New("unexpected recorder role command")
	}
	return pgconn.NewCommandTag("SET"), nil
}
func (x *principalRecorderTransaction) Commit(context.Context) error   { return nil }
func (x *principalRecorderTransaction) Rollback(context.Context) error { return nil }
func (q *releaseReadinessQueryer) beginPrincipalAuthorityTransaction(context.Context) (retentionOperatorTransaction, error) {
	if q == nil {
		return nil, errors.New("nil readiness recorder")
	}
	return &principalRecorderTransaction{recorder: q}, nil
}
func (q *innerDiagnosticQueryer) beginPrincipalAuthorityTransaction(context.Context) (retentionOperatorTransaction, error) {
	if q == nil {
		return nil, errors.New("nil diagnostic recorder")
	}
	return &principalRecorderTransaction{recorder: q}, nil
}
