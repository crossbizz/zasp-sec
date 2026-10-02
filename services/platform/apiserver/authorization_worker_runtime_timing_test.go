package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestWorkerRuntimeTimingOverlayPresent(t *testing.T) {
	t.Log("runtime timing overlay compiled")
}

// Fixed labels and timing only. Never print statements, request arguments,
// source metadata, proof envelopes, credentials, or native error text.
type workerRuntimeSQLTiming struct{ t *testing.T }
type workerRuntimeTimingKey struct{}
type workerRuntimeTimingStart struct {
	label string
	at    time.Time
}

func (d workerRuntimeSQLTiming) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	label := "other"
	for _, entry := range []struct{ needle, label string }{
		{"planning74_source(", "source"},
		{".revision(", "revision"},
		{".key_ready(", "key-ready"},
		{"prepare_test74(", "prepare"},
		{"zasp_temporal74.plan(", "native-plan"},
	} {
		if strings.Contains(data.SQL, entry.needle) {
			label = entry.label
			break
		}
	}
	if data.SQL == "begin isolation level read committed" || data.SQL == "begin" || data.SQL == "commit" || data.SQL == "rollback" {
		label = "transaction"
	}
	return context.WithValue(ctx, workerRuntimeTimingKey{}, workerRuntimeTimingStart{label, time.Now()})
}

func (d workerRuntimeSQLTiming) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	start, ok := ctx.Value(workerRuntimeTimingKey{}).(workerRuntimeTimingStart)
	if !ok {
		return
	}
	code := "none"
	var native *pgconn.PgError
	if errors.As(data.Err, &native) {
		code = native.Code
	} else if data.Err != nil {
		code = "non-postgres"
	}
	d.t.Logf("runtime planning SQL phase=%s elapsed=%s code=%s error_type=%T deadline=%t", start.label, time.Since(start.at).Round(time.Millisecond), code, data.Err, errors.Is(ctx.Err(), context.DeadlineExceeded))
}
