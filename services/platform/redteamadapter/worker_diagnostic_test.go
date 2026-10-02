package redteamadapter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func p7DiagnosticError(err error) string {
	if err == nil {
		return "none"
	}
	for _, item := range []struct {
		err  error
		name string
	}{{context.DeadlineExceeded, "deadline"}, {context.Canceled, "cancelled"}, {authorization.ErrDenied, "denied"}, {authorization.ErrInvalid, "invalid"}, {authorization.ErrPending, "pending"}, {authorization.ErrConflict, "conflict"}, {authorization.ErrUnavailable, "unavailable"}} {
		if errors.Is(err, item.err) {
			return item.name
		}
	}
	var native *pgconn.PgError
	if errors.As(err, &native) {
		return "sqlstate-" + native.Code
	}
	return "other"
}

type p7AdapterQueryTrace struct{ t *testing.T }
type p7TraceKey struct{}
type p7TraceValue struct {
	start time.Time
	label string
}

func (trace p7AdapterQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	label := "other"
	for _, name := range []string{"adapter74_source", "adapter_revision", "adapter_key_ready", "key_ready", "zasp_temporal74.invocation", "set_config"} {
		if strings.Contains(data.SQL, name) {
			label = name
			break
		}
	}
	if data.SQL == "begin isolation level read committed" || data.SQL == "commit" || data.SQL == "rollback" {
		label = data.SQL
	}
	return context.WithValue(ctx, p7TraceKey{}, p7TraceValue{time.Now(), label})
}
func (trace p7AdapterQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	value, ok := ctx.Value(p7TraceKey{}).(p7TraceValue)
	if ok {
		trace.t.Log("database", value.label, "elapsed", time.Since(value.start), "error", p7DiagnosticError(data.Err), "context", p7DiagnosticError(ctx.Err()))
	}
}
