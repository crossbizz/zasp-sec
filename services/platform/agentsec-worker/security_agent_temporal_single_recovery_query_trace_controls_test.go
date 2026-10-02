package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type recoveryTraceCountingTracer struct{ starts, ends int }

func (trace *recoveryTraceCountingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	trace.starts++
	return ctx
}

func (trace *recoveryTraceCountingTracer) TraceQueryEnd(_ context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	trace.ends++
}

func recoveryTraceQuery(t *testing.T, tracer pgx.QueryTracer, ctx context.Context, sql string, args []any, err error) {
	t.Helper()
	ctx = tracer.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: sql, Args: args})
	tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: err})
}

func TestSingleRecoveryContentionQueryTrace(t *testing.T) {
	t.Run("first query failure wins and callers remain separate", func(t *testing.T) {
		recorder := newRecoveryContentionQueryTrace()
		recorder.reset("pending")
		tracer := recoveryContentionPGXTracer(nil, recorder)
		secret := "postgres://private/body request-id-123"
		cleanup := recorder.caller(context.Background(), "pending", "cleanup", func(ctx context.Context) error {
			recoveryTraceQuery(t, tracer, ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb)`, []any{"inspect", secret}, nil)
			recoveryTraceQuery(t, tracer, ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb)`, []any{"recovery_status", secret}, &pgconn.PgError{Code: "40001", Message: secret})
			recoveryTraceQuery(t, tracer, ctx, `SELECT zasp_temporal74.cleanup($1::jsonb)`, []any{secret}, &pgconn.PgError{Code: "42501", Message: secret})
			return authorization.ErrConflict
		})
		step := recorder.caller(context.Background(), "pending", "step", func(ctx context.Context) error {
			recoveryTraceQuery(t, tracer, ctx, singleRecoveryLoadSQL, []any{secret}, nil)
			recoveryTraceQuery(t, tracer, ctx, `SELECT zasp_authorization80_worker.test74_effect_source($1,$2::jsonb)`, []any{"state", secret}, nil)
			return orchestration.ErrCleanupPending
		})
		finish := recorder.caller(context.Background(), "pending", "finish", func(ctx context.Context) error {
			recoveryTraceQuery(t, tracer, ctx, singleRecoveryFinishSQL, []any{secret}, nil)
			return nil
		})
		if cleanup != authorization.ErrConflict || step != orchestration.ErrCleanupPending || finish != nil {
			t.Fatal("caller result changed")
		}
		got := recorder.lines("pending")
		want := []string{
			"recovery-trace phase=pending caller=cleanup operation=source-status error=query sqlstate=40001 ordinal=2 source_state=0 state_completed=0 elapsed=lt1s result=auth-conflict",
			"recovery-trace phase=pending caller=step operation=source-state error=none sqlstate=none ordinal=2 source_state=1 state_completed=0 elapsed=lt1s result=pending",
			"recovery-trace phase=pending caller=finish operation=finish error=none sqlstate=none ordinal=1 source_state=0 state_completed=0 elapsed=lt1s result=nil",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") || strings.Contains(strings.Join(got, "\n"), secret) {
			t.Fatalf("bounded trace mismatch: %#v", got)
		}
	})

	t.Run("physical query ordinal and completed state statement are bounded", func(t *testing.T) {
		recorder := newRecoveryContentionQueryTrace()
		recorder.reset("settle")
		tracer := recoveryContentionPGXTracer(nil, recorder)
		_ = recorder.caller(context.Background(), "settle", "cleanup", func(ctx context.Context) error {
			for i := 0; i < 2; i++ {
				recoveryTraceQuery(t, tracer, ctx, `SELECT zasp_authorization80_worker.test74_effect_source($1,$2::jsonb)`, []any{"state", nil}, nil)
			}
			recoveryTraceQuery(t, tracer, ctx, `SELECT zasp_temporal74.test_state($1::jsonb)`, nil, nil)
			for i := 0; i < 6; i++ {
				recoveryTraceQuery(t, tracer, ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, nil, nil)
			}
			return context.DeadlineExceeded
		})
		got := strings.Join(recorder.lines("settle"), "\n")
		if !strings.Contains(got, "caller=cleanup operation=proof error=none sqlstate=none ordinal=many source_state=2 state_completed=1") {
			t.Fatalf("physical query counts missing: %s", got)
		}
		for value, want := range map[int]string{-1: "many", 0: "0", 8: "8", 9: "many"} {
			if got := recoveryContentionCount(value); got != want {
				t.Fatalf("count %d=%q want %q", value, got, want)
			}
		}
	})

	t.Run("closed operation elapsed and result classifiers", func(t *testing.T) {
		for _, test := range []struct {
			sql  string
			args []any
			want string
		}{
			{`SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb)`, []any{"inspect", nil}, "source-inspect"},
			{`SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb)`, []any{"cleanup", nil}, "source-cleanup"},
			{`SELECT set_config('zasp.worker_proof',$1,true)`, nil, "proof"},
			{`SELECT zasp_temporal74.inspect($1::jsonb)`, nil, "inspect"},
			{`SELECT zasp_temporal74.test_state($1::jsonb)`, nil, "state"},
			{`SELECT zasp_authorization80_worker.test74_recovery_status($1::jsonb)`, nil, "status"},
			{singleRecoveryObserveSQL, nil, "observe"},
			{"SELECT private_secret($1)", []any{"secret"}, "other"},
		} {
			if got := recoveryContentionOperation(test.sql, test.args); got != test.want {
				t.Fatalf("operation=%q, want %q", got, test.want)
			}
		}
		for _, test := range []struct {
			value time.Duration
			want  string
		}{{999 * time.Millisecond, "lt1s"}, {time.Second, "lt5s"}, {5 * time.Second, "lt10s"}, {10 * time.Second, "ge10s"}} {
			if got := recoveryContentionElapsed(test.value); got != test.want {
				t.Fatalf("elapsed=%q, want %q", got, test.want)
			}
		}
		for _, test := range []struct {
			err  error
			want string
		}{
			{nil, "nil"},
			{orchestration.ErrCleanupPending, "pending"},
			{authorization.ErrConflict, "auth-conflict"},
			{authorization.ErrUnavailable, "auth-unavailable"},
			{authorization.ErrDenied, "auth-denied"},
			{authorization.ErrInvalid, "auth-invalid"},
			{errWorkerExecution, "worker"},
			{orchestration.ErrConflict, "conflict"},
			{orchestration.ErrUnavailable, "unavailable"},
			{orchestration.ErrInvalid, "invalid"},
			{context.DeadlineExceeded, "deadline"},
			{context.Canceled, "canceled"},
			{errors.New("private body"), "other"},
		} {
			if got := recoveryContentionResult(test.err); got != test.want {
				t.Fatalf("result=%q, want %q", got, test.want)
			}
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if class, state := recoveryContentionQueryError(canceled, nil); class != "none" || state != "none" {
			t.Fatalf("successful canceled-context query classified %q/%q", class, state)
		}
		if class, state := recoveryContentionQueryError(canceled, context.DeadlineExceeded); class != "deadline" || state != "none" {
			t.Fatalf("deadline query classified %q/%q", class, state)
		}
	})

	t.Run("existing tracer is preserved", func(t *testing.T) {
		recorder := newRecoveryContentionQueryTrace()
		recorder.reset("settle")
		existing := &recoveryTraceCountingTracer{}
		tracer := recoveryContentionPGXTracer(existing, recorder)
		_ = recorder.caller(context.Background(), "settle", "finish", func(ctx context.Context) error {
			recoveryTraceQuery(t, tracer, ctx, singleRecoveryFinishSQL, nil, nil)
			return nil
		})
		if existing.starts != 1 || existing.ends != 1 {
			t.Fatalf("existing tracer calls=%d/%d", existing.starts, existing.ends)
		}
	})

	t.Run("untrusted caller phase SQLSTATE and text remain closed", func(t *testing.T) {
		recorder := newRecoveryContentionQueryTrace()
		recorder.reset("pending")
		tracer := recoveryContentionPGXTracer(nil, recorder)
		secret := "private SQL body postgres" + "://user:pass@host/id"
		_ = recorder.caller(context.Background(), "bad-phase", "attacker", func(ctx context.Context) error {
			recoveryTraceQuery(t, tracer, ctx, secret, []any{secret}, &pgconn.PgError{Code: "ZZ999", Message: secret})
			return errors.New(secret)
		})
		got := strings.Join(recorder.lines("pending"), "\n")
		if strings.Contains(got, secret) || strings.Contains(got, "ZZ999") || strings.Count(got, "recovery-trace ") != 3 {
			t.Fatalf("untrusted trace escaped: %q", got)
		}
	})
}
