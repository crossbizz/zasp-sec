package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOrderedTestTraceLabels(t *testing.T) {
	for _, tt := range []struct {
		sql  string
		args []any
		want string
	}{
		{`SELECT zasp_authorization80_worker.ordered68_dispatch_readback($1::jsonb)`, []any{json.RawMessage(`{"operation":"dispatch","secret":"never-log"}`)}, "readback/linked.dispatch"},
		{`SELECT zasp_authorization80_worker.ordered68_test_source($1,$2::jsonb)`, []any{"linked.dispatch", json.RawMessage(`{"secret":"never-log"}`)}, "source/linked.dispatch"},
		{`SELECT zasp_temporal68.linked($1::jsonb)`, []any{json.RawMessage(`{"operation":"input","secret":"never-log"}`)}, "execute/linked.input"},
		{`SELECT zasp_authorization80_worker.ordered68_test_source($1,$2::jsonb)`, []any{"unlisted-secret"}, ""},
		{`SELECT zasp_temporal68.linked($1::jsonb)`, []any{json.RawMessage(`{"operation":"secret"}`)}, ""},
		{"SELECT secret", nil, ""},
	} {
		if got := orderedTestTraceLabel(tt.sql, tt.args); got != tt.want {
			t.Fatalf("fixed trace label got %q want %q", got, tt.want)
		}
	}
}

func orderedTestTraceLabel(sql string, args []any) string {
	phase := func(allowed ...string) string {
		if len(args) == 0 {
			return ""
		}
		value, _ := args[0].(string)
		for _, want := range allowed {
			if value == want {
				return want
			}
		}
		return ""
	}
	operation := func(allowed ...string) string {
		if len(args) != 1 {
			return ""
		}
		var raw []byte
		switch v := args[0].(type) {
		case json.RawMessage:
			raw = v
		case []byte:
			raw = v
		default:
			return ""
		}
		var q struct {
			Operation string `json:"operation"`
		}
		if json.Unmarshal(raw, &q) != nil {
			return ""
		}
		for _, want := range allowed {
			if q.Operation == want {
				return want
			}
		}
		return ""
	}
	switch sql {
	case `SELECT zasp_authorization80_worker.ordered68_dispatch_readback($1::jsonb)`:
		if operation("dispatch") != "" {
			return "readback/linked.dispatch"
		}
	case `SELECT zasp_authorization80_worker.ordered68_test_source($1,$2::jsonb)`:
		if p := phase("progress", "test.state", "linked.read", "linked.input", "linked.dispatch", "adapter.resolve", "adapter.start", "adapter.complete", "test.settle", "test.replay", "test.stop"); p != "" {
			return "source/" + p
		}
	case `SELECT zasp_authorization80_worker.ordered68_effect_source($1,$2::jsonb)`:
		if p := phase("effect.reserve", "effect.start", "effect.read", "effect.unknown"); p != "" {
			return "source/" + p
		}
	case `SELECT zasp_temporal68.linked($1::jsonb)`:
		if p := operation("read", "input", "dispatch"); p != "" {
			return "execute/linked." + p
		}
	case `SELECT zasp_temporal68.effect($1::jsonb)`:
		if p := operation("reserve", "start", "read", "unknown"); p != "" {
			return "execute/effect." + p
		}
	case `SELECT zasp_temporal68.test_settle($1::jsonb)`:
		return "execute/test.settle"
	case `SELECT zasp_temporal68.test_stop($1::jsonb)`:
		return "execute/test.stop"
	case `SELECT zasp_authorization80_worker.ordered68_test_state($1::jsonb)`:
		return "execute/test.state"
	case `SELECT zasp_authorization80_worker.prepare_ordered68_effect($1::jsonb)`:
		return "prepare/effect.reserve"
	case `SELECT zasp_authorization80_worker.key_ready($1,$2)`:
		return "ready/worker"
	case `SELECT zasp_authorization80_worker.revision($1)`:
		return "authorize/revision"
	}
	return ""
}

type orderedTestTraceKey struct{}
type orderedTestTraceStart struct {
	label string
	began time.Time
}
type orderedTestNativeTrace struct{ t *testing.T }

func (x orderedTestNativeTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if label := orderedTestTraceLabel(data.SQL, data.Args); label != "" {
		return context.WithValue(ctx, orderedTestTraceKey{}, orderedTestTraceStart{label, time.Now()})
	}
	return ctx
}
func (x orderedTestNativeTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	start, ok := ctx.Value(orderedTestTraceKey{}).(orderedTestTraceStart)
	if !ok {
		return
	}
	x.t.Log("ordered Test native", start.label, "elapsed_ms", time.Since(start.began).Milliseconds(), "class", orderedTestNativeClass(data.Err))
}
func orderedTestNativeClass(err error) string {
	if err == nil {
		return "ok"
	}
	var native *pgconn.PgError
	if errors.As(err, &native) {
		return "sqlstate-" + native.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "other"
}

func orderedTestFailureCheckpoints(t *testing.T, ctx context.Context, owner *pgxpool.Pool, run string, engineCalls, artifactWrites int) {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var effects, reserved, started, stopped, inputs, everStarted, invocations, completed, settlements int
	err := owner.QueryRow(bounded, `SELECT
 (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test'),
 (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test' AND state='reserved'),
 (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test' AND state='started'),
 (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test' AND state='stopped'),
 (SELECT count(*) FROM zasp_temporal68.test_inputs WHERE run_id=$1),
 (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test' AND started_at IS NOT NULL),
 (SELECT count(*) FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1 AND j.state='started'),
 (SELECT count(*) FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1 AND j.state='completed'),
 (SELECT count(*) FROM zasp_temporal68.test_settlements WHERE run_id=$1)`, run).Scan(&effects, &reserved, &started, &stopped, &inputs, &everStarted, &invocations, &completed, &settlements)
	t.Log("ordered Test failure checkpoints", "class", orderedTestNativeClass(err), "effects", effects, "reserved", reserved, "started", started, "stopped", stopped, "inputs", inputs, "effects_ever_started", everStarted, "invocations_started", invocations, "invocations_completed", completed, "settlements", settlements, "engine_calls", engineCalls, "artifact_writes", artifactWrites)
}
