package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func orderedCapacityClass(err error) string {
	if class := orderedTestNativeClass(err); class != "other" {
		return class
	}
	for _, c := range []struct {
		err  error
		name string
	}{{authorization.ErrPending, "authorization-pending"}, {authorization.ErrDenied, "authorization-denied"}, {authorization.ErrConflict, "authorization-conflict"}, {authorization.ErrUnavailable, "authorization-unavailable"}, {authorization.ErrInvalid, "authorization-invalid"}} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "other"
}

type orderedCapacityTrace struct {
	t    *testing.T
	next pgx.QueryTracer
	mu   sync.Mutex
	last string
}
type orderedCapacityTraceKey struct{}
type orderedCapacityTraceCall struct {
	phase string
	began time.Time
}

func (p *orderedCapacityTrace) lastPhase() string { p.mu.Lock(); defer p.mu.Unlock(); return p.last }
func (p *orderedCapacityTrace) TraceQueryStart(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if p.next != nil {
		ctx = p.next.TraceQueryStart(ctx, c, q)
	}
	phase := orderedCapacityTraceLabel(q.SQL, q.Args)
	if phase == "" {
		return ctx
	}
	p.mu.Lock()
	p.last = phase
	p.mu.Unlock()
	return context.WithValue(ctx, orderedCapacityTraceKey{}, orderedCapacityTraceCall{phase, time.Now()})
}
func (p *orderedCapacityTrace) TraceQueryEnd(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryEndData) {
	if p.next != nil {
		p.next.TraceQueryEnd(ctx, c, q)
	}
	if call, ok := ctx.Value(orderedCapacityTraceKey{}).(orderedCapacityTraceCall); ok {
		p.t.Log("capacity native", call.phase, "elapsed_ms", time.Since(call.began).Milliseconds(), "class", orderedCapacityClass(q.Err))
	}
}

// All returned labels are fixed literals. Neither SQL, data, proof GUC nor
// unrecognized operation/error strings become diagnostic output.
func orderedCapacityTraceLabel(sql string, args []any) string {
	phase := ""
	switch sql {
	case `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`:
		phase = "prepare"
	case `SELECT zasp_authorization80_worker.ordered68_operation_source($1,$2::jsonb)`:
		phase = "source"
	case `SELECT zasp_authorization80_worker.ordered68_policy_source($1,$2::jsonb)`:
		phase = "source"
	case `SELECT zasp_authorization80_worker.ordered68_policy_begin($1,$2::jsonb,$3)`:
		phase = "sign-begin"
	case `SELECT zasp_authorization80_worker.ordered68_policy_store($1,$2::jsonb,$3,$4::bytea,$5::bytea,$6)`:
		phase = "sign-store"
	}
	if phase != "" && len(args) > 0 {
		if op, ok := args[0].(string); ok {
			switch op {
			case "ordered68.application.read", "ordered68.application.source", "ordered68.application.complete", "ordered68.delivery.apply.prepare", "ordered68.delivery.apply.store", "ordered68.delivery.apply.read", "ordered68.delivery.apply.ack":
				return phase + "/" + op
			}
		}
		return ""
	}
	native := ""
	switch sql {
	case `SELECT zasp_temporal68.application($1::jsonb)`:
		native = "application"
	case `SELECT zasp_temporal68.delivery($1::jsonb)`:
		native = "delivery"
	}
	if native != "" && len(args) == 1 {
		var raw []byte
		switch v := args[0].(type) {
		case []byte:
			raw = v
		case json.RawMessage:
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
		switch q.Operation {
		case "read", "prepare", "ack", "complete":
			return "execute/" + native + "." + q.Operation
		}
	}
	return ""
}

func TestOrderedCapacityTraceLabels(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{{authorization.ErrPending, "authorization-pending"}, {authorization.ErrDenied, "authorization-denied"}, {authorization.ErrConflict, "authorization-conflict"}, {authorization.ErrUnavailable, "authorization-unavailable"}, {authorization.ErrInvalid, "authorization-invalid"}, {context.DeadlineExceeded, "deadline"}, {context.Canceled, "cancelled"}, {nil, "ok"}} {
		if orderedCapacityClass(c.err) != c.want {
			t.Fatal("fixed capacity error class")
		}
	}
	for _, tc := range []struct {
		sql  string
		args []any
		want string
	}{
		{`SELECT zasp_authorization80_worker.ordered68_policy_store($1,$2::jsonb,$3,$4::bytea,$5::bytea,$6)`, []any{"ordered68.application.source", json.RawMessage(`{"secret":"must-not-log"}`)}, "sign-store/ordered68.application.source"},
		{`SELECT zasp_temporal68.delivery($1::jsonb)`, []any{json.RawMessage(`{"operation":"ack","secret":"must-not-log"}`)}, "execute/delivery.ack"},
		{`SELECT zasp_temporal68.delivery($1::jsonb)`, []any{json.RawMessage(`{"operation":"secret"}`)}, ""},
		{`SELECT zasp_authorization80_worker.ordered68_policy_source($1,$2::jsonb)`, []any{"secret"}, ""},
		{`SELECT set_config('zasp.worker_proof',$1,true)`, []any{"secret"}, ""},
	} {
		if got := orderedCapacityTraceLabel(tc.sql, tc.args); got != tc.want {
			t.Fatal("fixed capacity trace mismatch")
		}
	}
}
