package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type recoveryContentionTraceTag struct {
	phase  int
	caller int
}

type recoveryContentionTraceTagKey struct{}
type recoveryContentionTraceQueryKey struct{}

type recoveryContentionTraceQuery struct {
	tag       recoveryContentionTraceTag
	operation string
	ordinal   int
	started   time.Time
}

type recoveryContentionTraceSlot struct {
	operation, errorClass, sqlstate, elapsed, result string
	ordinal                                          int
	failed                                           bool
}

type recoveryContentionQueryTrace struct {
	mu             sync.Mutex
	slots          [2][3]recoveryContentionTraceSlot
	queryCount     [2][3]int
	sourceState    [2][3]int
	completedState [2][3]int
}

func newRecoveryContentionQueryTrace() *recoveryContentionQueryTrace {
	return &recoveryContentionQueryTrace{}
}

func recoveryContentionPhase(phase string) (int, bool) {
	switch phase {
	case "pending":
		return 0, true
	case "settle":
		return 1, true
	default:
		return 0, false
	}
}

func recoveryContentionCaller(caller string) (int, bool) {
	switch caller {
	case "cleanup":
		return 0, true
	case "step":
		return 1, true
	case "finish":
		return 2, true
	default:
		return 0, false
	}
}

func recoveryContentionDefaultSlot() recoveryContentionTraceSlot {
	return recoveryContentionTraceSlot{operation: "other", errorClass: "none", sqlstate: "none", elapsed: "lt1s", result: "other"}
}

func (trace *recoveryContentionQueryTrace) reset(phase string) {
	p, ok := recoveryContentionPhase(phase)
	if !ok {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	for caller := range trace.slots[p] {
		trace.slots[p][caller] = recoveryContentionDefaultSlot()
		trace.queryCount[p][caller] = 0
		trace.sourceState[p][caller] = 0
		trace.completedState[p][caller] = 0
	}
}

func (trace *recoveryContentionQueryTrace) caller(ctx context.Context, phase, caller string, call func(context.Context) error) error {
	p, phaseOK := recoveryContentionPhase(phase)
	c, callerOK := recoveryContentionCaller(caller)
	if !phaseOK || !callerOK {
		return call(ctx)
	}
	err := call(context.WithValue(ctx, recoveryContentionTraceTagKey{}, recoveryContentionTraceTag{phase: p, caller: c}))
	trace.mu.Lock()
	trace.slots[p][c].result = recoveryContentionResult(err)
	trace.mu.Unlock()
	return err
}

func (trace *recoveryContentionQueryTrace) lines(phase string) []string {
	p, ok := recoveryContentionPhase(phase)
	if !ok {
		return nil
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	callers := [...]string{"cleanup", "step", "finish"}
	lines := make([]string, 0, len(callers))
	for caller, name := range callers {
		slot := trace.slots[p][caller]
		lines = append(lines, fmt.Sprintf("recovery-trace phase=%s caller=%s operation=%s error=%s sqlstate=%s ordinal=%s source_state=%s state_completed=%s elapsed=%s result=%s", phase, name, slot.operation, slot.errorClass, slot.sqlstate, recoveryContentionCount(slot.ordinal), recoveryContentionCount(trace.sourceState[p][caller]), recoveryContentionCount(trace.completedState[p][caller]), slot.elapsed, slot.result))
	}
	return lines
}

func (trace *recoveryContentionQueryTrace) log(t *testing.T, phase string) {
	for _, line := range trace.lines(phase) {
		t.Log(line)
	}
}

type recoveryContentionTracer struct{ trace *recoveryContentionQueryTrace }

func (trace recoveryContentionTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	tag, ok := ctx.Value(recoveryContentionTraceTagKey{}).(recoveryContentionTraceTag)
	if !ok {
		return ctx
	}
	trace.trace.mu.Lock()
	trace.trace.queryCount[tag.phase][tag.caller]++
	ordinal := trace.trace.queryCount[tag.phase][tag.caller]
	if recoveryContentionOperation(data.SQL, data.Args) == "source-state" {
		trace.trace.sourceState[tag.phase][tag.caller]++
	}
	trace.trace.mu.Unlock()
	return context.WithValue(ctx, recoveryContentionTraceQueryKey{}, recoveryContentionTraceQuery{tag: tag, operation: recoveryContentionOperation(data.SQL, data.Args), ordinal: ordinal, started: time.Now()})
}

func (trace recoveryContentionTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	query, ok := ctx.Value(recoveryContentionTraceQueryKey{}).(recoveryContentionTraceQuery)
	if !ok {
		return
	}
	errorClass, sqlstate := recoveryContentionQueryError(ctx, data.Err)
	observation := recoveryContentionTraceSlot{operation: query.operation, errorClass: errorClass, sqlstate: sqlstate, ordinal: query.ordinal, elapsed: recoveryContentionElapsed(time.Since(query.started))}
	trace.trace.mu.Lock()
	defer trace.trace.mu.Unlock()
	if query.operation == "state" && errorClass == "none" {
		trace.trace.completedState[query.tag.phase][query.tag.caller]++
	}
	current := &trace.trace.slots[query.tag.phase][query.tag.caller]
	if current.failed {
		return
	}
	result := current.result
	*current = observation
	current.result = result
	current.failed = errorClass != "none"
}

func recoveryContentionCount(count int) string {
	if count < 0 || count > 8 {
		return "many"
	}
	return strconv.Itoa(count)
}

func recoveryContentionPGXTracer(existing pgx.QueryTracer, trace *recoveryContentionQueryTrace) pgx.QueryTracer {
	current := recoveryContentionTracer{trace: trace}
	if existing != nil {
		return multitracer.New(existing, current)
	}
	return current
}

func recoveryContentionOperation(sql string, args []any) string {
	switch sql {
	case `SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb)`:
		if len(args) > 0 {
			switch args[0] {
			case "inspect":
				return "source-inspect"
			case "recovery_status":
				return "source-status"
			case "cleanup":
				return "source-cleanup"
			}
		}
	case `SELECT zasp_authorization80_worker.test74_effect_source($1,$2::jsonb)`:
		if len(args) > 0 && args[0] == "state" {
			return "source-state"
		}
	case `SELECT set_config('zasp.worker_proof',$1,true)`:
		return "proof"
	case `SELECT zasp_temporal74.inspect($1::jsonb)`:
		return "inspect"
	case `SELECT zasp_temporal74.test_state($1::jsonb)`:
		return "state"
	case `SELECT zasp_authorization80_worker.test74_recovery_status($1::jsonb)`:
		return "status"
	case `SELECT zasp_temporal74.cleanup($1::jsonb)`:
		return "cleanup"
	case singleRecoveryLoadSQL:
		return "load"
	case singleRecoveryObserveSQL:
		return "observe"
	case singleRecoveryFinishSQL:
		return "finish"
	}
	return "other"
}

func recoveryContentionQueryError(ctx context.Context, err error) (string, string) {
	class := "none"
	if err != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		class = "deadline"
	} else if err != nil && (errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled)) {
		class = "canceled"
	} else if err != nil {
		class = "query"
	}
	state := "none"
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		switch postgres.Code {
		case "22023", "25001", "23514", "40001", "40P01", "42501", "55P03", "57014":
			state = postgres.Code
		default:
			state = "other"
		}
	}
	return class, state
}

func recoveryContentionElapsed(elapsed time.Duration) string {
	switch {
	case elapsed < time.Second:
		return "lt1s"
	case elapsed < 5*time.Second:
		return "lt5s"
	case elapsed < 10*time.Second:
		return "lt10s"
	default:
		return "ge10s"
	}
}

func recoveryContentionResult(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, orchestration.ErrCleanupPending):
		return "pending"
	case errors.Is(err, authorization.ErrConflict):
		return "auth-conflict"
	case errors.Is(err, authorization.ErrUnavailable):
		return "auth-unavailable"
	case errors.Is(err, authorization.ErrDenied):
		return "auth-denied"
	case errors.Is(err, authorization.ErrInvalid):
		return "auth-invalid"
	case errors.Is(err, errWorkerExecution):
		return "worker"
	case errors.Is(err, orchestration.ErrConflict):
		return "conflict"
	case errors.Is(err, orchestration.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, orchestration.ErrInvalid):
		return "invalid"
	default:
		return "other"
	}
}
