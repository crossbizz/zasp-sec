package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestOrderedDispatchReadbackRejectsForeignDecision(t *testing.T) {
	type reader interface {
		ExecuteOrderedTestDispatchReadback(context.Context, WorkerDecision) (json.RawMessage, error)
	}
	key, err := NewWorkerKey(WorkerForward, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	// A present key/pool makes wrong-operation refusals exercise the selector.
	// The zero pool must never be used: each case fails before BeginTx.
	e := &WorkerExecutor{key: key, pool: &pgxpool.Pool{}}
	r, ok := any(e).(reader)
	if !ok {
		t.Fatal("fixed dispatch readback executor absent")
	}
	for _, op := range []WorkerOperation{"ordered68.linked.read", "ordered68.linked.input", "ordered68.test.stop", "test74.linked.dispatch", "ordered68.adapter.start", "ordered68.linked.dispatch"} {
		if _, err := r.ExecuteOrderedTestDispatchReadback(context.Background(), WorkerDecision{operation: op, request: json.RawMessage(`{}`), envelope: json.RawMessage(`{}`)}); !errors.Is(err, ErrInvalid) {
			t.Fatal(op, err)
		}
	}
}
