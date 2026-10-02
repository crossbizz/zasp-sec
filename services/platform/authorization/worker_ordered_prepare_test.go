package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

// Scope capture must never turn a captured cleanup decision or caller-selected
// operation into fresh forward authority.
func TestOrderedPreparationClosedOperations(t *testing.T) {
	for _, tc := range []struct {
		operation WorkerOperation
		statement string
		policy    bool
	}{
		{"ordered68.effect.reserve", `SELECT zasp_authorization80_worker.prepare_ordered68_effect($1::jsonb)`, false},
		{"ordered68.application.source", `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, true},
		{"ordered68.delivery.apply.prepare", `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, true},
		{"ordered68.delivery.apply.store", `SELECT zasp_authorization80_worker.prepare_ordered68_policy($1,$2::jsonb)`, true},
	} {
		statement, policy := orderedPreparationStatement(tc.operation)
		if statement != tc.statement || policy != tc.policy {
			t.Fatal("required native capture absent or wrong", tc.operation)
		}
	}
	for _, op := range []WorkerOperation{"", "ordered68.effect.start", "ordered68.effect.read", "ordered68.cleanup.source", "ordered68.cleanup.renew", "ordered68.delivery.cleanup.store", "ordered68.delivery.cleanup.prepare", "ordered68.delivery.apply.read", "ordered68.delivery.apply.ack", "ordered68.application.complete", "SELECT arbitrary()"} {
		if statement, _ := orderedPreparationStatement(op); statement != "" {
			t.Fatal("unreviewed forward capture allowed", op)
		}
	}
}

func TestOrderedPreparationRejectsWrongAuthorityBeforeIO(t *testing.T) {
	forward, _ := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{63}, 32))
	compensation, _ := NewWorkerKey(CapturedCompensation, bytes.Repeat([]byte{64}, 32))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	// This zero pool panics if used. Refusals must precede database access.
	for _, tc := range []struct {
		key                *WorkerKey
		adapter, discovery bool
		ctx                context.Context
		op                 WorkerOperation
		raw                json.RawMessage
	}{
		{compensation, false, false, context.Background(), "ordered68.effect.reserve", json.RawMessage(`{}`)},
		{compensation, false, false, context.Background(), "ordered68.delivery.apply.prepare", json.RawMessage(`{}`)},
		{forward, true, false, context.Background(), "ordered68.effect.reserve", json.RawMessage(`{}`)},
		{forward, false, true, context.Background(), "ordered68.application.source", json.RawMessage(`{}`)},
		{forward, false, false, nil, "ordered68.effect.reserve", json.RawMessage(`{}`)},
		{forward, false, false, cancelled, "ordered68.application.source", json.RawMessage(`{}`)},
		{forward, false, false, cancelled, "ordered68.delivery.apply.prepare", json.RawMessage(`{}`)},
		{forward, false, false, context.Background(), "ordered68.cleanup.source", json.RawMessage(`{}`)},
		{forward, false, false, context.Background(), "ordered68.effect.reserve", json.RawMessage(`{`)},
		{forward, false, false, context.Background(), "ordered68.effect.reserve", append(bytes.Repeat([]byte(" "), 4096), []byte(`{}`)...)},
		{forward, false, false, context.Background(), "ordered68.application.source", append(bytes.Repeat([]byte(" "), 32768), []byte(`{}`)...)},
	} {
		executor := &WorkerExecutor{key: tc.key, pool: &pgxpool.Pool{}, adapter: tc.adapter, discovery: tc.discovery}
		if err := executor.PrepareOrdered68Operation(tc.ctx, tc.op, tc.raw); err != ErrInvalid {
			t.Fatal("invalid capture reached IO", err)
		}
	}
}

func TestOrderedPreparationRequiresPolicyDeadlineBeforeCapture(t *testing.T) {
	key, _ := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{63}, 32))
	for _, op := range []WorkerOperation{"ordered68.application.source", "ordered68.delivery.apply.prepare", "ordered68.delivery.apply.store"} {
		t.Run(string(op), func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("missing policy deadline reached database capture")
				}
			}()
			executor := &WorkerExecutor{key: key, pool: &pgxpool.Pool{}}
			if err := executor.PrepareOrdered68Operation(context.Background(), op, json.RawMessage(`{"organization_id":"pid_10000000-0000-4000-8000-000000000001"}`)); err != ErrInvalid {
				t.Fatal("missing policy deadline was not rejected", err)
			}
		})
	}
}
