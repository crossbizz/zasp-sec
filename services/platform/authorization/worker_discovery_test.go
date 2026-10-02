package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The zero pool deliberately cannot serve queries: every case must reject at
// the closed operation/mode boundary before touching database state.
func TestDiscoveryWorkerClosedModesAndPurposes(t *testing.T) {
	forward, _ := NewWorkerKey(WorkerForward, make([]byte, 32))
	captured, _ := NewWorkerKey(CapturedCompensation, make([]byte, 32))
	request := json.RawMessage(`{}`)
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		executor  WorkerExecutor
		operation WorkerOperation
	}{
		{"executor-to-discovery", WorkerExecutor{key: forward}, "discovery72.prepare_page"},
		{"adapter-to-discovery", WorkerExecutor{key: forward, adapter: true}, "discovery72.prepare_page"},
		{"discovery-to-finding", WorkerExecutor{key: forward, discovery: true}, FindingApply},
		{"discovery-to-adapter", WorkerExecutor{key: forward, discovery: true}, "test74.adapter.start"},
		{"forward-to-captured", WorkerExecutor{key: forward, discovery: true}, "discovery72.record_page"},
		{"captured-to-forward", WorkerExecutor{key: captured, discovery: true}, "discovery72.guard_page"},
		{"unknown", WorkerExecutor{key: forward, discovery: true}, "discovery72.provider_send"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.executor
			e.pool = &pgxpool.Pool{}
			if err := e.ReadyFor(ctx, tc.operation); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ReadyFor: %v", err)
			}
			if _, err := e.Authorize(ctx, tc.operation, request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Authorize: %v", err)
			}
			if _, err := e.Execute(ctx, WorkerDecision{operation: tc.operation, request: request, envelope: []byte(`{}`)}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Execute: %v", err)
			}
		})
	}
	e := &WorkerExecutor{key: forward, discovery: true, pool: &pgxpool.Pool{}}
	if err := e.PrepareFinding(ctx, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("PrepareFinding: %v", err)
	}
	if err := e.PrepareTest74(ctx, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("PrepareTest74: %v", err)
	}
}

func TestDiscoveryWorkerOperationsAndTaskIdentity(t *testing.T) {
	for _, phase := range []string{"prepare_page", "guard_page", "prepare_apply", "commit_apply", "record_page", "settle", "finish", "replay_page", "replay_apply"} {
		s, ok := workerOperation(WorkerOperation("discovery72." + phase))
		captured := phase == "record_page" || phase == "settle" || phase == "finish" || phase == "replay_page" || phase == "replay_apply"
		if !ok || !s.discovery || s.adapter || s.phase != phase || s.bindRequest || s.current == captured || (s.purpose == CapturedCompensation) != captured {
			t.Fatalf("operation %s is not closed to its discovery purpose: %+v", phase, s)
		}
	}
	for _, operation := range []WorkerOperation{"discovery72.", "discovery72.read", "discovery72.prepare_page.extra", "discovery72.adapter.start"} {
		if _, ok := workerOperation(operation); ok {
			t.Fatalf("accepted unknown %s", operation)
		}
	}
	var f workerFacts
	if err := json.Unmarshal([]byte(`{"run_id":"job","task_id":"sync","target_kind":"integration","target_id":"integration","trigger_kind":"manual","checks":[{"kind":"integration","id":"integration","permission":"manage_workflows"},{"kind":"integration","id":"integration","permission":"view"}]}`), &f); err != nil {
		t.Fatal(err)
	}
	spec, _ := workerOperation("discovery72.prepare_page")
	if !workerCheckShape(spec, f) {
		t.Fatal("valid discovery shape refused")
	}
	for _, mutate := range []func(*workerFacts){func(f *workerFacts) { f.TaskID = "" }, func(f *workerFacts) { f.TaskID = f.RunID }, func(f *workerFacts) { f.Checks = f.Checks[:1] }, func(f *workerFacts) { f.TargetID = "other" }, func(f *workerFacts) { f.TriggerKind = "runtime_decision" }, func(f *workerFacts) { f.DefinitionID = "definition" }} {
		bad := f
		mutate(&bad)
		if workerCheckShape(spec, bad) {
			t.Fatal("accepted non-discovery check shape")
		}
	}
}
