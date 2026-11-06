package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestOptionalPlannerDispatchClosedWorkerBoundary(t *testing.T) {
	for _, operation := range []WorkerOperation{"ordered68.planning.start", "test74.planning.start", "finding.planning.start"} {
		statement, ok := optionalPlannerDispatchStatement(operation)
		if !ok || statement == "" {
			t.Fatal("closed current planner family unavailable")
		}
		var executor *WorkerExecutor
		if !errors.Is(executor.AdmitOptionalPlannerDispatch(context.Background(), operation, json.RawMessage(`{}`), migrations.OptionalEgressProfileChecksum()), ErrInvalid) {
			t.Fatal("missing current proof issuer accepted")
		}
	}
	for _, operation := range []WorkerOperation{"", "finding.apply", "finding.planning.reconcile", "test74.planning.late_usage", "ordered68.planning.recovery", "discovery72.run", "finding.planning.start;SELECT 1"} {
		if statement, ok := optionalPlannerDispatchStatement(operation); ok || statement != "" {
			t.Fatal("nonforward, unknown or caller-selected operation accepted")
		}
		if !errors.Is((&WorkerExecutor{}).AdmitOptionalPlannerDispatch(context.Background(), operation, json.RawMessage(`{}`), migrations.OptionalEgressProfileChecksum()), ErrInvalid) {
			t.Fatal("unclassified optional operation reached database authority")
		}
	}
	for _, executor := range []*WorkerExecutor{nil, {}, {adapter: true}, {discovery: true}} {
		if !errors.Is(executor.OptionalEgressReady(context.Background(), migrations.OptionalEgressProfileChecksum()), ErrInvalid) {
			t.Fatal("wrong/missing worker authority reported optional readiness")
		}
	}
	for _, pin := range []string{"", "unknown", "0000000000000000000000000000000000000000000000000000000000000000"} {
		if !errors.Is((&WorkerExecutor{}).AdmitOptionalPlannerDispatch(context.Background(), "finding.planning.start", json.RawMessage(`{}`), pin), ErrInvalid) {
			t.Fatal("missing or uncompiled profile accepted")
		}
	}
}
