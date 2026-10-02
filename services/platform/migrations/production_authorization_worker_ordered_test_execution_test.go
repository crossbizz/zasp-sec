package migrations

import (
	"strings"
	"testing"
)

func TestOrderedTestDownstreamAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	last := -1
	for _, boundary := range []string{
		"DO $ordered_lifecycle_copies$",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_progress_facts(",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_test_source(",
		"DO $ordered_test_proof$",
		"DO $ordered_test_copies$",
		"CREATE OR REPLACE FUNCTION zasp_temporal68.progress(q jsonb)",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_test_complete(",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_test_replay(",
		"CREATE FUNCTION zasp_authorization80_worker.ordered68_test_state(",
		"DO $ordered_effect_catalog$",
		"FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace LOOP",
	} {
		position := strings.Index(source, boundary)
		if strings.Count(source, boundary) != 1 || position <= last {
			t.Fatalf("missing, repeated or unordered downstream boundary: %s", boundary)
		}
		last = position
	}
	for _, private := range []string{"ordered68_progress_facts", "ordered68_adapter_facts", "require_ordered68_test", "ordered68_test_exit", "ordered68_linked_start", "ordered68_progress_native", "ordered68_linked_native", "ordered68_invocation_native", "ordered68_completion_native", "ordered68_test_settle_native", "ordered68_test_stop_native"} {
		if strings.Contains(source, "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker."+private+"(") {
			t.Fatal("private downstream function exposed", private)
		}
	}
	for _, required := range []string{
		"'zasp_temporal68.progress(jsonb)'::regprocedure,'zasp_temporal68.linked(jsonb)'::regprocedure,'zasp_temporal68.invocation(jsonb)'::regprocedure,'zasp_temporal68.test_settle(jsonb)'::regprocedure,'zasp_temporal68.test_stop(jsonb)'::regprocedure",
		"GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_test_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation,zasp_red_team_adapter;",
		"SELECT zasp_temporal78.current_ready() AND false",
	} {
		if !strings.Contains(source, required) {
			t.Fatal("missing downstream boundary", required)
		}
	}
}

func TestOrderedTestStopCopyUsesExactRetainedReadCall(t *testing.T) {
	const signature = "CREATE FUNCTION zasp_temporal68.test_stop(q jsonb)"
	start := strings.Index(temporalExecutorSettlementSQL, signature)
	if start < 0 {
		t.Fatal("retained stop absent")
	}
	retained := temporalExecutorSettlementSQL[start:]
	const call = "zasp_temporal68.effect(q||jsonb_build_object('operation','read'))"
	if strings.Count(retained, call) != 1 || !strings.Contains(retained, "q->'payload' IS DISTINCT FROM '{}'::jsonb") {
		t.Fatal("retained stop input contract changed")
	}
	branch := strings.Index(authorizationWorkerOrderedTestSQL, "WHEN 'zasp_temporal68.test_stop(jsonb)' THEN")
	if branch < 0 {
		t.Fatal("stop copy absent")
	}
	copy := authorizationWorkerOrderedTestSQL[branch:]
	end := strings.Index(copy, "END CASE;")
	if end < 0 {
		t.Fatal("copy boundary absent")
	}
	copy = copy[:end]
	if !strings.Contains(copy, "$old$"+call+"$old$") || !strings.Contains(copy, "$new$zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read'))$new$") {
		t.Fatal("stop copy does not match exact retained call")
	}
}
