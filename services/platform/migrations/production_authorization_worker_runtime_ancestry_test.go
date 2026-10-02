package migrations

import (
	"strings"
	"testing"
)

func TestWorkerRuntimeAncestryAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, required := range []string{
		"CREATE FUNCTION zasp_authorization80_worker.runtime_occurrence_match(",
		"CREATE FUNCTION zasp_authorization80_worker.runtime_source(",
		"END $runtime_source_catalog$;",
		"END $test_context_inner$;",
		"'runtime-source-trigger'",
		"'public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass,'public.zasp_runtime_session_summaries'::regclass,'public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass",
		"t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate')",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("runtime ancestry not assembled: %s", required)
		}
	}
	start := strings.Index(source, "CREATE FUNCTION zasp_authorization80_worker.runtime_occurrence_match(")
	owners := strings.LastIndex(source, "DO $owners$")
	if start < 0 || start > owners {
		t.Error("runtime ancestry must precede the final private owner/ACL closure")
	}
}

func TestWorkerRuntimeAncestryProjectsEffective76(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, required := range []string{
		"signature='zasp_temporal78.predecessor76_fingerprint()'",
		"runtime76 executor body catalog changed",
		"CASE WHEN p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.load_plan(jsonb)'::regprocedure) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("effective76 runtime ancestry body projection missing: %s", required)
		}
	}
}
