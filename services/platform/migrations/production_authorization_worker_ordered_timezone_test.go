package migrations

import (
	"strings"
	"testing"
)

// A function-level timezone on these wrappers changes the full-row digest
// contract of their retained native callees, even before any effect is sent.
func TestOrdered68NativeTimezoneAssembly(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	for _, name := range []string{"ordered68_effect_metadata", "ordered68_policy_metadata", "ordered68_policy_input", "ordered68_policy_begin", "ordered68_policy_store", "ordered68_operation_source", "ordered68_test_source"} {
		marker := "CREATE FUNCTION zasp_authorization80_worker." + name + "("
		if strings.Count(source, marker) != 1 {
			t.Fatalf("missing or duplicate native wrapper %s", name)
		}
		header := strings.SplitN(strings.SplitN(source, marker, 2)[1], " AS $", 2)[0]
		if strings.Contains(header, "timezone") || strings.Contains(header, "TimeZone") {
			t.Errorf("%s overrides inherited native timezone", name)
		}
	}
	leaf := "CREATE FUNCTION zasp_authorization80_worker.ordered68_row_json(v anyelement)"
	if strings.Count(source, leaf) != 1 || !strings.Contains(source, "SET timezone='UTC' AS $ordered_row_json$ SELECT to_jsonb(v) $ordered_row_json$;") {
		t.Error("canonical typed serialization leaf absent")
	}
	if strings.Contains(source, "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_row_json") {
		t.Error("canonical typed serialization leaf exposed")
	}
	for _, call := range []string{
		"PERFORM zasp_temporal68.current_plan(x.organization_id,x.workspace_id,x.environment_id,x.run_id,NOT compensation);",
		"PERFORM zasp_sa_multistep_prior.application_current(fx.organization_id,fx.workspace_id,fx.environment_id,fx.run_id,fx.step_id);",
		"PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);",
	} {
		if !strings.Contains(source, call) {
			t.Errorf("native validator lost: %s", call)
		}
	}
}
