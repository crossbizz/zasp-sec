package apiserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// A malformed nested child snapshot must never select an execution branch.
func TestRelease61StateRejectsMalformedTestAuthority(t *testing.T) {
	o, _ := domain.ParseProductID("pid_70000001-0000-4000-8000-000000000001")
	w, _ := domain.ParseProductID("pid_70000002-0000-4000-8000-000000000002")
	e, _ := domain.ParseProductID("pid_70000003-0000-4000-8000-000000000003")
	scope, _ := domain.NewScope(o, w, e)
	const run = "pid_78000001-0000-4000-8000-000000000001"
	for _, mode := range []string{"exact", "state", "owned_without_lease", "category", "duplicate_category", "observation_category", "duplicate_observation", "observation_schema", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			value := map[string]any{"test_run_id": "pid_dad9132a-b5e6-4ab0-8806-339039ccd10b", "test_definition_id": run, "test_definition_version": 1, "target_id": run, "target_kind": "agent_endpoint", "categories": []string{"prompt_injection"}, "input_digest": strings.Repeat("a", 64), "child_state": "queued", "attempt": 0, "owned": false, "lease_expires_at": "", "input_manifest": map[string]any{}, "input_body": "", "observations": []any{}}
			switch mode {
			case "state":
				value["child_state"] = "invented_success"
			case "owned_without_lease":
				value["owned"] = true
			case "category":
				value["categories"] = []string{"arbitrary_external_action"}
			case "duplicate_category":
				value["categories"] = []string{"prompt_injection", "prompt_injection"}
			case "observation_category":
				value["observations"] = []any{map[string]any{"category": "foreign_category", "state": "started", "observation": map[string]any{}}}
			case "duplicate_observation":
				value["categories"] = []string{"prompt_injection", "data_leakage"}
				item := map[string]any{"category": "prompt_injection", "state": "started", "observation": map[string]any{}}
				value["observations"] = []any{item, item}
			case "observation_schema":
				value["observations"] = []any{map[string]any{"category": "prompt_injection", "state": "completed", "observation": map[string]any{"target_comparison": map[string]any{}, "schema_version": "foreign", "run_id": run, "category": "prompt_injection", "credential_version_digest": "bad", "observation": map[string]any{"secret": "must-not-escape"}}}}
			case "manifest":
				value["input_body"] = "{}"
				value["input_manifest"] = map[string]any{"reference": "foreign", "version_id": "", "sha256": "bad", "size_bytes": -1}
			}
			raw, _ := json.Marshal(value)
			if got := validRelease61TestState(raw, scope, run); got != (mode == "exact") {
				t.Fatal("malformed authoritative child state accepted", mode, got)
			}
		})
	}
}
