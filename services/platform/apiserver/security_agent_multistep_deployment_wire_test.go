package apiserver

import (
	"strings"
	"testing"
)

func TestSecurityAgentMultistepDeploymentWireDecoder(t *testing.T) {
	for _, maximum := range []int{8 * 1024 * 1024, 10 * 1024 * 1024} {
		for _, delta := range []int{-1, 0, 1} {
			raw := []byte(`{"value": "` + strings.Repeat("x", maximum-13+delta) + `"}`)
			if len(raw) != maximum+delta {
				t.Fatal("fixture wire size", len(raw))
			}
			_, valid := orderedDeploymentClosedObject(raw, maximum, "value")
			if valid != (delta <= 0) {
				t.Fatal("deployment wire boundary", maximum, delta, valid)
			}
		}
	}
	for _, raw := range []string{`{"value":null}`, `{"value":1,"value":2}`, `{"value":1,"extra":2}`, `{"value":1} {}`, "{\"value\":\"\xff\"}"} {
		if _, valid := orderedDeploymentClosedObject([]byte(raw), orderedDeploymentResponseBytes, "value"); valid {
			t.Fatal("deployment decoder weakened closed shape", raw)
		}
	}
}

func TestSecurityAgentMultistepDeploymentSigningBudget(t *testing.T) {
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	scope, valid := orderedApplicationScope(o, w, e, "pid_78000001-0000-4000-8000-000000000001", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914")
	if !valid {
		t.Fatal("boundary scope")
	}
	for _, delta := range []int{-1, 0, 1} {
		policies := orderedWireFitPolicies(t, orderedWireBoundaryDefinitions(), o, w, e, 1024*1024+delta)
		if orderedDeploymentSignable(scope, orderedApplicationDevice, 1, policies) != (delta <= 0) {
			t.Fatal("maximum-key gateway envelope budget", delta)
		}
	}
}
