package policy

import (
	"context"
	"testing"
)

func TestPolicyValidationCompileEvaluateBundleAndCache(t *testing.T) {
	value := Policy{ID: "policy-1", Name: "Block shell", Scope: "environment", Trigger: "tool_call", Conditions: []Condition{{Field: "tool.category", Operator: "equals", Value: "shell"}}, Action: ActionBlock, Rollout: "enforced", FailureMode: "closed"}
	capabilities := Capabilities{Triggers: []string{"tool_call"}, Fields: []string{"tool.category"}, Actions: []Action{ActionMonitor, ActionBlock}}
	if err := Validate(value, capabilities); err != nil {
		t.Fatal(err)
	}
	first, err := Compile(value)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := Compile(value)
	if first.Rego != second.Rego || first.Digest != second.Digest {
		t.Fatal("compile drift")
	}
	decision, err := Evaluate(context.Background(), first, map[string]string{"tool.category": "shell"})
	if err != nil || decision.Action != ActionBlock {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	bundle, err := SignBundle([]byte("0123456789abcdef0123456789abcdef"), "environment-1", []CompiledPolicy{first})
	if err != nil || VerifyBundle([]byte("0123456789abcdef0123456789abcdef"), bundle) != nil {
		t.Fatal(err)
	}
	bundle.Manifest += "tampered"
	if VerifyBundle([]byte("0123456789abcdef0123456789abcdef"), bundle) == nil {
		t.Fatal("tampered bundle passed")
	}
	bundle, _ = SignBundle([]byte("0123456789abcdef0123456789abcdef"), "environment-1", []CompiledPolicy{first})
	bundle.Policies[0].Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if VerifyBundle([]byte("0123456789abcdef0123456789abcdef"), bundle) == nil {
		t.Fatal("policy drift passed signed manifest")
	}
	cache := NewBundleCache()
	bundle, _ = SignBundle([]byte("0123456789abcdef0123456789abcdef"), "environment-1", []CompiledPolicy{first})
	if cache.Store(bundle) != nil || cache.Load("environment-1").EnvironmentID != "environment-1" {
		t.Fatal("cache failed")
	}
	forged := value
	forged.Action = "approve"
	if Validate(forged, capabilities) == nil {
		t.Fatal("unsupported action accepted")
	}
}
