package policy

import (
	"context"
	"net/http"
	"testing"
	"time"
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
	cache := NewBundleCache([]byte("0123456789abcdef0123456789abcdef"))
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

func TestPolicyAdministrationRuntimeAndGate(t *testing.T) {
	ctx := context.Background()
	capabilities := Capabilities{Triggers: []string{"tool_call"}, Fields: []string{"tool.name"}, Actions: []Action{ActionMonitor, ActionBlock}}
	store := NewMemoryStore()
	value := Policy{ID: "policy-1", Name: "Shell control", Scope: "environment", Trigger: "tool_call", Conditions: []Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}, Action: ActionMonitor, Rollout: "monitor", FailureMode: "closed"}
	if err := store.Create(ctx, value, capabilities); err != nil {
		t.Fatal(err)
	}
	value.Action, value.Rollout = ActionBlock, "enforced"
	if err := store.Update(ctx, value, capabilities); err != nil {
		t.Fatal(err)
	}
	simulation, err := store.Simulate(ctx, value.ID, []ActionContext{{PrincipalID: "principal-1", AgentID: "agent-1", SessionID: "session-1", Action: "tool_call", Resource: "shell", EnvironmentID: "environment-1", Metadata: map[string]string{"tool.name": "shell"}}})
	if err != nil || simulation.Matches != 1 || simulation.WouldBlock != 1 {
		t.Fatalf("simulation=%+v err=%v", simulation, err)
	}
	if _, err := store.Rollout(ctx, value.ID, RolloutEnforced, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.RolloutAudit()) != 1 {
		t.Fatal("rollout audit missing")
	}
	if _, err := store.Rollout(ctx, value.ID, RolloutMonitor, "agent-1"); err == nil {
		t.Fatal("invalid rollout reversal accepted")
	}

	upstreamCalls := 0
	proxy := RuntimeProxy{Evaluate: func(context.Context, ActionContext) (Decision, error) {
		return Decision{Action: ActionBlock, Matched: true}, nil
	}, Upstream: func(context.Context, HTTPAction) (HTTPResult, error) { upstreamCalls++; return HTTPResult{}, nil }}
	blocked, err := proxy.Handle(ctx, HTTPAction{Method: http.MethodPost, URL: "https://tool.internal/run", Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"safe":true}`)}, ActionContext{PrincipalID: "principal-1", AgentID: "agent-1", SessionID: "session-1", Action: "tool_call", Resource: "shell", EnvironmentID: "environment-1"})
	if err != nil || blocked.Status != http.StatusForbidden || blocked.CorrelationID == "" || upstreamCalls != 0 {
		t.Fatalf("blocked=%+v calls=%d err=%v", blocked, upstreamCalls, err)
	}
	monitorEvents := 0
	action := HTTPAction{Method: http.MethodPost, URL: "https://tool.internal/run", Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"safe":true}`)}
	proxy = RuntimeProxy{PolicyID: value.ID, Evaluate: func(context.Context, ActionContext) (Decision, error) {
		return Decision{Action: ActionMonitor, Matched: true}, nil
	}, Monitor: func(_ context.Context, event RuntimeDecision) error {
		if event.PolicyID != value.ID || event.Result != "monitor" {
			t.Fatal("invalid monitor event")
		}
		monitorEvents++
		return nil
	}, Upstream: func(_ context.Context, received HTTPAction) (HTTPResult, error) {
		upstreamCalls++
		if received.Method != action.Method || received.URL != action.URL || string(received.Body) != string(action.Body) {
			t.Fatal("proxy changed action")
		}
		return HTTPResult{Status: http.StatusOK, Headers: received.Headers, Body: received.Body}, nil
	}}
	allowed, err := proxy.Handle(ctx, action, ActionContext{PrincipalID: "principal-1", AgentID: "agent-1", SessionID: "session-1", Action: "tool_call", Resource: "shell", EnvironmentID: "environment-1"})
	if err != nil || allowed.Status != http.StatusOK || monitorEvents != 1 || upstreamCalls != 1 {
		t.Fatalf("allowed=%+v monitor=%d calls=%d err=%v", allowed, monitorEvents, upstreamCalls, err)
	}

	parsed, err := ParseMCPAction([]byte(`{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"shell","arguments":{"resource":"repo"}}}`), "principal-1", "agent-1", "session-1", "environment-1")
	if err != nil || parsed.Action != "tools/call" || parsed.Resource != "repo" {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	decisions := NewDecisionStore()
	event := RuntimeDecision{ID: "decision-1", PolicyID: value.ID, EnvironmentID: "environment-1", Result: "monitor", CorrelationID: "correlation-1", At: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}
	if decisions.Record(ctx, event) != nil || decisions.Record(ctx, event) != nil || decisions.Count() != 1 {
		t.Fatal("decision replay was not idempotent")
	}
	compiled, _ := Compile(value)
	secret := []byte("0123456789abcdef0123456789abcdef")
	bundle, _ := SignBundle(secret, "environment-1", []CompiledPolicy{compiled})
	fallback, err := EvaluateBundleFallback(ctx, secret, bundle, time.Now().Add(time.Minute), "closed", time.Now(), map[string]string{"tool.name": "shell"})
	if err != nil || fallback.Action != ActionBlock || !fallback.Matched {
		t.Fatalf("fallback=%+v err=%v", fallback, err)
	}
	p95, err := MeasureDecisionP95(ctx, compiled, map[string]string{"tool.name": "shell"}, 100)
	if err != nil || p95 > 25*time.Millisecond {
		t.Fatalf("p95=%s err=%v", p95, err)
	}
	if ApplyDecisionEvidence("verified", RuntimeDecision{}) != "verified" || ApplyDecisionEvidence("verified", RuntimeDecision{PolicyID: "policy-1", EnvironmentID: "environment-1", Result: "block", CorrelationID: "correlation-1"}) != "blocked" {
		t.Fatal("re-test state was not evidence-bound")
	}
	report, err := EvaluateM6Gate(M6GateFixture{Created: true, Simulated: true, Monitored: true, Enforced: true, Retested: true, OutageEnforced: true})
	if err != nil || report.Status != "PASS" || report.Checks != 6 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}
