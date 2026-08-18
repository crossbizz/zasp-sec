package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
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

func TestOPAArtifactRuntimeAndHistoricalBoundaries(t *testing.T) {
	ctx := context.Background()
	secret := []byte("0123456789abcdef0123456789abcdef")
	value := Policy{ID: "policy-1", Name: "Block shell", Scope: "environment", Trigger: "tool_call", Conditions: []Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}, Action: ActionBlock, Rollout: "enforced", FailureMode: "closed"}
	compiled, err := Compile(value)
	if err != nil || !strings.Contains(compiled.Rego, "default decision") || !strings.Contains(compiled.Rego, "input[") {
		t.Fatalf("compiled=%+v err=%v", compiled, err)
	}
	matched, err := Evaluate(ctx, compiled, map[string]string{"tool.name": "shell"})
	unmatched, unmatchedErr := Evaluate(ctx, compiled, map[string]string{"tool.name": "read"})
	if err != nil || unmatchedErr != nil || !matched.Matched || matched.Action != ActionBlock || unmatched.Matched || unmatched.Action != ActionMonitor {
		t.Fatalf("matched=%+v unmatched=%+v err=%v/%v", matched, unmatched, err, unmatchedErr)
	}
	tampered := compiled
	tampered.Rego = strings.Replace(tampered.Rego, "package zasp.runtime", "package zasp.runtime[", 1)
	if _, err := Evaluate(ctx, tampered, map[string]string{"tool.name": "shell"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("tampered Rego error=%v", err)
	}
	if _, err := Evaluate(ctx, compiled, map[string]string{"tool.name": "shell", "extra": strings.Repeat("x", 257)}); !errors.Is(err, ErrRejected) {
		t.Fatalf("unbounded OPA input error=%v", err)
	}

	bundle, err := SignBundle(secret, "environment-1", []CompiledPolicy{compiled})
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope(t)
	reference, err := domain.NewEvidenceRef(testProductID(t))
	if err != nil {
		t.Fatal(err)
	}
	artifactTarget := &recordingBundleArtifacts{}
	artifact, err := WriteBundleArtifact(ctx, secret, artifactTarget, scope, reference, bundle)
	if err != nil || artifact.Reference != reference || artifactTarget.request.MediaType != "application/json" || !bytes.Equal(artifact.Body, artifactTarget.request.Body) || artifact.SHA256 != sha256.Sum256(artifact.Body) {
		t.Fatalf("artifact=%+v request=%+v err=%v", artifact, artifactTarget.request, err)
	}

	cache := NewBundleCache(secret)
	if err := cache.Store(bundle); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := RestoreBundleCache(secret, snapshot)
	if err != nil || restarted.Load("environment-1").Signature != bundle.Signature {
		t.Fatalf("restored=%+v err=%v", restarted, err)
	}
	handler, err := NewBundleHTTPHandler(restarted, "runtime-token-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/policy-bundle?environment_id=environment-1", nil)
	request.Header.Set("Authorization", "Bearer runtime-token-0123456789abcdef")
	request.Header.Set("X-Zasp-Runtime-Environment", "environment-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), bundle.Signature) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/internal/v1/policy-bundle?environment_id=environment-1", nil)
	request.Header.Set("Authorization", "Bearer wrong-runtime-token")
	request.Header.Set("X-Zasp-Runtime-Environment", "environment-1")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d body=%q", response.Code, response.Body.String())
	}

	store := NewMemoryStore()
	capabilities := Capabilities{Triggers: []string{"tool_call"}, Fields: []string{"tool.name"}, Actions: []Action{ActionMonitor, ActionBlock}}
	if err := store.Create(ctx, value, capabilities); err != nil {
		t.Fatal(err)
	}
	history := &recordingOpenSearchHistory{events: []ActionContext{{PrincipalID: "principal-1", AgentID: "agent-1", SessionID: "session-1", Action: "tool_call", Resource: "shell", EnvironmentID: "environment-1", Metadata: map[string]string{"tool.name": "shell"}}}}
	simulation, err := store.SimulateOpenSearch(ctx, value.ID, "environment-1", history)
	if err != nil || history.limit != 100 || simulation.Matches != 1 || simulation.WouldBlock != 1 {
		t.Fatalf("simulation=%+v limit=%d err=%v", simulation, history.limit, err)
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

type recordingBundleArtifacts struct{ request artifactstore.PutRequest }

func (store *recordingBundleArtifacts) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	store.request = request
	return artifactstore.Artifact{Locator: request.Locator, MediaType: request.MediaType, Body: bytes.Clone(request.Body), Size: int64(len(request.Body)), SHA256: sha256.Sum256(request.Body)}, nil
}

func (*recordingBundleArtifacts) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, errors.New("unexpected get")
}

func (*recordingBundleArtifacts) Delete(context.Context, artifactstore.Locator) error {
	return errors.New("unexpected delete")
}

type recordingOpenSearchHistory struct {
	events []ActionContext
	limit  int
}

func (history *recordingOpenSearchHistory) SearchPolicyActions(_ context.Context, environmentID string, limit int) ([]ActionContext, error) {
	if environmentID != "environment-1" {
		return nil, errors.New("wrong environment")
	}
	history.limit = limit
	return append([]ActionContext(nil), history.events...), nil
}

func testProductID(t *testing.T) domain.ProductID {
	t.Helper()
	value, err := domain.NewProductID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testScope(t *testing.T) domain.Scope {
	t.Helper()
	value, err := domain.NewScope(testProductID(t), testProductID(t), testProductID(t))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
