package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestGatewayRuntimeSyncsSignedPolicyAndEvaluatesWithoutControlPlaneCall(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope, recorded: make(chan struct{}, 1)}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	controlCalls := control.calls
	result, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")})
	if err != nil || result.Decision != "block" || result.PolicyVersion != 1 || len(result.MatchedPolicyIDs) != 1 || control.calls != controlCalls {
		t.Fatalf("result=%#v err=%v calls=%d/%d", result, err, control.calls, controlCalls)
	}
	if runtime.RecordOnce(context.Background()) != nil || len(control.events) != 1 || control.events[0].Decision != "block" || control.events[0].Classification["outcome"] != "blocked" || control.events[0].NextFloor != 1 {
		t.Fatalf("events=%#v", control.events)
	}
}

func TestGatewayRuntimeAppliesDeterministicOfflineFailureMode(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	authority := gatewayRuntimeAuthority()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	for _, test := range []struct{ mode, decision string }{{"open", "allow"}, {"closed", "block"}} {
		cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), gatewayRuntimeTime)
		runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: test.mode, MaximumPendingEvents: 2, Now: gatewayRuntimeTime})
		if err != nil {
			t.Fatal(err)
		}
		result, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(8), ActionKind: "http", Attributes: map[string]string{"http.method": "GET", "http.route_class": "read"}, Classification: gatewayRuntimeClassification(test.decision)})
		if err != nil || result.Decision != test.decision || result.CacheState != "unavailable_"+test.mode {
			t.Fatalf("mode=%s result=%#v err=%v", test.mode, result, err)
		}
	}
}

func TestGatewayRuntimeRejectsRawOrUnboundEvaluationData(t *testing.T) {
	authority := gatewayRuntimeAuthority()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), gatewayRuntimeTime)
	runtime, _ := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 2, Now: gatewayRuntimeTime})
	for _, request := range []gatewayEvaluationRequest{
		{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.arguments": "secret"}, Classification: gatewayRuntimeClassification("block")},
		{EventID: gatewayRuntimeID(8), ActionKind: "http", Attributes: map[string]string{"http.body": "secret"}, Classification: gatewayRuntimeClassification("block")},
		{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: map[string]string{"category": "runtime", "outcome": "block", "authorization": "secret"}},
	} {
		if result, err := runtime.Evaluate(context.Background(), request); !errors.Is(err, errGatewayRuntime) || result.Decision != "" {
			t.Fatalf("request=%#v result=%#v err=%v", request, result, err)
		}
	}
}

func TestGatewayRuntimeBackgroundSyncsAndDrainsEvidence(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope, recorded: make(chan struct{}, 1)}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, _ := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if runtime.SyncOnce(context.Background()) != nil {
		t.Fatal("initial sync failed")
	}
	if _, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx, 10*time.Millisecond, time.Millisecond) }()
	select {
	case <-control.recorded:
	case <-time.After(time.Second):
		t.Fatal("evidence did not drain")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type gatewayControlStub struct {
	authority gatewayAuthority
	envelope  *policy.GatewayPolicyEnvelope
	events    []gatewayDecisionEvent
	calls     int
	recorded  chan struct{}
}

func (stub *gatewayControlStub) Ready(context.Context) error { stub.calls++; return nil }
func (stub *gatewayControlStub) Authority(context.Context, string) (gatewayAuthority, error) {
	stub.calls++
	return stub.authority, nil
}
func (stub *gatewayControlStub) Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error) {
	stub.calls++
	if stub.envelope == nil {
		return nil, nil
	}
	copy := *stub.envelope
	return &copy, nil
}
func (stub *gatewayControlStub) Record(_ context.Context, event gatewayDecisionEvent) error {
	stub.calls++
	stub.events = append(stub.events, event)
	if stub.recorded != nil {
		select {
		case stub.recorded <- struct{}{}:
		default:
		}
	}
	return nil
}

func gatewayRuntimeAuthority() gatewayAuthority {
	return gatewayAuthority{OrganizationID: gatewayRuntimeID(1), WorkspaceID: gatewayRuntimeID(2), EnvironmentID: gatewayRuntimeID(3), DeviceID: gatewayRuntimeID(4), CredentialID: gatewayRuntimeID(5), ReplayFloor: 0}
}

func gatewayRuntimeID(value int) string {
	return "pid_9000000" + string(rune('0'+value)) + "-0000-4000-8000-00000000000" + string(rune('0'+value))
}

func gatewayRuntimeTime() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }

func gatewayRuntimeClassification(outcome string) map[string]string {
	return map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": outcome}
}

func signedGatewayRuntimeEnvelope(t *testing.T, private ed25519.PrivateKey, authority gatewayAuthority, now time.Time, failureMode string) policy.GatewayPolicyEnvelope {
	t.Helper()
	compiled, err := policy.Compile(policy.Policy{ID: "policy-1", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}})
	if err != nil {
		t.Fatal(err)
	}
	envelope := policy.GatewayPolicyEnvelope{ContractVersion: 1, KeyID: "gateway-key-1", Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, Sequence: 1, PolicyVersion: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), FailureMode: failureMode, Policies: []policy.CompiledPolicy{compiled}}
	policies := append([]policy.CompiledPolicy(nil), envelope.Policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	payload, _ := json.Marshal(struct {
		ContractVersion int                     `json:"contract_version"`
		KeyID           string                  `json:"key_id"`
		Algorithm       string                  `json:"algorithm"`
		Audience        string                  `json:"audience"`
		OrganizationID  string                  `json:"organization_id"`
		WorkspaceID     string                  `json:"workspace_id"`
		EnvironmentID   string                  `json:"environment_id"`
		DeviceID        string                  `json:"device_id"`
		Sequence        uint64                  `json:"sequence"`
		PolicyVersion   uint64                  `json:"policy_version"`
		IssuedAt        time.Time               `json:"issued_at"`
		ExpiresAt       time.Time               `json:"expires_at"`
		FailureMode     string                  `json:"failure_mode"`
		Policies        []policy.CompiledPolicy `json:"policies"`
	}{envelope.ContractVersion, envelope.KeyID, envelope.Algorithm, envelope.Audience, envelope.OrganizationID, envelope.WorkspaceID, envelope.EnvironmentID, envelope.DeviceID, envelope.Sequence, envelope.PolicyVersion, envelope.IssuedAt, envelope.ExpiresAt, envelope.FailureMode, policies})
	digest := sha256.Sum256(payload)
	envelope.PayloadDigest = hex.EncodeToString(digest[:])
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))
	return envelope
}
