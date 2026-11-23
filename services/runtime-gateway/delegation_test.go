package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation/testfixture"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestDelegationHardBlockEvenWhenPolicyCacheFailsOpen(t *testing.T) {
	f := testfixture.Read(t, "../../sdks/fixtures/task-delegation.json")
	now := time.Unix(f.Issued, 0).UTC()
	authority := gatewayRuntimeAuthority()
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": pk})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	r, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{}, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "open", MaximumPendingEvents: 8, Now: func() time.Time { return now }, Delegation: &f.Verifier})
	if err != nil {
		t.Fatal(err)
	}
	q := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Classification: gatewayRuntimeClassification("requested"), Attributes: map[string]string{"agent_id": f.Verifier.Agent, "resource": "inbox", "tool.name": "draft_reply", "action": "draft_reply"}}
	check := func(want string) {
		t.Helper()
		v, err := r.Evaluate(context.Background(), q)
		if err != nil || v.Decision != want {
			t.Fatalf("got %s, %v want %s", v.Decision, err, want)
		}
	}
	check("block")
	q.Delegation = f.Token
	check("allow")
	q.Attributes["tool.name"] = "send_reply"
	check("block")
	q.Attributes["tool.name"] = "draft_reply"
	q.Attributes["resource"] = "archive"
	check("block")
	q.Attributes["resource"] = "inbox"
	target, _ := url.Parse("https://upstream.example/tools")
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set(delegation.Header, f.Token)
	if r.delegatedProxy(&q, req, []byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"send_reply"}}`), target) {
		t.Fatal("proxy accepted mismatched actual tool")
	}
	now = now.Add(time.Minute)
	check("block")
}
