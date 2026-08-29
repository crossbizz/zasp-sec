package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestGatewayProxyForwardsMonitoredHTTPActionExactlyOnceWithoutControlHeaders(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "http.method", Operator: "equals", Value: http.MethodPost})
	upstream := &gatewayProxyRoundTripper{response: &http.Response{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"Content-Type": {"application/json"}, "X-Request-ID": {"accepted"}, "Set-Cookie": {"provider-secret=value"}, "X-Unapproved": {"discarded"}},
		Body:       io.NopCloser(strings.NewReader(`{"accepted":true}`)),
	}}
	base, _ := url.Parse("https://tools.customer.example/v1/actions")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{
		Runtime: runtime, Client: &http.Client{Transport: upstream}, Upstream: base,
		ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 16 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"operation":"read","resource":"repository"}`)
	request := httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, bytes.NewReader(body))
	setGatewayProxyHeaders(request, gatewayRuntimeID(9))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	request.Header.Set("Authorization", "Bearer upstream-token")
	request.Header.Set("Cookie", "session=local-secret")
	request.Header.Set("X-Unapproved", "discarded")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", "action-idempotency-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("X-Zasp-Correlation-ID") != gatewayRuntimeID(9) || response.Header().Get("X-Request-ID") != "accepted" || response.Header().Get("Set-Cookie") != "" || response.Header().Get("X-Unapproved") != "" || response.Body.String() != `{"accepted":true}` {
		t.Fatalf("status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if upstream.calls != 1 || upstream.request == nil || upstream.request.Method != http.MethodPost || upstream.request.URL.String() != base.String() || !bytes.Equal(upstream.body, body) {
		t.Fatalf("calls=%d request=%#v body=%s", upstream.calls, upstream.request, upstream.body)
	}
	if upstream.request.Header.Get("Authorization") != "" || upstream.request.Header.Get("Cookie") != "" || upstream.request.Header.Get("X-Unapproved") != "" || upstream.request.Header.Get("Content-Type") != "application/json" || upstream.request.Header.Get("Accept") != "application/json" || upstream.request.Header.Get("Idempotency-Key") != "action-idempotency-0001" {
		t.Fatalf("upstream headers=%#v", upstream.request.Header)
	}
	for name := range upstream.request.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Zasp-") {
			t.Fatalf("forwarded control header %q", name)
		}
	}
}

func TestGatewayProxyPreservesHTTPMethodEscapedPathQueryAndEmptyBody(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "http.method", Operator: "equals", Value: http.MethodPut})
	upstream := &gatewayProxyRoundTripper{}
	base, _ := url.Parse("https://tools.customer.example/v1/actions")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{
		Runtime: runtime, Client: &http.Client{Transport: upstream}, Upstream: base,
		ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 16 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, gatewayHTTPProxyPath+"/repositories/a%2Fb?dry_run=true&limit=10", nil)
	if target, ok := gatewayProxyTarget(base, request.URL, false); !ok {
		t.Fatalf("source_url=%#v target=%#v", request.URL, target)
	}
	setGatewayProxyHeaders(request, gatewayRuntimeSequenceID(12))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || upstream.calls != 1 || upstream.request == nil {
		t.Fatalf("status=%d calls=%d request=%#v body=%s", response.Code, upstream.calls, upstream.request, response.Body.String())
	}
	if upstream.request.Method != http.MethodPut || upstream.request.URL.String() != "https://tools.customer.example/v1/actions/repositories/a%2Fb?dry_run=true&limit=10" || len(upstream.body) != 0 {
		t.Fatalf("method=%q url=%q body=%q", upstream.request.Method, upstream.request.URL.String(), upstream.body)
	}
}

func TestGatewayProxyRejectsHTTPTraversalAndUnsafeMethodsBeforeUpstream(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "action", Operator: "equals", Value: "write"})
	upstream := &gatewayProxyRoundTripper{}
	base, _ := url.Parse("https://tools.customer.example/v1/actions")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{Runtime: runtime, Client: &http.Client{Transport: upstream}, Upstream: base, ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		target string
	}{
		{method: http.MethodPut, target: gatewayHTTPProxyPath + "/%2e%2e/admin"},
		{method: http.MethodConnect, target: gatewayHTTPProxyPath + "/repositories"},
		{method: http.MethodTrace, target: gatewayHTTPProxyPath + "/repositories"},
	} {
		request := httptest.NewRequest(test.method, test.target, nil)
		setGatewayProxyHeaders(request, gatewayRuntimeSequenceID(13))
		request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code < http.StatusBadRequest || response.Code >= http.StatusInternalServerError {
			t.Fatalf("method=%q target=%q status=%d body=%s", test.method, test.target, response.Code, response.Body.String())
		}
	}
	if upstream.calls != 0 {
		t.Fatalf("upstream calls=%d", upstream.calls)
	}
}

func TestGatewayProxyRejectsHopByHopRequestAndRedirectResponse(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "action", Operator: "equals", Value: "write"})
	upstream := &gatewayProxyRoundTripper{response: &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://foreign.example/"}}, Body: io.NopCloser(strings.NewReader("redirect"))}}
	base, _ := url.Parse("https://tools.customer.example/v1/actions")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{Runtime: runtime, Client: &http.Client{Transport: upstream, CheckRedirect: func(*http.Request, []*http.Request) error { return errGatewayRuntime }}, Upstream: base, ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, strings.NewReader(`{"operation":"write"}`))
	setGatewayProxyHeaders(request, gatewayRuntimeID(5))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	request.Header.Set("Connection", "Idempotency-Key")
	request.Header.Set("Idempotency-Key", "do-not-forward")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || upstream.calls != 0 {
		t.Fatalf("hop status=%d calls=%d body=%s", response.Code, upstream.calls, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, strings.NewReader(`{"operation":"write"}`))
	setGatewayProxyHeaders(request, gatewayRuntimeID(4))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || upstream.calls != 1 || response.Header().Get("Location") != "" {
		t.Fatalf("redirect status=%d calls=%d headers=%#v body=%s", response.Code, upstream.calls, response.Header(), response.Body.String())
	}
}

func TestGatewayProxyAcceptsCapabilityEvidenceOnlyForBlockingDecision(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "action", Operator: "equals", Value: "write"})
	upstream := &gatewayProxyRoundTripper{}
	base, _ := url.Parse("https://tools.customer.example/v1/actions")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{Runtime: runtime, Client: &http.Client{Transport: upstream}, Upstream: base, ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, strings.NewReader(`{"operation":"write"}`))
	setGatewayProxyHeaders(request, gatewayRuntimeID(3))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	request.Header.Set("X-Zasp-Capability-Agent-ID", gatewayRuntimeID(6))
	request.Header.Set("X-Zasp-Capability-Target-ID", gatewayRuntimeID(7))
	request.Header.Set("X-Zasp-Capability-Category", "data_write")
	request.Header.Set("X-Zasp-Capability-Outcome", "write")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || upstream.calls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, upstream.calls, response.Body.String())
	}
}

func TestGatewayProxyBlocksMatchingMCPCallBeforeUpstreamWithStableProductResponse(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "tool_call", policy.ActionBlock, policy.Condition{Field: "action", Operator: "equals", Value: "write"})
	upstream := &gatewayProxyRoundTripper{}
	base, _ := url.Parse("https://tools.customer.example/mcp")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{
		Runtime: runtime, Client: &http.Client{Transport: upstream}, Upstream: base,
		ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 16 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"shell","arguments":{"resource":"repository","command":"secret-not-evidence"}}}`)
	request := httptest.NewRequest(http.MethodPost, gatewayMCPProxyPath, bytes.NewReader(body))
	setGatewayProxyHeaders(request, gatewayRuntimeID(8))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || upstream.calls != 0 || response.Header().Get("X-Zasp-Correlation-ID") != gatewayRuntimeID(8) {
		t.Fatalf("status=%d calls=%d headers=%#v body=%s", response.Code, upstream.calls, response.Header(), response.Body.String())
	}
	if response.Body.String() != `{"code":"policy_blocked","correlation_id":"`+gatewayRuntimeID(8)+`","policy_ids":["policy-proxy"]}`+"\n" || strings.Contains(response.Body.String(), "secret-not-evidence") {
		t.Fatalf("body=%s", response.Body.String())
	}
}

func TestGatewayProxyRejectsInvalidAuthorityAndBodiesBeforeEvaluationOrUpstream(t *testing.T) {
	runtime := gatewayProxyRuntime(t, "tool_call", policy.ActionBlock, policy.Condition{Field: "tool.name", Operator: "equals", Value: "shell"})
	upstream := &gatewayProxyRoundTripper{}
	base, _ := url.Parse("https://tools.customer.example/mcp")
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{
		Runtime: runtime, Client: &http.Client{Transport: upstream}, Upstream: base,
		ClientToken: []byte("0123456789abcdef0123456789abcdef"), MaximumBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	validBody := `{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"shell","arguments":{"resource":"repository"}}}`
	tests := []struct {
		name  string
		body  string
		apply func(*http.Request)
		want  int
	}{
		{name: "missing token", body: validBody, apply: func(request *http.Request) { setGatewayProxyHeaders(request, gatewayRuntimeID(7)) }, want: http.StatusUnauthorized},
		{name: "wrong token", body: validBody, apply: func(request *http.Request) {
			setGatewayProxyHeaders(request, gatewayRuntimeID(7))
			request.Header.Set("X-Zasp-Gateway-Token", "wrong-secret-value-that-is-not-valid")
		}, want: http.StatusUnauthorized},
		{name: "missing principal", body: validBody, apply: func(request *http.Request) {
			setGatewayProxyHeaders(request, gatewayRuntimeID(7))
			request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
			request.Header.Del("X-Zasp-Principal-ID")
		}, want: http.StatusBadRequest},
		{name: "unknown MCP field", body: strings.Replace(validBody, `"params":`, `"secret":"leak","params":`, 1), apply: func(request *http.Request) {
			setGatewayProxyHeaders(request, gatewayRuntimeID(7))
			request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
		}, want: http.StatusBadRequest},
		{name: "missing resource", body: `{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"shell","arguments":{"command":"value"}}}`, apply: func(request *http.Request) {
			setGatewayProxyHeaders(request, gatewayRuntimeID(7))
			request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
		}, want: http.StatusBadRequest},
		{name: "oversized", body: strings.Repeat("x", 1025), apply: func(request *http.Request) {
			setGatewayProxyHeaders(request, gatewayRuntimeID(7))
			request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
		}, want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, gatewayMCPProxyPath, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			test.apply(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || strings.Contains(response.Body.String(), "leak") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if upstream.calls != 0 {
		t.Fatalf("upstream calls=%d", upstream.calls)
	}
}

type gatewayProxyRoundTripper struct {
	request  *http.Request
	body     []byte
	response *http.Response
	calls    int
}

func (transport *gatewayProxyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	transport.request = request.Clone(request.Context())
	transport.request.Header = request.Header.Clone()
	transport.body, _ = io.ReadAll(request.Body)
	if transport.response == nil {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	}
	return transport.response, nil
}

func setGatewayProxyHeaders(request *http.Request, eventID string) {
	request.Header.Set("X-Zasp-Event-ID", eventID)
	request.Header.Set("X-Zasp-Principal-ID", gatewayRuntimeID(6))
	request.Header.Set("X-Zasp-Agent-ID", gatewayRuntimeID(7))
	request.Header.Set("X-Zasp-Session-ID", gatewayRuntimeSequenceID(10))
	request.Header.Set("X-Zasp-Route-Class", "local")
	request.Header.Set("X-Zasp-Resource-Class", "tool")
	request.Header.Set("X-Zasp-Action", "write")
	request.Header.Set("X-Zasp-Resource", "repository")
}

func gatewayProxyRuntime(t *testing.T, trigger string, action policy.Action, condition policy.Condition) *gatewayRuntime {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	compiled, err := policy.Compile(policy.Policy{ID: "policy-proxy", Trigger: trigger, Action: action, Conditions: []policy.Condition{condition}})
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedGatewayRuntimePolicies(t, private, authority, now, "closed", []policy.CompiledPolicy{compiled})
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	return runtime
}
