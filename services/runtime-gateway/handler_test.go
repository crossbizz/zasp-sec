package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestGatewayHandlerEvaluatesLocallyWithStrictNoStoreResponse(t *testing.T) {
	runtime := gatewayHTTPRuntime(t)
	handler, err := newGatewayHandler(runtime, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")})
	request := httptest.NewRequest(http.MethodPost, gatewayEvaluatePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var result gatewayEvaluationResult
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Decision != "block" || result.PolicyVersion != 1 {
		t.Fatalf("result=%#v body=%s", result, response.Body.String())
	}
}

func TestGatewayHandlerRejectsUnknownOversizedAndNonPOSTRequests(t *testing.T) {
	runtime := gatewayHTTPRuntime(t)
	handler, _ := newGatewayHandler(runtime, 1024)
	for _, test := range []struct {
		method, contentType, body string
		status                    int
	}{
		{http.MethodGet, "application/json", `{}`, http.StatusMethodNotAllowed},
		{http.MethodPost, "text/plain", `{}`, http.StatusUnsupportedMediaType},
		{http.MethodPost, "application/json", `{"event_id":"` + gatewayRuntimeID(9) + `","action_kind":"mcp","attributes":{"tool.name":"shell"},"classification":{"category":"runtime","route_class":"local","resource_class":"tool","outcome":"blocked"},"raw":"secret"}`, http.StatusBadRequest},
		{http.MethodPost, "application/json", `{"event_id":"` + strings.Repeat("x", 1025) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		request := httptest.NewRequest(test.method, gatewayEvaluatePath, strings.NewReader(test.body))
		request.Header.Set("Content-Type", test.contentType)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("test=%#v status=%d body=%s", test, response.Code, response.Body.String())
		}
	}
}

func gatewayHTTPRuntime(t *testing.T) *gatewayRuntime {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	return runtime
}
