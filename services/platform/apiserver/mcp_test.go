package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductMCPRechecksToolRouteAndTenantScope(t *testing.T) {
	seen := []string{}
	product := &evidencePackProduct{}
	dependency := func() http.Handler { return &evidencePackDependencyStub{product: product, operations: &seen} }
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: dependency(), Risk: dependency(), Workflow: dependency(), Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	server, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://app.zasp.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(_ context.Context, c Credential) (RequestIdentity, error) {
		if c.Value != "fixture" {
			return RequestIdentity{}, ErrAuthenticationRequired
		}
		return identity, nil
	}}, composition)
	if err != nil {
		t.Fatal(err)
	}
	call := func(bearer, origin, method, params string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "https://app.zasp.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	if w := call("", "", "tools/list", "{}"); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous %d", w.Code)
	}
	if w := call("fixture", "https://elsewhere.example", "tools/list", "{}"); w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin %d", w.Code)
	}
	w := call("fixture", "", "tools/list", "{}")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "list_agents") || strings.Contains(w.Body.String(), "inspect_session") {
		t.Fatalf("tool list %d %s", w.Code, w.Body)
	}
	w = call("fixture", "", "tools/call", `{"name":"get_attack_path","arguments":{"id":"`+packAgent+`"}}`)
	if w.Code != 200 || !json.Valid(w.Body.Bytes()) || len(seen) != 1 || seen[0] != "getAttackPath" {
		t.Fatalf("tool route %d %s %v", w.Code, w.Body, seen)
	}
	w = call("fixture", "", "tools/call", `{"name":"get_posture_summary","arguments":{"id":"`+packAgent+`"}}`)
	if len(seen) != 1 {
		t.Fatalf("browser-only call reached handler: %s", w.Body)
	}
}
