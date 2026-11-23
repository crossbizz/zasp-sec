package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/mcpserver"
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
	if w.Code != 200 || !strings.Contains(w.Body.String(), "list_agents") || strings.Contains(w.Body.String(), "inspect_session") || strings.Contains(w.Body.String(), "propose_policy") || strings.Contains(w.Body.String(), "request_containment") || strings.Contains(w.Body.String(), "trigger_verification") {
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
	for _, action := range []string{"propose_policy", "request_containment", "trigger_verification"} {
		w := call("fixture", "", "tools/call", `{"name":"`+action+`","arguments":{"id":"`+packAgent+`"}}`)
		if !strings.Contains(w.Body.String(), "error") || len(seen) != 1 {
			t.Fatalf("read-only token reached action %s: %s", action, w.Body)
		}
	}
}

func TestMCPReviewReadsExactPendingApprovalAndCase(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	ref := packAgent
	payload := ""
	wantPath := ""
	reads := 0
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.Method != http.MethodGet || r.URL.Path != wantPath || r.URL.RawQuery != "" {
			t.Fatalf("review attempted unexpected operation %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(payload))
	})
	r := httptest.NewRequest("POST", "/mcp", nil)
	r = r.WithContext(context.WithValue(r.Context(), productRouterContextKey{}, http.Handler(router)))
	routes := map[string]string{"getSecurityAgentApproval": "/api/v1/security-agent-approvals/{id}", "getSecurityCaseVerification": "/api/v1/security-agents/cases/{id}/verify"}
	check := func(name string, allowed bool, surface string) {
		t.Helper()
		status, raw := mcpReview(r, identity, routes, name, mcpserver.Proposal{Reference: ref})
		if !allowed {
			if status != http.StatusNotFound || len(raw) != 0 {
				t.Fatalf("unavailable handoff: %d %s", status, raw)
			}
			return
		}
		var review struct {
			URL    string `json:"review_url"`
			Record string `json:"record_id"`
		}
		if status != 200 || json.Unmarshal(raw, &review) != nil || review.Record != ref {
			t.Fatal("missing handoff", status, string(raw))
		}
		u, err := url.ParseRequestURI(review.URL)
		if err != nil || u.Path != surface || u.Query().Get("entity_id") != ref || u.Query().Get("environment_id") != identity.Scope.EnvironmentID().String() {
			t.Fatalf("wrong scope or target: %s", review.URL)
		}
	}
	wantPath = "/api/v1/security-agent-approvals/" + ref
	approval := SecurityAgentApproval{ID: ref, State: "pending", ExpiresAt: time.Now().Add(time.Minute), Context: &SecurityAgentApprovalContext{Action: "isolate_session"}}
	raw, _ := json.Marshal(approval)
	payload = string(raw)
	check("request_containment", true, "/protect/approvals")
	approval.State = "approved"
	raw, _ = json.Marshal(approval)
	payload = string(raw)
	check("request_containment", false, "")
	approval.State = "pending"
	approval.Context.Action = "other"
	raw, _ = json.Marshal(approval)
	payload = string(raw)
	check("request_containment", false, "")
	wantPath = "/api/v1/security-agents/cases/" + ref + "/verify"
	payload = `{"case_id":"` + ref + `","state":"open","reason":"owner_fixture_required"}`
	check("trigger_verification", true, "/protect/security-agents")
	payload = `{"case_id":"` + ref + `","state":"open","reason":"remediation_pending"}`
	check("trigger_verification", false, "")
	if reads != 5 {
		t.Fatal("unexpected request count", reads)
	}
}
