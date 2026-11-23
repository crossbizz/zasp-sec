package apiserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/inventoryprojection"
)

func TestProductMCPTenantIsolatedAgentListingOnInstalledPostgres(t *testing.T) {
	first, second := startInstalledV2Baseline(t), startInstalledV2Baseline(t)
	setup := func(b *installedBaseline) (*PostgresRepository, string, string, string) {
		t.Helper()
		if err := b.product.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		repo, err := NewPostgresRepository(b.product)
		if err != nil {
			t.Fatal(err)
		}
		admin := b.member("security_admin", "manage_api_tokens", "manage_identity", "manage_workflows", "view")
		issue, tokens := installedWorkloadTokenIssuer(t, b, repo, admin)
		issue("MCP inventory reader", `["view"]`)
		issue("MCP policy author", `["view","manage_workflows"]`)
		id := b.id()
		b.seed(func() {
			seedCurrentMCPAgent(b, admin, id)
		})
		return repo, tokens["MCP inventory reader"], tokens["MCP policy author"], id
	}
	repo, a, writer, agentA := setup(first)
	_, b, _, agentB := setup(second)
	inventory, err := NewPostgresInventoryRepository(first.product)
	if err != nil {
		t.Fatal(err)
	}
	reads, err := newInventoryHTTPHandler(inventory, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	workflows, err := newWorkflowHTTPHandler(repo, bytes.Repeat([]byte{2}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	product, err := NewComposition(Dependencies{Authorizer: first.authorizer, Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: reads, Risk: handlerResponse("risk"), Workflow: workflows, Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://app.zasp.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(ctx context.Context, c Credential) (RequestIdentity, error) { return repo.Authenticate(ctx, c) }}, product)
	if err != nil {
		t.Fatal(err)
	}
	call := func(token, method, params string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "https://app.zasp.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct{ token, own, other string }{{a, agentA, agentB}, {b, agentB, agentA}} {
		w := call(tc.token, "tools/call", `{"name":"list_agents","arguments":{}}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.own) || strings.Contains(w.Body.String(), tc.other) {
			t.Fatalf("MCP scoped read %d %s", w.Code, w.Body)
		}
	}
	ref := first.id()
	draft := "policy-mcp-" + ref[4:]
	input := `{"name":"propose_policy","arguments":{"request_id":"` + ref + `","name":"Review file reads","tool_action":"read","effect":"monitor"}}`
	for _, token := range []string{a, b} {
		w := call(token, "tools/call", input)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "error") || strings.Contains(w.Body.String(), draft) {
			t.Fatalf("reader authorized draft: %s", w.Body)
		}
	}
	for range 2 {
		w := call(writer, "tools/call", input)
		if w.Code != 200 || !strings.Contains(w.Body.String(), draft) || !strings.Contains(w.Body.String(), "human_review_required") {
			t.Fatalf("persisted draft: %d %s", w.Code, w.Body)
		}
	}
	for _, tc := range []struct {
		token    string
		expected int
	}{{a, 200}, {b, 404}} {
		r := httptest.NewRequest("GET", "https://app.zasp.test/api/v1/policies/"+draft, nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		var resource struct {
			ID      string `json:"id"`
			Rollout string `json:"rollout"`
		}
		if w.Code != tc.expected || (w.Code == 200 && (json.Unmarshal(w.Body.Bytes(), &resource) != nil || resource.ID != draft || resource.Rollout != "draft")) {
			t.Fatalf("draft readback %d %s", w.Code, w.Body)
		}
	}
}

func seedCurrentMCPAgent(b *installedBaseline, principal installedPrincipal, id string) {
	digest := inventoryprojection.RuleCatalogDigest()
	seedTypedInventoryAgent(b.exec, b.o, b.w, b.e, principal.identity.PrincipalID.String(), id, b.id(), b.id(), b.id(), b.id(), hex.EncodeToString(digest[:]))
}
