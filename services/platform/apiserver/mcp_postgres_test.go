package apiserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductMCPTenantIsolatedAgentListingOnInstalledPostgres(t *testing.T) {
	first, second := startInstalledV2Baseline(t), startInstalledV2Baseline(t)
	setup := func(b *installedBaseline) (*PostgresRepository, string, string) {
		t.Helper()
		if err := b.product.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		repo, err := NewPostgresRepository(b.product)
		if err != nil {
			t.Fatal(err)
		}
		admin := b.member("security_admin", "manage_api_tokens", "manage_identity", "view")
		issue, tokens := installedWorkloadTokenIssuer(t, b, repo, admin)
		issue("MCP inventory reader", `["view"]`)
		id := b.id()
		b.seed(func() {
			b.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind)
VALUES($1,$2,$3,$4,'agent','MCP audit agent','{"name":"audit-agent"}',now(),now(),'agent')`, b.o, b.w, b.e, id)
		})
		return repo, tokens["MCP inventory reader"], id
	}
	repo, a, agentA := setup(first)
	_, b, agentB := setup(second)
	inventory, err := NewPostgresInventoryRepository(first.product)
	if err != nil {
		t.Fatal(err)
	}
	reads, err := newInventoryHTTPHandler(inventory, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	product, err := NewComposition(Dependencies{Authorizer: first.authorizer, Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: reads, Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://app.zasp.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(ctx context.Context, c Credential) (RequestIdentity, error) { return repo.Authenticate(ctx, c) }}, product)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ token, own, other string }{{a, agentA, agentB}, {b, agentB, agentA}} {
		r := httptest.NewRequest("POST", "https://app.zasp.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_agents","arguments":{}}}`))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.own) || strings.Contains(w.Body.String(), tc.other) {
			t.Fatalf("MCP scoped read %d %s", w.Code, w.Body)
		}
	}
}
