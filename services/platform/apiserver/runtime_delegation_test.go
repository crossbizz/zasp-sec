package apiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation/issuer"
)

func TestRuntimeDelegationOnInstalledPostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "manage_api_tokens", "manage_identity", "manage_workflows", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	newToken, _ := installedWorkloadTokenIssuer(t, b, repo, admin)
	parent := newToken("Delegation parent", `["use_gateway"]`)
	child := newToken("Delegation child", `["use_gateway","decide_actions"]`)
	peer := newToken("Delegation peer", `["use_gateway"]`)
	parentID, childID, peerID := b.id(), b.id(), b.id()
	b.seed(func() {
		for _, id := range []string{parentID, childID, peerID} {
			b.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind)
VALUES($1,$2,$3,$4,'agent','helper','{"name":"helper"}',now(),now(),'agent')`, b.o, b.w, b.e, id)
		}
	})
	h := workloadActionHandler{database: b.product, newProductID: newWorkflowProductID}
	binder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		h.binding(w, r, op)
	})
	for _, a := range []struct{ cred, id string }{{parent.binding.ID, parentID}, {child.binding.ID, childID}, {peer.binding.ID, peerID}} {
		res := b.serve(binder, admin, "bindWorkloadCredential", "PUT", "/api/v1/runtime/workload-bindings/"+a.cred, map[string]string{"id": a.cred}, `{"agent_id":"`+a.id+`"}`, nil)
		if res.Code != 200 {
			t.Fatalf("bind %d %s", res.Code, res.Body.String())
		}
	}
	tenant := delegation.Tenant{Organization: b.o, Workspace: b.w, Environment: b.e}
	scope := delegation.Scope{Operations: []string{"draft_reply"}, Resources: []string{"inbox"}}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := issuer.NewAuthority(issuer.Configuration{Seed: key.Seed(), Agents: []issuer.Agent{
		{Tenant: tenant, ID: parentID, Credential: parent.binding.ID, Purpose: scope},
		{Tenant: tenant, ID: childID, Credential: child.binding.ID, Delegated: true, Purpose: scope},
		{Tenant: tenant, ID: peerID, Credential: peer.binding.ID, Delegated: true, Purpose: scope},
	}, Tasks: []issuer.Task{{Binding: delegation.Binding{Tenant: tenant, Task: "task-1", Agent: parentID}, Scope: scope, MaxDepth: 2}},
		Policies: []issuer.Policy{{Tenant: tenant, Scope: scope}}})
	if err != nil {
		t.Fatal(err)
	}
	host := &hostedGatewayHandler{database: b.product, authority: authority}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		host.ServeHTTP(w, r, op)
	})
	q := issuer.IssueRequest{Scope: scope, Task: "task-1", Child: childID, MaxDepth: 2, TTL: 60}
	payload, _ := json.Marshal(q)
	grantResponse := b.serve(surface, parent, "issueRuntimeDelegation", "POST", "/api/v1/runtime/delegations/issue", nil, string(payload), nil)
	var grant issuer.Grant
	if grantResponse.Code != 200 || json.Unmarshal(grantResponse.Body.Bytes(), &grant) != nil || grant.Token == "" {
		t.Fatalf("issue %d %s", grantResponse.Code, grantResponse.Body.String())
	}
	admit := func(c installedPrincipal, token, op, status string) {
		t.Helper()
		v, _ := json.Marshal(verifyDelegation{Task: q.Task, Token: token, Operation: op, Resource: "inbox"})
		r := b.serve(surface, c, "verifyRuntimeDelegation", "POST", "/api/v1/runtime/delegations/verify", nil, string(v), nil)
		var d delegation.Decision
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &d) != nil || d.Status != status || d.Allowed != (status == "verified") {
			t.Fatalf("verify %d %s", r.Code, r.Body.String())
		}
	}
	admit(child, grant.Token, "draft_reply", "verified")
	admit(child, grant.Token, "send_reply", "denied")
	admit(child, "", "draft_reply", "delegation_unverified")
	records := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		serveWorkloadDelegations(b.product, w, r, op)
	})
	read := func(id string) *httptest.ResponseRecorder {
		return b.serve(records, admin, "getWorkloadDelegations", "GET", "/api/v1/runtime/workload-bindings/"+id+"/delegations", map[string]string{"id": id}, "", nil)
	}
	resp := read(child.binding.ID)
	var page delegationPage
	if resp.Code != 200 || json.Unmarshal(resp.Body.Bytes(), &page) != nil || page.Agent != childID || len(page.Items) != 3 || len(page.Items[0].Grants) != 0 || len(page.Items[2].Grants) != 1 || page.Items[2].Grants[0].Child != childID {
		t.Fatalf("read %d %s", resp.Code, resp.Body)
	}
	if resp := read(b.id()); resp.Code != http.StatusNotFound {
		t.Fatalf("unbound credential %d", resp.Code)
	}
	if n := b.text(`SELECT count(*)::text FROM public.delegation_receipts WHERE (organization_id,workspace_id,environment_id,parent_task_id)=($1,$2,$3,'task-1')`, b.o, b.w, b.e); n != "4" {
		t.Fatalf("receipts %s", n)
	}
	q.Child, q.ParentToken, q.TTL = peerID, grant.Token, 30
	payload, _ = json.Marshal(q)
	issued := b.serve(surface, child, "issueRuntimeDelegation", "POST", "/api/v1/runtime/delegations/issue", nil, string(payload), nil)
	var next issuer.Grant
	if issued.Code != 200 || json.Unmarshal(issued.Body.Bytes(), &next) != nil || next.Depth != 2 {
		t.Fatalf("child grant %d %s", issued.Code, issued.Body)
	}
	admit(peer, next.Token, "draft_reply", "verified")
	resp = read(peer.binding.ID)
	if resp.Code != 200 || json.Unmarshal(resp.Body.Bytes(), &page) != nil || len(page.Items) != 1 || len(page.Items[0].Grants) != 2 ||
		page.Items[0].Grants[0].Parent != parentID || page.Items[0].Grants[1].Child != peerID {
		t.Fatalf("delegation chain %d %s", resp.Code, resp.Body)
	}

}

func TestDelegationTrafficRejectsUnconfiguredGrant(t *testing.T) {
	h := &hostedGatewayHandler{}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(delegation.Header, "invalid")
	if h.delegationTraffic(httptest.NewRecorder(), r, RequestIdentity{}, RoutedOperation{OperationID: "callMCPGateway"}, nil) {
		t.Fatal("unconfigured delegated request forwarded")
	}
}
