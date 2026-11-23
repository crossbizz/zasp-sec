package apiserver

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestCustomStudioRevisionProofOnInstalledDatabase(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	path := "/api/v1/security-agents/custom"
	key := b.id()
	d := studioDefinition{Name: "Case review", Mission: "Read deployment evidence", Trigger: "manual", Tools: []string{"inspect_session"}, Proposal: "none", Approval: true, Steps: 3}
	save := func(op, method, url string, params map[string]string, key string, n int, want int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(d)
		headers := map[string]string{"Idempotency-Key": key}
		if n >= 0 {
			headers["If-Match"] = fmt.Sprintf(`"%d"`, n)
		}
		rec := b.serve(surface, admin, op, method, url, params, string(raw), headers)
		if rec.Code != want {
			t.Fatalf("%s: %d expected %d %s", op, rec.Code, want, rec.Body.String())
		}
		var result map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &result) != nil {
			t.Fatal("invalid response")
		}
		return result
	}
	first := save("createCustomSecurityAgent", "POST", path, nil, key, -1, 200)
	id := first["id"].(string)
	if again := save("createCustomSecurityAgent", "POST", path, nil, key, -1, 200); again["id"] != id || again["revision"] != float64(1) {
		t.Fatal(again)
	}
	d.Approval = false
	save("createCustomSecurityAgent", "POST", path, nil, b.id(), -1, 400)
	d.Approval = true
	d.Model = "unqualified"
	d.Budget = 100
	save("createCustomSecurityAgent", "POST", path, nil, b.id(), -1, 409)
	d.Model = ""
	d.Budget = 0
	d.Mission = "Read the latest case receipts"
	save("createCustomSecurityAgent", "POST", path, nil, key, -1, 409)
	params := map[string]string{"id": id}
	if row := save("updateCustomSecurityAgent", "PUT", path+"/"+id, params, b.id(), 1, 200); row["revision"] != float64(2) {
		t.Fatal(row)
	}
	save("updateCustomSecurityAgent", "PUT", path+"/"+id, params, b.id(), 1, 409)
	rec := b.serve(surface, admin, "getCustomSecurityAgent", "GET", path+"/"+id, params, "", nil)
	if rec.Code != 200 || rec.Header().Get("ETag") != `"2"` {
		t.Fatalf("read %d: %s", rec.Code, rec.Body.String())
	}
	rec = b.serve(surface, admin, "listCustomSecurityAgents", "GET", path+"?limit=1", nil, "", nil)
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != id || page.Next != nil {
		t.Fatalf("page %d %s", rec.Code, rec.Body.String())
	}
	if old := b.text("SELECT zasp_authorization80.studio_revision($1,$2,$3,$4,1)#>>'{definition,mission}'", b.o, b.w, b.e, id); old != "Read deployment evidence" {
		t.Fatal(old)
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getCustomSecurityAgent", PathParameters: params}, studioGetSQL, b.o, b.w, b.id(), id); installedSQLState(err) != "42501" {
		t.Fatal("scope fence", err)
	}
}

func TestCustomStudioValidatesBoundedToolsAndAuthority(t *testing.T) {
	good := studioDefinition{Name: "Review", Mission: "Inspect session evidence", Trigger: "manual", Tools: []string{"inspect_session"}, Proposal: "propose_policy", Approval: true, Steps: 3, Budget: 100}
	if !good.valid() {
		t.Fatal("valid workflow rejected")
	}
	for _, change := range []func(*studioDefinition){
		func(d *studioDefinition) { d.Steps = 7 }, func(d *studioDefinition) { d.Steps = 0 }, func(d *studioDefinition) { d.Approval = false },
		func(d *studioDefinition) { d.Tools = []string{"write_policy"} }, func(d *studioDefinition) { d.Tools = []string{"inspect_session", "inspect_session"} },
		func(d *studioDefinition) { d.Proposal = "execute" }, func(d *studioDefinition) { d.Budget = 1000000000001 },
	} {
		d := good
		change(&d)
		if d.valid() {
			t.Fatalf("admitted %+v", d)
		}
	}
}
