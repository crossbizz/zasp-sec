package apiserver

import (
	"encoding/json"
	"testing"
)

func TestWorkforceInventoryRegistersLockedPurposeAndFindingReceipt(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	d := studioDefinition{Name: "New finding reviewer", Mission: "Track opened findings", Trigger: "finding_opened", Tools: []string{"get_posture_summary"}, Proposal: "none", Approval: true, Steps: 2}
	raw, _ := json.Marshal(d)
	rec := b.serve(surface, admin, "createCustomSecurityAgent", "POST", "/api/v1/security-agents/custom", nil, string(raw), map[string]string{"Idempotency-Key": b.id()})
	if rec.Code != 200 {
		t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	get := func(want int) {
		t.Helper()
		rec := b.serve(surface, admin, "listWorkforceInventory", "GET", "/api/v1/agents/workforce", nil, "", nil)
		var page struct {
			Items []struct {
				ID      string `json:"id"`
				Source  string `json:"source"`
				Mission string `json:"mission"`
				Count   int    `json:"trigger_receipts"`
			} `json:"items"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != created.ID || page.Items[0].Source != "studio" || page.Items[0].Mission != d.Mission || page.Items[0].Count != want {
			t.Fatalf("inventory %d: %s", rec.Code, rec.Body.String())
		}
	}
	get(0)
	finding := b.id()
	b.exec("INSERT INTO public.zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'prowler','review_needed','Review recorded access','high','open')", b.o, b.w, b.e, finding)
	get(1)
	b.exec("UPDATE public.zasp_risk_findings SET status='open' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)", b.o, b.w, b.e, finding)
	get(1)
}
