package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDeploymentReviewReopensOnPurposeAccessAndRoleDrift(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	exerciseDeploymentReview(t, b, admin, b.id())
}

func exerciseDeploymentReview(t *testing.T, b *installedBaseline, admin installedPrincipal, agent string) {
	t.Helper()
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	version, role := b.id(), b.id()
	digest := "sha256:" + strings.Repeat("c", 64)
	b.seed(func() {
		b.exec("INSERT INTO zasp_addon_versions(organization_id,workspace_id,environment_id,id,manifest_digest,origin,origin_credential,ruleset,findings,review_state) VALUES($1,$2,$3,$4,$5,'local',$6,'zasp-static.v2','[]','approved')", b.o, b.w, b.e, version, digest, b.id())
		for id, kind := range map[string]string{agent: "agent", role: "identity"} {
			b.exec("INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_provider) VALUES($1,$2,$3,$4,$5,'registered','{}',now(),now(),$5,'github')", b.o, b.w, b.e, id, kind)
		}
		b.exec("INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,'aws',$6,$7,$8,'uses_identity','role',now(),now())", b.o, b.w, b.e, b.id(), b.id(), b.id(), agent, role)
		b.exec("INSERT INTO zasp_agent_purpose_versions(organization_id,workspace_id,environment_id,agent_id,revision,actor,request_key,allowed_tool_ids) VALUES($1,$2,$3,$4,1,$5,$6,'[]')", b.o, b.w, b.e, agent, b.id(), b.id())
	})
	access := func(n int, destination string) {
		b.seed(func() {
			b.exec("INSERT INTO zasp_action_analysis_versions(organization_id,workspace_id,environment_id,agent_id,revision,actor,request_key,settings) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)", b.o, b.w, b.e, agent, n, b.id(), b.id(), fmt.Sprintf(`{"allowed_destinations":[%q],"allowed_operations":[],"allowed_classifications":[],"blocked_transitions":[]}`, destination))
		})
	}
	purpose := b.serve(surface, admin, "getAgentPurpose", http.MethodGet, "/api/v1/agents/"+agent+"/purpose", map[string]string{"id": agent}, "", nil)
	var approved agentPurpose
	if purpose.Code != 200 || json.Unmarshal(purpose.Body.Bytes(), &approved) != nil || approved.AgentID != agent || approved.Revision != 1 {
		t.Fatalf("missing registered purpose: %d %s", purpose.Code, purpose.Body)
	}
	var last map[string]any
	params := map[string]string{"id": version}
	path := "/api/v1/addon-versions/" + version + "/deployment-approvals?agent_id=" + agent
	read := func(state string) {
		t.Helper()
		r := b.serve(surface, admin, "getAddonDeploymentApproval", http.MethodGet, path, params, "", nil)
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &last) != nil || last["state"] != state {
			t.Fatalf("expected %s: %d %s", state, r.Code, r.Body.String())
		}
	}
	post := func(rev int, key string, contextDigest any, want int) {
		t.Helper()
		input, _ := json.Marshal(map[string]any{"state": "approved", "permission_context_digest": contextDigest})
		r := b.serve(surface, admin, "reviewAddonDeploymentApproval", http.MethodPost, path, params, string(input), map[string]string{"Idempotency-Key": key, "If-Match": fmt.Sprintf(`"%d"`, rev)})
		if r.Code != want {
			t.Fatalf("decision got %d, want %d: %s", r.Code, want, r.Body.String())
		}
	}
	read("pending")
	post(0, b.id(), last["permission_context_digest"], 409)
	access(1, "internal")
	read("pending")
	first := last["permission_context_digest"]
	key := b.id()
	post(0, key, first, 200)
	read("approved")
	access(2, "external")
	read("needs_re_review")
	post(0, key, first, 200) // An idempotent replay cannot restore the old authority.
	read("needs_re_review")
	post(1, b.id(), first, 409)
	post(1, b.id(), last["permission_context_digest"], 200)
	read("approved")
	b.seed(func() {
		b.exec("UPDATE zasp_inventory_entities SET winning_attributes=jsonb_build_object('permission','write') WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)", b.o, b.w, b.e, role)
	})
	read("needs_re_review")
	post(2, b.id(), last["permission_context_digest"], 200)
	b.seed(func() {
		b.exec("INSERT INTO zasp_agent_purpose_versions(organization_id,workspace_id,environment_id,agent_id,revision,actor,request_key,allowed_tool_ids) VALUES($1,$2,$3,$4,2,$5,$6,jsonb_build_array($7::text))", b.o, b.w, b.e, agent, b.id(), b.id(), b.id())
	})
	read("needs_re_review")
	route := RoutedOperation{OperationID: "getAddonDeploymentApproval", PathParameters: params}
	b.refused[admin.identity.PrincipalID.String()+" view"] = true
	defer delete(b.refused, admin.identity.PrincipalID.String()+" view")
	if _, err := b.checkedQuery(admin, route, url.Values{"agent_id": []string{agent}}); err == nil {
		t.Fatal("refused view granted")
	}
}
