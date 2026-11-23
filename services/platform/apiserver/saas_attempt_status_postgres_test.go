package apiserver

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestV3SaaSSignInAttemptOnInstalledBaseline(t *testing.T) {
	b := startInstalledV2Baseline(t)
	owner := b.member("security_admin", "view", "manage_workflows")
	peer := b.member("security_admin", "view", "manage_workflows")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	integration, attempt := b.id(), b.id()
	user := owner.identity.PrincipalID.String()
	cookie := "session-secret-" + user
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	b.seed(func() {
		b.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Sign in','connector_key','saas','configuration',jsonb_build_object('platform','servicenow','tenant_id','acme'),'status','pending_authorization'))`, b.o, b.w, b.e, integration)
		b.exec(`INSERT INTO zasp_saas_sign_in_attempts(organization_id,workspace_id,environment_id,id,integration_id,integration_version,platform,tenant_id,principal_id,session_digest,state_hash,status,connection_reference,consumed_at,finished_at,expires_at) VALUES($1,$2,$3,$4,$5,1,'servicenow','acme',$6,$7,$8,'completed',$9,now(),now(),now()+interval '5 minutes')`, b.o, b.w, b.e, attempt, integration, user, connectorDigest(cookie), connectorDigest(attempt), reference)
	})
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	read := func(p installedPrincipal, id, session string, status int) {
		t.Helper()
		resp := b.serve(surface, p, "getSaaSSignInAttempt", http.MethodGet, "/api/v1/integrations/"+integration+"/sign-in-attempts/"+id, map[string]string{"id": integration, "attemptId": id}, "", map[string]string{"Cookie": browserSessionCookie + "=" + session})
		if resp.Code != status || resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("read attempt: %d %s", resp.Code, resp.Body.String())
		}
		if status == http.StatusOK {
			var result struct {
				Attempt     string `json:"attempt_id"`
				Integration string `json:"integration_id"`
				Reference   string `json:"connection_reference"`
				Status      string `json:"status"`
			}
			if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil || result.Attempt != attempt || result.Integration != integration || result.Reference != reference || result.Status != "completed" {
				t.Fatalf("callback readback: %s, %v", resp.Body.String(), err)
			}
		}
	}
	read(owner, attempt, cookie, http.StatusOK)
	read(owner, attempt, "different-session", http.StatusNotFound)
	read(peer, attempt, "session-secret-"+peer.identity.PrincipalID.String(), http.StatusNotFound)
	read(owner, b.id(), cookie, http.StatusNotFound)
	b.seed(func() {
		b.exec(`UPDATE zasp_saas_sign_in_attempts SET created_at=now()-interval '10 minutes',expires_at=now()-interval '1 minute' WHERE id=$1`, attempt)
	})
	read(owner, attempt, cookie, http.StatusNotFound)
}
