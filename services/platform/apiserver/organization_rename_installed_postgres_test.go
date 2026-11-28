package apiserver

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestOrganizationRenameInstalled(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("organization_admin", "manage_identity", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	handler := &identityHTTPHandler{administration: repo}
	domain := b.text("SELECT domain FROM public.zasp_organizations WHERE id=$1", b.o)
	patch := func(body, tag string, status int) {
		t.Helper()
		response := b.serve(handler, admin, "updateOrganization", http.MethodPatch, "/api/v1/organization", nil, body, map[string]string{"If-Match": tag, "X-Zasp-Fresh-Auth": "confirmed"})
		if response.Code != status {
			t.Fatalf("rename response %d (want %d): %s", response.Code, status, response.Body.String())
		}
		if status == http.StatusOK {
			var result struct {
				ID, Name, Domain string
				Version          int
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.ID != b.o || result.Name != "Research" || result.Domain != domain || result.Version != 2 || response.Header().Get("ETag") != `"2"` {
				t.Fatalf("renamed organization: %s", response.Body.String())
			}
		}
	}
	patch(`{"name":"Research"}`, "", http.StatusPreconditionRequired)
	patch(`{"name":"Research","domain":"other.example"}`, `"1"`, http.StatusBadRequest)
	patch(`{"name":"Research"}`, `"1"`, http.StatusOK)
	patch(`{"name":"Stale edit"}`, `"1"`, http.StatusConflict)
	if got := b.text("SELECT name FROM public.zasp_organizations WHERE id=$1", b.o); got != "Research" {
		t.Fatalf("stored display name %q", got)
	}
	if got := b.text("SELECT count(*)::text FROM public.zasp_admin_audit WHERE organization_id=$1 AND target_id=$1 AND action='organization.update' AND actor_id=$2", b.o, admin.identity.PrincipalID.String()); got != "1" {
		t.Fatalf("audit count %s", got)
	}
}
