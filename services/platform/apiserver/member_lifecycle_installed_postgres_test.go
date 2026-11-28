package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Use the real callback adapter, API service login and installed database.
// Only the external provider is replaced by a local HTTP service.
func TestMemberLifecycleInstalled(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("organization_admin", "manage_identity", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	orgRef := "organization-" + b.o[4:12]
	memberRef := "member-test-" + b.id()[4:]
	const email = "jordan@example.test"
	var deliveries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/b2b/organizations/members/search":
			_, _ = w.Write([]byte(`{"status_code":200,"members":[]}`))
		case "/v1/b2b/magic_links/email/invite":
			deliveries.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"status_code": 200, "member": map[string]string{"member_id": memberRef, "organization_id": orgRef, "email_address": email, "status": "invited"}})
		case "/v1/b2b/magic_links/authenticate":
			var request struct {
				Token string `json:"magic_links_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Token != "invitation" && request.Token != "other" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status_code": 200, "session_jwt": "header." + request.Token + ".signature"})
		case "/v1/b2b/sessions/authenticate":
			var request struct {
				JWT string `json:"session_jwt"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			verified := memberRef
			if request.JWT != "header.invitation.signature" {
				verified = "member-other"
			}
			now := time.Now().UTC().Truncate(time.Second)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status_code":    200,
				"member_session": map[string]string{"member_session_id": "member-session-" + verified, "member_id": verified, "organization_id": orgRef, "started_at": now.Format(time.RFC3339), "last_accessed_at": now.Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339)},
				"member":         map[string]string{"member_id": verified, "organization_id": orgRef},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	deployment := authorization.IdentityDeployment{PublicOrigin: "https://console.example", ProviderBaseURL: server.URL, ProjectID: "project-member-test", ConfiguredOrganization: orgRef, Mode: "saas"}
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }
	auth, err := NewStytchOAuthAuthenticator(server.URL, deployment.ProjectID, "fixture-secret", 5*time.Second, clock)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewRepositoryIdentityProviderWithStart(auth, repo, repo, server.URL+"/v1/b2b/public/oauth/google/start", "public-token-fixture", orgRef, deployment.PublicOrigin+"/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("session-admission-member-test-seed-0123456789")
	sessionKey, err := authorization.NewIdentitySessionKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	webhookKey, err := authorization.NewIdentityWebhookKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	audience, err := deployment.Audience()
	if err != nil {
		t.Fatal(err)
	}
	operator := b.login("zasp_operator")
	for _, key := range []struct {
		purpose, version string
		verifier         []byte
	}{{"session", sessionKey.Version(), sessionKey.Verifier()}, {"webhook", webhookKey.Version(), webhookKey.Verifier()}} {
		if _, err := operator.Exec(b.ctx, "SELECT zasp_authorization80_identity.register_"+key.purpose+"($1,$2,$3,$4,'zasp_svc_api','')", key.version, key.verifier, audience, deployment.ProjectID); err != nil {
			t.Fatal(err)
		}
	}
	if err := provider.RequireNativeIdentity(seed, deployment); err != nil {
		t.Fatal(err)
	}
	repo.memberDirectory = provider
	handler := &identityHTTPHandler{administration: repo, now: clock}
	call := func(op, method, path, id, body string, headers map[string]string, want int) string {
		t.Helper()
		params := map[string]string{}
		if id != "" {
			params["id"] = id
		}
		r := b.serve(handler, admin, op, method, path, params, body, headers)
		if r.Code != want {
			t.Fatalf("%s status %d, want %d: %s", op, r.Code, want, r.Body.String())
		}
		return r.Body.String()
	}
	const invites = "/api/v1/admin/member-invitations"
	inviteBody := `{"email":"jordan@example.test","display_name":"Jordan","role":"read_only_viewer"}`
	headers := map[string]string{"Idempotency-Key": b.id(), "X-Zasp-Fresh-Auth": "confirmed"}
	for i := 0; i < 2; i++ {
		call("inviteMember", "POST", invites, "", inviteBody, headers, http.StatusCreated)
	}
	if deliveries.Load() != 1 {
		t.Fatalf("invitation deliveries %d", deliveries.Load())
	}
	if _, err := provider.CompleteInvitation(b.ctx, "other"); err == nil {
		t.Fatal("another verified member consumed the invitation")
	}
	if response := call("listMemberInvitations", "GET", invites, "", "", nil, 200); !strings.Contains(response, email) {
		t.Fatal("pending invitation missing")
	}
	// A directory identity is insufficient after the product invitation expires.
	b.exec("UPDATE public.zasp_member_invitations SET expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND email=$2", b.o, email)
	if _, err := provider.CompleteInvitation(b.ctx, "invitation"); err == nil {
		t.Fatal("expired invitation accepted")
	}
	if response := call("listMemberInvitations", "GET", invites, "", "", nil, 200); strings.Contains(response, email) {
		t.Fatal("expired invitation listed as pending")
	}
	headers["Idempotency-Key"] = b.id()
	call("inviteMember", "POST", invites, "", inviteBody, headers, 201)
	if deliveries.Load() != 2 {
		t.Fatal("expired invitation did not send a new link")
	}
	grant, err := provider.CompleteInvitation(b.ctx, "invitation")
	if err != nil {
		t.Fatal(err)
	}
	token, err := repo.CreateSession(b.ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Authenticate(b.ctx, Credential{Kind: CredentialBrowserSession, Value: token}); err != nil {
		t.Fatal(err)
	}
	if response := call("listMemberInvitations", "GET", invites, "", "", nil, 200); strings.Contains(response, email) {
		t.Fatal("accepted invitation remained pending")
	}
	id := grant.PrincipalID.String()
	memberPath := "/api/v1/admin/members/" + id
	access := call("getMemberAccess", "GET", memberPath+"/access", id, "", nil, 200)
	if !strings.Contains(access, b.e) || !strings.Contains(access, "read_only_viewer") {
		t.Fatalf("initial access: %s", access)
	}
	edit := map[string]string{"If-Match": `"1"`, "X-Zasp-Fresh-Auth": "confirmed"}
	call("updateMemberProfile", "PATCH", memberPath+"/profile", id, `{"display_name":"Jordan Smith"}`, edit, 200)
	call("removeMember", "DELETE", memberPath, id, "", edit, 409)
	edit["If-Match"] = `"2"`
	addResourceGrant := func() {
		b.exec("INSERT INTO zasp_authorization79.grants(organization_id,workspace_id,environment_id,kind,id,principal_kind,principal_id,permission) VALUES($1,$2,$3,'finding',$4,'user',$5,'manage_findings')", b.o, b.w, b.e, b.id(), id)
	}
	assertNoResourceGrants := func() {
		t.Helper()
		if got := b.text("SELECT count(*)::text FROM zasp_authorization79.grants WHERE organization_id=$1 AND principal_kind='user' AND principal_id=$2", b.o, id); got != "0" {
			t.Fatalf("resource grants retained: %s", got)
		}
	}
	addResourceGrant()
	call("removeMember", "DELETE", memberPath, id, "", edit, 200)
	assertNoResourceGrants()
	if _, err = repo.Authenticate(b.ctx, Credential{Kind: CredentialBrowserSession, Value: token}); err == nil {
		t.Fatal("removed member still authenticated")
	}
	if _, err = provider.CompleteInvitation(b.ctx, "invitation"); err == nil {
		t.Fatal("old invitation reactivated a removed member")
	}
	// Older provider deprovisioning could leave dormant resource grants.
	addResourceGrant()
	headers["Idempotency-Key"] = b.id()
	call("inviteMember", "POST", invites, "", inviteBody, headers, 201)
	rejoined, err := provider.CompleteInvitation(b.ctx, "invitation")
	if err != nil || rejoined.PrincipalID != grant.PrincipalID {
		t.Fatalf("reactivation: %v", err)
	}
	assertNoResourceGrants()
	adminID := admin.identity.PrincipalID.String()
	adminPath := "/api/v1/admin/members/" + adminID
	versionOne := map[string]string{"If-Match": `"1"`, "X-Zasp-Fresh-Auth": "confirmed"}
	call("removeMember", "DELETE", adminPath, adminID, "", versionOne, http.StatusConflict)
	call("updateMemberRole", "PATCH", adminPath, adminID, `{"role":"read_only_viewer"}`, versionOne, http.StatusConflict)
	if role := b.text("SELECT role FROM public.zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 AND active", b.o, adminID); role != "organization_admin" {
		t.Fatalf("last administrator changed: %q", role)
	}
}
