package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memberManagementRecorder struct {
	administrationRecorder
	operation string
	params    map[string]string
}

func (repo *memberManagementRecorder) ReadAdministration(_ context.Context, _ RequestIdentity, operation string, params map[string]string) (json.RawMessage, error) {
	repo.reads++
	repo.operation = operation
	repo.params = params
	switch operation {
	case "listMemberInvitations":
		return json.RawMessage(`{"items":[]}`), nil
	case "getMemberAccess":
		return json.Marshal(map[string]any{"member_id": params["id"], "items": []any{}})
	default:
		return nil, ErrRepositoryOperation
	}
}

func TestMemberManagementThroughProductRouter(t *testing.T) {
	const member = "pid_21000001-0000-4000-8000-000000000001"
	const invite = "/api/v1/admin/member-invitations"
	const memberPath = "/api/v1/admin/members/" + member
	const input = `{"display_name":"Jordan Lee","email":"Jordan.Lee+Zasp@Example.COM","role":"read_only_viewer"}`
	const key = "invite-member-test-01"

	repo := &memberManagementRecorder{}
	deps := auditExportCompositionDependencies()
	deps.Identity = &identityHTTPHandler{administration: repo}
	router, err := NewComposition(deps)
	if err != nil {
		t.Fatal(err)
	}
	admin := fixtureRequestIdentity(t)
	admin.Permissions = []string{"manage_identity"}
	call := func(method, path, body, version, idempotency string, identity RequestIdentity, scope, csrf bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", idempotency)
		request.Header.Set("If-Match", version)
		if scope {
			request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		}
		if csrf {
			request.Header.Set("Origin", "https://app.zasp.test")
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		}
		ctx := context.WithValue(request.Context(), identityContextKey{}, identity)
		ctx = context.WithValue(ctx, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request.WithContext(ctx))
		return response
	}

	response := call(http.MethodPost, invite, input, "", key, admin, true, true)
	if response.Code != http.StatusCreated || repo.mutations != 1 || repo.last.Operation != "inviteMember" || repo.last.Email != "jordan.lee+zasp@example.com" || repo.last.Name != "Jordan Lee" || repo.last.Role != "read_only_viewer" || repo.last.IdempotencyKey != key || !validAdministrationProductID(repo.last.ID) || !validAdministrationProductID(repo.last.AuditID) {
		t.Fatalf("invite = %d, mutation = %#v", response.Code, repo.last)
	}
	response = call(http.MethodPatch, memberPath+"/profile", `{"display_name":"Jordan Smith"}`, `"7"`, "", admin, true, true)
	if response.Code != http.StatusOK || repo.last.Operation != "updateMemberProfile" || repo.last.ID != member || repo.last.Name != "Jordan Smith" || repo.last.ExpectedVersion != 7 {
		t.Fatalf("profile change = %d, mutation = %#v", response.Code, repo.last)
	}
	response = call(http.MethodDelete, memberPath, "", `"8"`, "", admin, true, true)
	if response.Code != http.StatusOK || repo.last.Operation != "removeMember" || repo.last.ID != member || repo.last.ExpectedVersion != 8 {
		t.Fatalf("removal = %d, mutation = %#v", response.Code, repo.last)
	}
	response = call(http.MethodGet, invite+"?limit=10", "", "", "", admin, true, false)
	if response.Code != http.StatusOK || repo.operation != "listMemberInvitations" || repo.params["limit"] != "10" || !strings.Contains(response.Body.String(), `"has_more":false`) {
		t.Fatalf("invitation page = %d %s", response.Code, response.Body.String())
	}
	response = call(http.MethodGet, memberPath+"/access", "", "", "", admin, true, false)
	if response.Code != http.StatusOK || repo.operation != "getMemberAccess" || repo.params["id"] != member {
		t.Fatalf("access = %d %s", response.Code, response.Body.String())
	}

	stale, viewer, pat := admin, admin, admin
	stale.FreshAuthenticated = false
	viewer.Permissions = []string{"view"}
	pat.CredentialKind = CredentialBearerToken
	for _, example := range []struct {
		name, method, path, body, version, key string
		identity                               RequestIdentity
		scope, csrf                            bool
		status                                 int
	}{
		{"invite requires admin", "POST", invite, input, "", key, viewer, true, true, http.StatusForbidden},
		{"directory scope required", "GET", invite, "", "", "", admin, false, true, http.StatusConflict},
		{"access requires admin", "GET", memberPath + "/access", "", "", "", viewer, true, false, http.StatusForbidden},
		{"no machine credentials", "GET", memberPath + "/access", "", "", "", pat, true, false, http.StatusUnauthorized},
		{"fresh auth for removal", "DELETE", memberPath, "", `"8"`, "", stale, true, true, http.StatusForbidden},
		{"csrf for edits", "PATCH", memberPath + "/profile", `{"display_name":"Jordan"}`, `"8"`, "", admin, true, false, http.StatusForbidden},
		{"missing edit precondition", "PATCH", memberPath + "/profile", `{"display_name":"Jordan"}`, "", "", admin, true, true, http.StatusPreconditionRequired},
		{"remove with body", "DELETE", memberPath, `{}`, `"8"`, "", admin, true, true, http.StatusBadRequest},
		{"caller-selected scope", "POST", invite, strings.Replace(input, "{", `{"organization_id":"elsewhere",`, 1), "", key, admin, true, true, http.StatusBadRequest},
		{"invalid mailbox", "POST", invite, strings.Replace(input, "Jordan.Lee+Zasp@Example.COM", "Jordan Lee <jordan@example.com>", 1), "", key, admin, true, true, http.StatusBadRequest},
		{"invalid role", "POST", invite, strings.Replace(input, "read_only_viewer", "owner", 1), "", key, admin, true, true, http.StatusBadRequest},
		{"missing invite key", "POST", invite, input, "", "", admin, true, true, http.StatusBadRequest},
		{"empty profile", "PATCH", memberPath + "/profile", `{"display_name":" "}`, `"8"`, "", admin, true, true, http.StatusBadRequest},
		{"unknown member ID", "GET", "/api/v1/admin/members/bad/access", "", "", "", admin, true, false, http.StatusNotFound},
	} {
		t.Run(example.name, func(t *testing.T) {
			reads, writes := repo.reads, repo.mutations
			response := call(example.method, example.path, example.body, example.version, example.key, example.identity, example.scope, example.csrf)
			if response.Code != example.status || repo.reads != reads || repo.mutations != writes {
				t.Fatalf("%s %s = %d, want %d, reads=%d writes=%d: %s", example.method, example.path, response.Code, example.status, repo.reads-reads, repo.mutations-writes, response.Body.String())
			}
		})
	}
}
