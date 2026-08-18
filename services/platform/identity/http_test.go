package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestIdentityHTTPHandlerServesOrganizationScopeAndAdminOperations(t *testing.T) {
	store := newFixtureStore(t)
	organization, principal, workspace, environments := seedHTTPIdentity(t, store)
	handler, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principal, nil }, func() (domain.ProductID, error) {
		return fixtureID(t, 990), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	assertHTTPJSON(t, handler, http.MethodGet, "/api/v1/organization", "", http.StatusOK,
		`{"id":"`+organization.ID().String()+`","name":"Acme","domain":"acme.example"}`)
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/workspaces", "", http.StatusOK,
		`"id":"`+workspace.ID().String()+`"`, `"has_more":false`)

	createdWorkspace := requestObject(t, handler, http.MethodPost, "/api/v1/workspaces", `{"name":"Research"}`, http.StatusCreated)
	createdWorkspaceID := requireString(t, createdWorkspace, "id")
	if requireString(t, createdWorkspace, "audit_correlation_id") != fixtureID(t, 990).String() {
		t.Fatal("create workspace omitted the audit correlation ID")
	}
	firstWorkspacePage := requestObject(t, handler, http.MethodGet, "/api/v1/workspaces?limit=1", "", http.StatusOK)
	pageInfo := requireObject(t, firstWorkspacePage, "page_info")
	if pageInfo["has_more"] != true {
		t.Fatalf("first page = %#v", pageInfo)
	}
	nextCursor := requireString(t, pageInfo, "next_cursor")
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/workspaces?limit=1&cursor="+nextCursor, "", http.StatusOK,
		`"name":"Research"`, `"has_more":false`)
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/workspaces", "", http.StatusOK,
		`"name":"Default"`, `"name":"Research"`)
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/workspaces/"+createdWorkspaceID, "", http.StatusOK,
		`"name":"Research"`)
	assertHTTPContains(t, handler, http.MethodPatch, "/api/v1/workspaces/"+createdWorkspaceID, `{"name":"Platform"}`, http.StatusOK,
		`"name":"Platform"`)

	workspaceID := workspace.ID().String()
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/environments?workspace_id="+workspaceID, "", http.StatusOK,
		`"name":"production"`, `"name":"staging"`, `"name":"development"`)
	createdEnvironment := requestObject(t, handler, http.MethodPost, "/api/v1/environments",
		`{"workspace_id":"`+workspaceID+`","name":"sandbox"}`, http.StatusCreated)
	createdEnvironmentID := requireString(t, createdEnvironment, "id")
	requireString(t, createdEnvironment, "audit_correlation_id")
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/environments/"+createdEnvironmentID, "", http.StatusOK,
		`"name":"sandbox"`)
	assertHTTPContains(t, handler, http.MethodPatch, "/api/v1/environments/"+createdEnvironmentID, `{"name":"preview"}`, http.StatusOK,
		`"name":"preview"`)

	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/me", "", http.StatusOK,
		`"id":"`+principal.ID().String()+`"`, `"role":"organization_admin"`)
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/admin/members", "", http.StatusOK,
		`"member_reference":"member-live-a"`)
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/admin/roles", "", http.StatusOK,
		`"role":"organization_admin"`, `"permissions":["view","manage_identity"`, `"role":"read_only_viewer"`)

	if len(environments) != 3 {
		t.Fatalf("seed environments = %d", len(environments))
	}
}

func TestIdentityHTTPHandlerReturnsOneStableAuthenticationErrorForEveryOperation(t *testing.T) {
	store := newFixtureStore(t)
	_, _, workspace, environments := seedHTTPIdentity(t, store)
	errorID := fixtureID(t, 991)
	handler, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{}, errors.New("provider detail")
	}, func() (domain.ProductID, error) { return errorID, nil })
	if err != nil {
		t.Fatal(err)
	}

	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/organization", ""},
		{http.MethodGet, "/api/v1/workspaces", ""},
		{http.MethodPost, "/api/v1/workspaces", `{"name":"Research"}`},
		{http.MethodGet, "/api/v1/workspaces/" + workspace.ID().String(), ""},
		{http.MethodPatch, "/api/v1/workspaces/" + workspace.ID().String(), `{"name":"Platform"}`},
		{http.MethodGet, "/api/v1/environments?workspace_id=" + workspace.ID().String(), ""},
		{http.MethodPost, "/api/v1/environments", `{"workspace_id":"` + workspace.ID().String() + `","name":"sandbox"}`},
		{http.MethodGet, "/api/v1/environments/" + environments[0].ID().String(), ""},
		{http.MethodPatch, "/api/v1/environments/" + environments[0].ID().String(), `{"name":"prod"}`},
		{http.MethodGet, "/api/v1/me", ""},
		{http.MethodGet, "/api/v1/admin/members", ""},
		{http.MethodGet, "/api/v1/admin/roles", ""},
		{http.MethodGet, "/api/v1/admin/sso-connections", ""},
		{http.MethodPost, "/api/v1/admin/sso-connections", `{"display_name":"Corporate","protocol":"saml","identity_provider":"generic"}`},
		{http.MethodDelete, "/api/v1/admin/sso-connections/saml-connection-live-a", ""},
		{http.MethodPost, "/api/v1/admin/sso-connections/saml-connection-live-a/test", ""},
		{http.MethodGet, "/api/v1/admin/scim-connections", ""},
		{http.MethodPost, "/api/v1/admin/scim-connections", `{"display_name":"Corporate","identity_provider":"generic"}`},
		{http.MethodDelete, "/api/v1/admin/scim-connections/scim-connection-live-a", ""},
	}
	want := `{"code":"authentication_required","message":"Authentication required","correlation_id":"` + errorID.String() + `","retryable":false}`
	for _, route := range routes {
		recorder := performHTTPRequest(handler, route.method, route.path, route.body)
		if recorder.Code != http.StatusUnauthorized || strings.TrimSpace(recorder.Body.String()) != want {
			t.Fatalf("%s %s = %d %q", route.method, route.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestIdentityHTTPHandlerServesFreshAuthorizedSSOAndSCIMOperations(t *testing.T) {
	store := newFixtureStore(t)
	_, principal, _, _ := seedHTTPIdentity(t, store)
	driver := newFakeStytchDriver()
	driver.ssoConnections = nil
	driver.scimConnections = nil
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	connections, _ := NewConnectionService(adapter)
	freshCalls := 0
	handler, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principal, nil }, func() (domain.ProductID, error) {
		return fixtureID(t, 992), nil
	}, WithConnectionService(connections, func(context.Context, Principal) error {
		freshCalls++
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	createdSSO := requestObject(t, handler, http.MethodPost, "/api/v1/admin/sso-connections",
		`{"display_name":"Corporate SAML","protocol":"saml","identity_provider":"generic"}`, http.StatusCreated)
	ssoID := requireString(t, createdSSO, "id")
	requireString(t, createdSSO, "audit_correlation_id")
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/admin/sso-connections", "", http.StatusOK,
		`"id":"`+ssoID+`"`, `"display_name":"Corporate SAML"`)
	assertHTTPContains(t, handler, http.MethodPost, "/api/v1/admin/sso-connections/"+ssoID+"/test", "", http.StatusOK,
		`"healthy":true`, `"audit_correlation_id"`)
	assertHTTPContains(t, handler, http.MethodDelete, "/api/v1/admin/sso-connections/"+ssoID, "", http.StatusOK,
		`"id":"`+ssoID+`"`, `"audit_correlation_id"`)

	createdSCIM := requestObject(t, handler, http.MethodPost, "/api/v1/admin/scim-connections",
		`{"display_name":"Corporate SCIM","identity_provider":"generic"}`, http.StatusCreated)
	scimID := requireString(t, createdSCIM, "id")
	if requireString(t, createdSCIM, "bearer_token") != "scim_bearer_token_fixture" {
		t.Fatal("SCIM create omitted the one-time bearer token")
	}
	assertHTTPContains(t, handler, http.MethodGet, "/api/v1/admin/scim-connections", "", http.StatusOK,
		`"id":"`+scimID+`"`, `"base_url":"https://scim.example.invalid/v2"`)
	assertHTTPContains(t, handler, http.MethodDelete, "/api/v1/admin/scim-connections/"+scimID, "", http.StatusOK,
		`"id":"`+scimID+`"`, `"audit_correlation_id"`)
	if freshCalls != 5 {
		t.Fatalf("fresh authorization calls = %d", freshCalls)
	}
}

func TestIdentityHTTPHandlerFailsClosedBeforeSensitiveConnectionMutation(t *testing.T) {
	store := newFixtureStore(t)
	_, principal, _, _ := seedHTTPIdentity(t, store)
	driver := newFakeStytchDriver()
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	connections, _ := NewConnectionService(adapter)
	handler, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principal, nil }, func() (domain.ProductID, error) {
		return fixtureID(t, 993), nil
	}, WithConnectionService(connections, func(context.Context, Principal) error { return ErrFreshAuthentication }))
	if err != nil {
		t.Fatal(err)
	}
	recorder := performHTTPRequest(handler, http.MethodPost, "/api/v1/admin/sso-connections",
		`{"display_name":"Corporate SAML","protocol":"saml","identity_provider":"generic"}`)
	if recorder.Code != http.StatusForbidden || len(driver.ssoConnections) != 1 {
		t.Fatalf("fresh rejection = %d %q provider_count=%d", recorder.Code, recorder.Body.String(), len(driver.ssoConnections))
	}
}

func seedHTTPIdentity(t *testing.T, store *MemoryStore) (Organization, Principal, Workspace, []Environment) {
	t.Helper()
	organization, err := store.ReconcileOrganization(context.Background(), ExternalOrganization{
		Reference: "organization-live-a", Name: "Acme", Domain: "acme.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := store.ReconcilePrincipal(context.Background(), organization.ID(), mustExternalPrincipal(t, driverFixtureSession()), RoleOrganizationAdmin)
	if err != nil {
		t.Fatal(err)
	}
	workspace, environments, err := store.EnsureDefaultScopes(context.Background(), organization.ID())
	if err != nil {
		t.Fatal(err)
	}
	return organization, principal, workspace, environments
}

func performHTTPRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func assertHTTPJSON(t *testing.T, handler http.Handler, method, path, body string, status int, want string) {
	t.Helper()
	recorder := performHTTPRequest(handler, method, path, body)
	if recorder.Code != status || strings.TrimSpace(recorder.Body.String()) != want {
		t.Fatalf("%s %s = %d %q, want %d %s", method, path, recorder.Code, recorder.Body.String(), status, want)
	}
}

func assertHTTPContains(t *testing.T, handler http.Handler, method, path, body string, status int, fragments ...string) {
	t.Helper()
	recorder := performHTTPRequest(handler, method, path, body)
	if recorder.Code != status {
		t.Fatalf("%s %s status = %d body = %q", method, path, recorder.Code, recorder.Body.String())
	}
	for _, fragment := range fragments {
		if !strings.Contains(recorder.Body.String(), fragment) {
			t.Fatalf("%s %s body %q lacks %q", method, path, recorder.Body.String(), fragment)
		}
	}
}

func requestObject(t *testing.T, handler http.Handler, method, path, body string, status int) map[string]any {
	t.Helper()
	recorder := performHTTPRequest(handler, method, path, body)
	if recorder.Code != status {
		t.Fatalf("%s %s status = %d body = %q", method, path, recorder.Code, recorder.Body.String())
	}
	var value map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func requireString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok || value == "" {
		t.Fatalf("%s = %#v", key, object[key])
	}
	return value
}

func requireObject(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v", key, object[key])
	}
	return value
}
