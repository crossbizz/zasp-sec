package identity

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	platformaudit "github.com/zasp-ai/zasp-sec/services/platform/audit"
	platformconfig "github.com/zasp-ai/zasp-sec/services/platform/config"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestM2IdentityTokenAndAuditLifecycle(t *testing.T) {
	store := newFixtureStore(t)
	organization, principal, workspace, environments := seedHTTPIdentity(t, store)
	driver := newFakeStytchDriver()
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	connections, _ := NewConnectionService(adapter)
	groups, _ := NewGroupMappingStore(store)
	sequence := 3000
	generate := func() (domain.ProductID, error) { sequence++; return fixtureID(t, sequence), nil }
	tokens, _ := NewAPITokenStore(generate, bytes.NewReader(bytes.Repeat([]byte{0x67}, 96)), func() time.Time { return fixtureNow })
	audits, _ := platformaudit.NewProductService(platformaudit.NewEventStore(), generate, func() time.Time { return fixtureNow })
	fresh := func(context.Context, Principal) error { return nil }
	handler, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principal, nil }, generate,
		WithConnectionService(connections, fresh), WithAdministrationServices(groups, tokens, audits, fresh))
	if err != nil {
		t.Fatal(err)
	}

	assertHTTPContains(t, handler, http.MethodPost, "/api/v1/admin/sso-connections", `{"display_name":"Corporate","protocol":"saml","identity_provider":"generic"}`, http.StatusCreated, `"audit_correlation_id"`)
	assertHTTPContains(t, handler, http.MethodPost, "/api/v1/admin/scim-connections", `{"display_name":"Provisioning","identity_provider":"generic"}`, http.StatusCreated, `"bearer_token"`)
	groupBody := `{"group_reference":"scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31","role":"security_engineer","workspace_id":"` + workspace.ID().String() + `","environment_id":"` + environments[0].ID().String() + `","expected_version":0}`
	assertHTTPContains(t, handler, http.MethodPatch, "/api/v1/admin/group-mappings", groupBody, http.StatusOK, `"version":1`)

	expires := fixtureNow.Add(time.Hour).Format(time.RFC3339)
	tokenBody := `{"name":"M2 E2E","workspace_id":"` + workspace.ID().String() + `","environment_id":"` + environments[0].ID().String() + `","permissions":["view"],"expires_at":"` + expires + `"}`
	created := requestObject(t, handler, http.MethodPost, "/api/v1/admin/api-tokens", tokenBody, http.StatusCreated)
	tokenID := requireString(t, created, "id")
	raw := requireString(t, created, "raw_token")
	scope, _ := domain.NewScope(organization.ID(), workspace.ID(), environments[0].ID())
	if authorization, err := tokens.Authenticate(context.Background(), raw, scope, PermissionView); err != nil || authorization.Scope() != scope {
		t.Fatalf("token authorization = %#v, %v", authorization, err)
	}
	assertHTTPContains(t, handler, http.MethodDelete, "/api/v1/admin/api-tokens/"+tokenID, "", http.StatusOK, `"revoked_at"`)
	if _, err := tokens.Authenticate(context.Background(), raw, scope, PermissionView); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("revoked token = %v", err)
	}

	recorder := performHTTPRequest(handler, http.MethodGet, "/api/v1/audit-events", "")
	for _, action := range []string{"sso_connection.create", "scim_connection.create", "group_mapping.update", "api_token.create", "api_token.use", "api_token.revoke"} {
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"action":"`+action+`"`) {
			t.Fatalf("audit history lacks %s: %d %q", action, recorder.Code, recorder.Body.String())
		}
	}
}

func TestM2SaaSOrganizationsWithIdenticalWorkspaceNamesRemainIsolated(t *testing.T) {
	store := newFixtureStore(t)
	organizationA, principalA, workspaceA, _ := seedHTTPIdentity(t, store)
	organizationB, err := store.ReconcileOrganization(context.Background(), ExternalOrganization{Reference: "organization-live-b", Name: "Beta", Domain: "beta.example"})
	if err != nil {
		t.Fatal(err)
	}
	externalB, err := newExternalPrincipal(DriverSession{MemberReference: "member-live-b", OrganizationReference: "organization-live-b", SessionReference: "member-session-live-b", AuthenticatedAt: fixtureNow.Add(-time.Minute), ExpiresAt: fixtureNow.Add(time.Hour), Active: true})
	if err != nil {
		t.Fatal(err)
	}
	principalB, err := store.ReconcilePrincipal(context.Background(), organizationB.ID(), externalB, RoleOrganizationAdmin)
	if err != nil {
		t.Fatal(err)
	}
	workspaceB, _, err := store.EnsureDefaultScopes(context.Background(), organizationB.ID())
	if err != nil || workspaceA.Name() != workspaceB.Name() {
		t.Fatalf("identical names = %q %q, %v", workspaceA.Name(), workspaceB.Name(), err)
	}

	generate := func() (domain.ProductID, error) { return fixtureID(t, 3400), nil }
	handlerA, _ := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principalA, nil }, generate)
	handlerB, _ := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principalB, nil }, generate)
	for _, attempt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/workspaces/" + workspaceB.ID().String(), ""},
		{http.MethodPatch, "/api/v1/workspaces/" + workspaceB.ID().String(), `{"name":"Compromised"}`},
	} {
		if code := performHTTPRequest(handlerA, attempt.method, attempt.path, attempt.body).Code; code != http.StatusForbidden {
			t.Fatalf("cross-Organization %s = %d", attempt.method, code)
		}
	}
	assertHTTPContains(t, handlerA, http.MethodGet, "/api/v1/workspaces", "", http.StatusOK, `"organization_id":"`+organizationA.ID().String()+`"`)
	assertHTTPContains(t, handlerB, http.MethodGet, "/api/v1/workspaces", "", http.StatusOK, `"id":"`+workspaceB.ID().String()+`"`, `"name":"Default"`)
}

func TestM2SingleTenantPinRejectsMismatchedOrganizationBeforeMutation(t *testing.T) {
	store := newFixtureStore(t)
	organization, principal, _, _ := seedHTTPIdentity(t, store)
	pinned := fixtureID(t, 3600)
	deployment := singleTenantDeployment(t, pinned)
	handler, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principal, nil }, func() (domain.ProductID, error) { return fixtureID(t, 3601), nil }, WithDeployment(deployment))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.ListWorkspaces(context.Background(), organization.ID())
	recorder := performHTTPRequest(handler, http.MethodPost, "/api/v1/workspaces", `{"name":"Must not exist"}`)
	after, _ := store.ListWorkspaces(context.Background(), organization.ID())
	if recorder.Code != http.StatusForbidden || len(before) != len(after) {
		t.Fatalf("pin guard = %d, workspaces %d -> %d", recorder.Code, len(before), len(after))
	}
	matching, err := NewHTTPHandler(store, func(*http.Request) (Principal, error) { return principal, nil }, func() (domain.ProductID, error) { return fixtureID(t, 3602), nil }, WithDeployment(singleTenantDeployment(t, organization.ID())))
	if err != nil {
		t.Fatal(err)
	}
	assertHTTPContains(t, matching, http.MethodGet, "/api/v1/workspaces", "", http.StatusOK, `"organization_id":"`+organization.ID().String()+`"`)
}

func singleTenantDeployment(t *testing.T, organizationID domain.ProductID) platformconfig.Deployment {
	t.Helper()
	values := map[string]string{
		platformconfig.KeyDeploymentMode:             "single_tenant",
		platformconfig.KeySingleTenantOrganizationID: organizationID.String(),
		platformconfig.KeyStytchProjectID:            "project-live-platform",
		platformconfig.KeyStytchSecretRef:            "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/stytch",
		platformconfig.KeyNeonDSNSecretRef:           "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/neon-dsn",
		platformconfig.KeyAWSRegion:                  "us-east-1",
		platformconfig.KeyOTelCollectorEndpoint:      "http://otel-collector.platform.svc:4317",
	}
	configuration, err := platformconfig.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	return configuration.Deployment()
}
