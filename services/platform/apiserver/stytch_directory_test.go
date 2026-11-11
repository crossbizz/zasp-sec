package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/bootstrap"
)

// fakeStytchDirectory records every provider request and answers from the
// organizations and members a test seeds, in the provider's response shapes.
type fakeStytchDirectory struct {
	mu            sync.Mutex
	organizations []stytchOrganization
	members       []stytchMember
	requests      []fakeStytchRequest
	mutate        func(path string, response map[string]any)
}

type fakeStytchRequest struct {
	Method, Path string
	Body         map[string]any
}

func (fake *fakeStytchDirectory) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		user, password, ok := request.BasicAuth()
		if !ok || user != "project-test-directory" || password != "secret-test-directory" {
			t.Errorf("provider request without project credentials: %s", request.URL.Path)
		}
		raw, _ := io.ReadAll(request.Body)
		body := map[string]any{}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("provider request body: %v", err)
			}
		}
		fake.requests = append(fake.requests, fakeStytchRequest{Method: request.Method, Path: request.URL.Path, Body: body})
		response := map[string]any{"status_code": 200}
		switch request.URL.Path {
		case "/v1/b2b/organizations/search":
			response["organizations"] = fake.organizations
		case "/v1/b2b/organizations":
			created := stytchOrganization{Reference: "organization-test-created", Name: body["organization_name"].(string), Slug: body["organization_slug"].(string)}
			for _, value := range body["email_allowed_domains"].([]any) {
				created.AllowedDomains = append(created.AllowedDomains, value.(string))
			}
			created.TrustedMetadata, _ = body["trusted_metadata"].(map[string]any)
			fake.organizations = append(fake.organizations, created)
			response["organization"] = created
		case "/v1/b2b/organizations/members/search":
			response["members"] = fake.members
		case "/v1/b2b/magic_links/email/invite":
			invited := stytchMember{Reference: "member-test-invited", OrganizationReference: body["organization_id"].(string), Email: body["email_address"].(string), Status: "invited"}
			fake.members = append(fake.members, invited)
			response["member"] = invited
		default:
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if fake.mutate != nil {
			fake.mutate(request.URL.Path, response)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	})
}

func (fake *fakeStytchDirectory) paths() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	paths := make([]string, len(fake.requests))
	for index, request := range fake.requests {
		paths[index] = request.Path
	}
	return paths
}

func newTestStytchDirectory(t *testing.T, fake *fakeStytchDirectory) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(fake.handler(t))
	t.Cleanup(server.Close)
	return server
}

// The identity adapter accepts only a canonical UTC millisecond clock.
func directoryTestClock() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// directoryFor returns the production driver pointed at the fake provider.
func directoryFor(t *testing.T, server *httptest.Server) *stytchSessionDriver {
	t.Helper()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &stytchSessionDriver{baseURL: target, client: server.Client(), project: "project-test-directory", secret: "secret-test-directory", inviteRedirectURL: "https://app.zasp.test/auth/callback"}
}

func TestStytchDirectoryCreatesOrganizationOnceAndResolvesItAfterwards(t *testing.T) {
	fake := &fakeStytchDirectory{}
	driver := directoryFor(t, newTestStytchDirectory(t, fake))

	created, err := driver.EnsureOrganization(context.Background(), "Acme Security", "acme.example")
	if err != nil || created.Reference != "organization-test-created" || created.Name != "Acme Security" || created.Domain != "acme.example" {
		t.Fatalf("created = (%#v, %v)", created, err)
	}
	creation := fake.requests[len(fake.requests)-1]
	// Nobody may join by holding an address in the allowed domain: the
	// Organization is invitation-only from its first moment.
	want := map[string]any{"organization_name": "Acme Security", "organization_slug": "acme.example", "email_allowed_domains": []any{"acme.example"}, "email_invites": "ALL_ALLOWED", "email_jit_provisioning": "NOT_ALLOWED", "trusted_metadata": map[string]any{"zasp_bootstrap": "v1"}}
	if creation.Path != "/v1/b2b/organizations" || !reflect.DeepEqual(creation.Body, want) {
		t.Fatalf("creation request = %#v", creation)
	}

	resolved, err := driver.EnsureOrganization(context.Background(), "Acme Security", "acme.example")
	if err != nil || resolved != created {
		t.Fatalf("resolved = (%#v, %v), want %#v", resolved, err, created)
	}
	if got := fake.paths(); !reflect.DeepEqual(got, []string{"/v1/b2b/organizations/search", "/v1/b2b/organizations", "/v1/b2b/organizations/search"}) {
		t.Fatalf("provider calls = %v", got)
	}
}

func TestStytchDirectoryRefusesAnExistingOrganizationThatDoesNotMatch(t *testing.T) {
	stamp := map[string]any{"zasp_bootstrap": "v1"}
	for name, existing := range map[string]stytchOrganization{
		"different name":     {Reference: "organization-test-existing", Name: "Someone Else", Slug: "acme.example", AllowedDomains: []string{"acme.example"}, TrustedMetadata: stamp},
		"domain not allowed": {Reference: "organization-test-existing", Name: "Acme Security", Slug: "acme.example", AllowedDomains: []string{"other.example"}, TrustedMetadata: stamp},
		"different slug":     {Reference: "organization-test-existing", Name: "Acme Security", Slug: "acme", AllowedDomains: []string{"acme.example"}, TrustedMetadata: stamp},
		"invalid reference":  {Reference: "not-an-organization", Name: "Acme Security", Slug: "acme.example", AllowedDomains: []string{"acme.example"}, TrustedMetadata: stamp},
		// Created by something other than this bootstrap in the same project.
		"not created by bootstrap": {Reference: "organization-test-existing", Name: "Acme Security", Slug: "acme.example", AllowedDomains: []string{"acme.example"}},
		"foreign stamp":            {Reference: "organization-test-existing", Name: "Acme Security", Slug: "acme.example", AllowedDomains: []string{"acme.example"}, TrustedMetadata: map[string]any{"zasp_bootstrap": "v0"}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeStytchDirectory{organizations: []stytchOrganization{existing}}
			driver := directoryFor(t, newTestStytchDirectory(t, fake))
			if _, err := driver.EnsureOrganization(context.Background(), "Acme Security", "acme.example"); err == nil {
				t.Fatal("mismatched provider organization was adopted")
			}
			// A mismatch is refused, never repaired by writing to the provider.
			if got := fake.paths(); !reflect.DeepEqual(got, []string{"/v1/b2b/organizations/search"}) {
				t.Fatalf("provider calls = %v", got)
			}
		})
	}
}

// A deployment already bound to a provider Organization resolves only that
// one. A request for another domain must not create a second Organization.
func TestStytchDirectoryBoundToAnOrganizationNeverCreatesOrResolvesAnother(t *testing.T) {
	stamp := map[string]any{"zasp_bootstrap": "v1"}
	bound := stytchOrganization{Reference: "organization-test-bound", Name: "Acme Security", Slug: "acme.example", AllowedDomains: []string{"acme.example"}, TrustedMetadata: stamp}

	fake := &fakeStytchDirectory{organizations: []stytchOrganization{bound}}
	driver := directoryFor(t, newTestStytchDirectory(t, fake))
	driver.expectedOrganization = "organization-test-bound"
	if resolved, err := driver.EnsureOrganization(context.Background(), "Acme Security", "acme.example"); err != nil || resolved.Reference != "organization-test-bound" {
		t.Fatalf("bound organization = (%#v, %v)", resolved, err)
	}

	for name, existing := range map[string][]stytchOrganization{
		"other domain has no organization":      nil,
		"domain resolves a different reference": {{Reference: "organization-test-other", Name: "Acme Security", Slug: "acme.example", AllowedDomains: []string{"acme.example"}, TrustedMetadata: stamp}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeStytchDirectory{organizations: existing}
			driver := directoryFor(t, newTestStytchDirectory(t, fake))
			driver.expectedOrganization = "organization-test-bound"
			if _, err := driver.EnsureOrganization(context.Background(), "Acme Security", "acme.example"); err == nil {
				t.Fatal("a second provider organization was accepted")
			}
			if got := fake.paths(); !reflect.DeepEqual(got, []string{"/v1/b2b/organizations/search"}) {
				t.Fatalf("provider calls = %v", got)
			}
		})
	}
}

// Two domains that differ only in dots and dashes are different customers.
func TestStytchOrganizationSlugIsTheDomainItself(t *testing.T) {
	if a, b := stytchOrganizationSlug("foo-bar.com"), stytchOrganizationSlug("foo.bar.com"); a == b || a != "foo-bar.com" {
		t.Fatalf("slugs = %q, %q", a, b)
	}
}

func TestStytchDirectoryInvitesTheFirstAdministratorWithoutAPasswordOnlyOnce(t *testing.T) {
	fake := &fakeStytchDirectory{}
	driver := directoryFor(t, newTestStytchDirectory(t, fake))

	invited, err := driver.InviteAdmin(context.Background(), "organization-test-acme", "admin@acme.example")
	if err != nil || invited.MemberReference != "member-test-invited" || invited.OrganizationReference != "organization-test-acme" || invited.Email != "admin@acme.example" {
		t.Fatalf("invited = (%#v, %v)", invited, err)
	}
	invitation := fake.requests[len(fake.requests)-1]
	want := map[string]any{"organization_id": "organization-test-acme", "email_address": "admin@acme.example", "invite_redirect_url": "https://app.zasp.test/auth/callback"}
	if invitation.Path != "/v1/b2b/magic_links/email/invite" || !reflect.DeepEqual(invitation.Body, want) {
		t.Fatalf("invitation request = %#v", invitation)
	}
	for _, request := range fake.requests {
		for key := range request.Body {
			if strings.Contains(key, "password") {
				t.Fatalf("provider request %s carries %q", request.Path, key)
			}
		}
	}

	again, err := driver.InviteAdmin(context.Background(), "organization-test-acme", "admin@acme.example")
	if err != nil || again != invited {
		t.Fatalf("repeated = (%#v, %v), want %#v", again, err, invited)
	}
	// The repeat finds the member and sends no second invitation.
	if got := fake.paths(); !reflect.DeepEqual(got, []string{"/v1/b2b/organizations/members/search", "/v1/b2b/magic_links/email/invite", "/v1/b2b/organizations/members/search"}) {
		t.Fatalf("provider calls = %v", got)
	}
}

func TestStytchDirectoryRefusesAnInvitationForAnotherOrganizationOrAddress(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"other organization": func(response map[string]any) {
			response["member"] = stytchMember{Reference: "member-test-invited", OrganizationReference: "organization-test-other", Email: "admin@acme.example", Status: "invited"}
		},
		"other address": func(response map[string]any) {
			response["member"] = stytchMember{Reference: "member-test-invited", OrganizationReference: "organization-test-acme", Email: "intruder@acme.example", Status: "invited"}
		},
		"deleted member": func(response map[string]any) {
			response["member"] = stytchMember{Reference: "member-test-invited", OrganizationReference: "organization-test-acme", Email: "admin@acme.example", Status: "deleted"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeStytchDirectory{mutate: func(path string, response map[string]any) {
				if path == "/v1/b2b/magic_links/email/invite" {
					mutate(response)
				}
			}}
			driver := directoryFor(t, newTestStytchDirectory(t, fake))
			if _, err := driver.InviteAdmin(context.Background(), "organization-test-acme", "admin@acme.example"); err == nil {
				t.Fatal("mismatched provider invitation was accepted")
			}
		})
	}
}

func TestStytchDirectoryRequiresTheDeploymentCallbackAsInviteRedirect(t *testing.T) {
	config := StytchDirectoryConfig{BaseURL: "https://test.stytch.com", ProjectID: "project-test-directory", Secret: "secret-test-directory", InviteRedirectURL: "https://app.zasp.test/auth/callback", Timeout: 5 * time.Second, Now: directoryTestClock}
	if adapter, err := NewStytchDirectory(config); err != nil || adapter == nil {
		t.Fatalf("deployment callback refused: %v", err)
	}
	for _, redirect := range []string{"", "http://app.zasp.test/auth/callback", "https://app.zasp.test/other", "https://app.zasp.test/auth/callback?next=/", "https://user@app.zasp.test/auth/callback"} {
		refused := config
		refused.InviteRedirectURL = redirect
		if _, err := NewStytchDirectory(refused); err == nil {
			t.Fatalf("invite redirect %q accepted", redirect)
		}
	}
	malformed := config
	malformed.ExpectedOrganization = "acme"
	if _, err := NewStytchDirectory(malformed); err == nil {
		t.Fatal("malformed expected organization accepted")
	}
}

func TestProviderTokenTypesSelectExactlyOneProviderExchange(t *testing.T) {
	if got := ProviderTokenTypeFromContext(context.Background()); got != ProviderTokenTypeOAuth {
		t.Fatalf("default token type = %q", got)
	}
	for tokenType, want := range map[string]stytchTokenExchange{
		ProviderTokenTypeOAuth:     {path: "/v1/b2b/oauth/authenticate", field: "oauth_token"},
		ProviderTokenTypeMagicLink: {path: "/v1/b2b/magic_links/authenticate", field: "magic_links_token"},
	} {
		ctx := WithProviderTokenType(context.Background(), tokenType)
		if got := stytchTokenExchanges[ProviderTokenTypeFromContext(ctx)]; got != want || !ValidProviderTokenType(tokenType) {
			t.Fatalf("%s exchange = %#v", tokenType, got)
		}
	}
	for _, tokenType := range []string{"sso", "discovery", "session_jwt", "OAUTH", " oauth"} {
		if ValidProviderTokenType(tokenType) {
			t.Fatalf("token type %q accepted", tokenType)
		}
	}
}

func TestStytchAuthenticatorExchangesAnInvitationTokenAndRefusesUnknownTypesWithoutCallingTheProvider(t *testing.T) {
	var mu sync.Mutex
	var seen []fakeStytchRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		body := map[string]any{}
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		seen = append(seen, fakeStytchRequest{Method: request.Method, Path: request.URL.Path, Body: body})
		mu.Unlock()
		// The provider refuses every token here; the test observes which
		// exchange the product chose, not a session.
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"status_code":401,"error_type":"unable_to_auth_magic_link"}`)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewStytchOAuthAuthenticator("https://test.stytch.com", "project-test-directory", "secret-test-directory", 5*time.Second, directoryTestClock)
	if err != nil {
		t.Fatal(err)
	}
	authenticator.baseURL, authenticator.client = target, server.Client()

	if _, err := authenticator.Authenticate(WithProviderTokenType(context.Background(), ProviderTokenTypeMagicLink), "invitation-token"); err != ErrRepositoryAuthentication {
		t.Fatalf("refused invitation = %v", err)
	}
	if _, err := authenticator.Authenticate(context.Background(), "oauth-token"); err != ErrRepositoryAuthentication {
		t.Fatalf("refused oauth = %v", err)
	}
	if _, err := authenticator.Authenticate(WithProviderTokenType(context.Background(), "sso"), "sso-token"); err != ErrRepositoryAuthentication {
		t.Fatalf("unknown type = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []fakeStytchRequest{
		{Method: http.MethodPost, Path: "/v1/b2b/magic_links/authenticate", Body: map[string]any{"magic_links_token": "invitation-token", "session_duration_minutes": float64(60)}},
		{Method: http.MethodPost, Path: "/v1/b2b/oauth/authenticate", Body: map[string]any{"oauth_token": "oauth-token", "session_duration_minutes": float64(60)}},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("provider exchanges = %#v", seen)
	}
}

// The bootstrap grants the first administrator exactly the Organization Admin
// permissions the API serves for that role; the two lists must not drift.
func TestBootstrapAdministratorPermissionsMatchTheServedOrganizationAdminRole(t *testing.T) {
	for _, role := range serverOwnedRoles() {
		if role["role"] == bootstrap.AdminRole {
			if !reflect.DeepEqual(role["permissions"], bootstrap.AdminPermissions) {
				t.Fatalf("bootstrap permissions %v differ from served %v", bootstrap.AdminPermissions, role["permissions"])
			}
			return
		}
	}
	t.Fatalf("served roles have no %s", bootstrap.AdminRole)
}
