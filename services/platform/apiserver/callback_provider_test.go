package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

type fixedExternalAuthenticator struct {
	principal platformidentity.ExternalPrincipal
}

func (value fixedExternalAuthenticator) Authenticate(context.Context, string) (platformidentity.ExternalPrincipal, error) {
	return value.principal, nil
}
func (fixedExternalAuthenticator) Ready(context.Context) error { return nil }

type fixedGrantResolver struct {
	grant SessionGrant
	got   platformidentity.ExternalPrincipal
}

func (resolver *fixedGrantResolver) ResolveIdentity(_ context.Context, principal platformidentity.ExternalPrincipal) (SessionGrant, error) {
	resolver.got = principal
	return resolver.grant, nil
}

type fixedIdentityStateRepository struct {
	state    string
	consumed string
	returnTo string
}

func (repository *fixedIdentityStateRepository) BeginIdentity(context.Context, string) (string, error) {
	return repository.state, nil
}
func (repository *fixedIdentityStateRepository) ConsumeIdentity(_ context.Context, state string) (string, error) {
	repository.consumed = state
	return repository.returnTo, nil
}

func TestRepositoryIdentityProviderDerivesGrantFromServerSideMembership(t *testing.T) {
	grant := sessionGrant(t, "1")
	principal := stytchExternalPrincipal(t, grant.ExpiresAt)
	resolver := &fixedGrantResolver{grant: grant}
	provider, err := NewRepositoryIdentityProvider(fixedExternalAuthenticator{principal: principal}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	grant.ReturnTo = "/"
	got, err := provider.Complete(context.Background(), "provider-token", strings.Repeat("s", 32))
	if err != nil || !reflect.DeepEqual(got, grant) || resolver.got != principal {
		t.Fatalf("grant = (%#v, %v), external=%#v", got, err, resolver.got)
	}
}

func TestStytchOAuthAuthenticatorUsesProviderFaithfulExchangeAndIdentityAdapter(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var headRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodHead {
			headRequests.Add(1)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		project, secret, ok := request.BasicAuth()
		if !ok || project != "project-test-local" || secret != "secret-test-local" {
			t.Fatal("missing Stytch project authentication")
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch request.URL.Path {
		case "/v1/b2b/oauth/authenticate":
			var input map[string]any
			if json.NewDecoder(request.Body).Decode(&input) != nil || !reflect.DeepEqual(input, map[string]any{"oauth_token": "provider-token", "session_duration_minutes": float64(60)}) {
				t.Fatalf("oauth input = %#v", input)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"status_code": 200, "request_id": "request-id-test-local", "member_id": "member-test-local",
				"organization_id": "organization-test-local", "session_jwt": "header.payload.signature",
				"member": map[string]any{"status": "active", "roles": []string{"provider-admin-must-not-authorize"}},
			})
		case "/v1/b2b/sessions/authenticate":
			var input map[string]any
			if json.NewDecoder(request.Body).Decode(&input) != nil || !reflect.DeepEqual(input, map[string]any{"session_jwt": "header.payload.signature"}) {
				t.Fatalf("session input = %#v", input)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"status_code": 200, "request_id": "request-id-test-session", "session_jwt": "header.payload.signature",
				"member_session": map[string]any{
					"member_session_id": "member-session-test-local", "member_id": "member-test-local",
					"organization_id": "organization-test-local", "started_at": now.Format(time.RFC3339),
					"last_accessed_at": now.Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339),
					"roles": []string{"provider-admin-must-not-authorize"},
				},
			})
		default:
			t.Fatalf("unexpected Stytch path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	authenticator, err := NewStytchOAuthAuthenticator(server.URL, "project-test-local", "secret-test-local", time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authenticator.Authenticate(context.Background(), "provider-token")
	if err != nil || principal.OrganizationReference() != "organization-test-local" || principal.MemberReference() != "member-test-local" || principal.SessionReference() != "member-session-test-local" || principal.ExpiresAt() != now.Add(time.Hour) {
		t.Fatalf("external principal = (%#v, %v)", principal, err)
	}
	if err := authenticator.Ready(context.Background()); err != nil || headRequests.Load() != 0 {
		t.Fatalf("readiness = %v, HEAD count = %d", err, headRequests.Load())
	}
}

func TestRepositoryIdentityProviderOwnsStateAndBuildsStytchStartURL(t *testing.T) {
	grant := sessionGrant(t, "1")
	principal := stytchExternalPrincipal(t, grant.ExpiresAt)
	states := &fixedIdentityStateRepository{state: strings.Repeat("s", 32), returnTo: "/discovery/assets"}
	provider, err := NewRepositoryIdentityProviderWithStart(
		fixedExternalAuthenticator{principal: principal}, &fixedGrantResolver{grant: grant}, states,
		"https://test.stytch.com/v1/b2b/public/oauth/google/start", "public-token-test-local", "organization-test-local", "https://app.zasp.example/auth/callback",
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := provider.Start(context.Background(), "/discovery/assets")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(target)
	callback, _ := url.Parse(parsed.Query().Get("login_redirect_url"))
	if parsed.Host != "test.stytch.com" || parsed.Path != "/v1/b2b/public/oauth/google/start" || parsed.Query().Get("public_token") != "public-token-test-local" || parsed.Query().Get("organization_id") != "organization-test-local" || callback.Path != "/auth/callback" || callback.Query().Get("state") != states.state || parsed.Query().Get("signup_redirect_url") != callback.String() {
		t.Fatalf("start target = %s", target)
	}
	completed, err := provider.Complete(context.Background(), "provider-token", states.state)
	if err != nil || states.consumed != states.state || completed.ReturnTo != "/discovery/assets" {
		t.Fatalf("complete/consumed = (%v, %q, %q)", err, states.consumed, completed.ReturnTo)
	}
}

func stytchExternalPrincipal(t *testing.T, expires time.Time) platformidentity.ExternalPrincipal {
	t.Helper()
	driver := &callbackIdentityDriver{session: platformidentity.DriverSession{
		MemberReference: "member-test-local", OrganizationReference: "organization-test-local",
		SessionReference: "member-session-test-local", AuthenticatedAt: expires.Add(-time.Hour), ExpiresAt: expires, Active: true,
	}}
	adapter, err := platformidentity.NewAdapter(driver, func() time.Time { return expires.Add(-time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	principal, err := adapter.Authenticate(context.Background(), "header.payload.signature")
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

type callbackIdentityDriver struct {
	session platformidentity.DriverSession
}

func (driver *callbackIdentityDriver) AuthenticateJWT(context.Context, string) (platformidentity.DriverSession, error) {
	return driver.session, nil
}
func (driver *callbackIdentityDriver) RevalidateSession(context.Context, string) (platformidentity.DriverSession, error) {
	return driver.session, nil
}
func (*callbackIdentityDriver) GetOrganization(context.Context, string) (platformidentity.DriverOrganization, error) {
	return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) EnsureOrganization(context.Context, string, string) (platformidentity.DriverOrganization, error) {
	return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) InviteAdmin(context.Context, string, string) (platformidentity.DriverInvitation, error) {
	return platformidentity.DriverInvitation{}, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) ListSSOConnections(context.Context, string) ([]platformidentity.DriverSSOConnection, error) {
	return nil, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) CreateSSOConnection(context.Context, string, platformidentity.DriverSSOConfig) (platformidentity.DriverSSOConnection, error) {
	return platformidentity.DriverSSOConnection{}, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) DeleteSSOConnection(context.Context, string, string) (string, error) {
	return "", platformidentity.ErrProvider
}
func (*callbackIdentityDriver) TestSSOConnection(context.Context, string, string) error {
	return platformidentity.ErrProvider
}
func (*callbackIdentityDriver) ListSCIMConnections(context.Context, string) ([]platformidentity.DriverSCIMConnection, error) {
	return nil, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) CreateSCIMConnection(context.Context, string, platformidentity.DriverSCIMConfig) (platformidentity.DriverSCIMCredential, error) {
	return platformidentity.DriverSCIMCredential{}, platformidentity.ErrProvider
}
func (*callbackIdentityDriver) DeleteSCIMConnection(context.Context, string, string) (string, error) {
	return "", platformidentity.ErrProvider
}
