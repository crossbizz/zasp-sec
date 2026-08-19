package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixedIdentityExchanger struct{ identity ExternalIdentity }

func (value fixedIdentityExchanger) Exchange(context.Context, string, string) (ExternalIdentity, error) {
	return value.identity, nil
}
func (fixedIdentityExchanger) Ready(context.Context) error { return nil }

type fixedGrantResolver struct {
	grant SessionGrant
	got   ExternalIdentity
}

func (resolver *fixedGrantResolver) ResolveIdentity(_ context.Context, identity ExternalIdentity) (SessionGrant, error) {
	resolver.got = identity
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
	external := ExternalIdentity{OrganizationReference: "organization-live-a", MemberReference: "member-live-a", ExpiresAt: grant.ExpiresAt}
	resolver := &fixedGrantResolver{grant: grant}
	provider, err := NewRepositoryIdentityProvider(fixedIdentityExchanger{identity: external}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	grant.ReturnTo = "/"
	got, err := provider.Complete(context.Background(), "code", strings.Repeat("s", 32))
	if err != nil || !reflect.DeepEqual(got, grant) || resolver.got != external {
		t.Fatalf("grant = (%#v, %v), external=%#v", got, err, resolver.got)
	}
}

func TestOIDCCodeExchangerReturnsOnlyBoundedExternalIdentity(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodHead {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		client, secret, ok := request.BasicAuth()
		if !ok || client != "client-id" || secret != "client-secret" {
			t.Fatal("missing client authentication")
		}
		if request.ParseForm() != nil || request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code") != "code" || request.Form.Get("state") != strings.Repeat("s", 32) {
			t.Fatalf("form = %#v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"organization_reference": "organization-live-a", "member_reference": "member-live-a", "expires_at": expires.Format(time.RFC3339)})
	}))
	defer server.Close()
	exchanger, err := NewOIDCCodeExchanger(server.URL+"/token", "client-id", "client-secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := exchanger.Exchange(context.Background(), "code", strings.Repeat("s", 32))
	if err != nil || identity.OrganizationReference != "organization-live-a" || identity.ExpiresAt != expires {
		t.Fatalf("identity = (%#v, %v)", identity, err)
	}
}

func TestRepositoryIdentityProviderOwnsStartStateAndConsumesItBeforeExchange(t *testing.T) {
	grant := sessionGrant(t, "1")
	external := ExternalIdentity{OrganizationReference: "organization-live-a", MemberReference: "member-live-a", ExpiresAt: grant.ExpiresAt}
	states := &fixedIdentityStateRepository{state: strings.Repeat("s", 32), returnTo: "/discovery/assets"}
	provider, err := NewRepositoryIdentityProviderWithStart(fixedIdentityExchanger{identity: external}, &fixedGrantResolver{grant: grant}, states, "https://identity.example/authorize", "client-id", "https://app.zasp.example/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	target, err := provider.Start(context.Background(), "/discovery/assets")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(target)
	if parsed.Host != "identity.example" || parsed.Query().Get("state") != states.state || parsed.Query().Get("redirect_uri") != "https://app.zasp.example/auth/callback" {
		t.Fatalf("start target = %s", target)
	}
	completed, err := provider.Complete(context.Background(), "code", states.state)
	if err != nil || states.consumed != states.state || completed.ReturnTo != "/discovery/assets" {
		t.Fatalf("complete/consumed = (%v, %q, %q)", err, states.consumed, completed.ReturnTo)
	}
}
