package idpdiscovery

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

type exchangeFunc func(context.Context, ExchangeRequest) (Connection, error)

func (function exchangeFunc) Exchange(ctx context.Context, request ExchangeRequest) (Connection, error) {
	return function(ctx, request)
}

func TestOktaAuthorizationPinsIssuerCallbackScopesAndPKCE(t *testing.T) {
	config := Config{Issuer: "https://acme.okta.com", ClientID: "0oa1234567890abcdef", ClientSecretReference: "ref:okta/client-secret-0001", CallbackURL: "https://zasp.example/api/v1/integrations/oauth/callback"}
	adapter, err := NewOktaAdapter(config, exchangeFunc(func(context.Context, ExchangeRequest) (Connection, error) { return Connection{}, nil }), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	target, err := adapter.AuthorizationURL("abcdefghijklmnopqrstuvwxyzABCDEFGH123456789", "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(target)
	if parsed.Host != "acme.okta.com" || parsed.Path != "/oauth2/v1/authorize" || parsed.Query().Get("scope") != "offline_access okta.apps.read okta.groups.read okta.users.read" || parsed.Query().Get("response_type") != "code" || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL %q", target)
	}
	for _, issuer := range []string{"http://acme.okta.com", "https://okta.com.evil.example", "https://127.0.0.1", "https://acme.okta.com/oauth2/default"} {
		config.Issuer = issuer
		if _, err := NewOktaAdapter(config, exchangeFunc(func(context.Context, ExchangeRequest) (Connection, error) { return Connection{}, nil }), time.Second); !errors.Is(err, ErrInvalid) {
			t.Fatalf("issuer %q error=%v", issuer, err)
		}
	}
}

func TestOktaCompletionRequiresExactReadScopesAndOpaqueRefreshReference(t *testing.T) {
	client := exchangeFunc(func(_ context.Context, request ExchangeRequest) (Connection, error) {
		if request.Code != "provider-code" || string(request.PKCEVerifier) != "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789" {
			t.Fatalf("exchange request %#v", request)
		}
		return Connection{Reference: "ref:okta/refresh/subject-0001", Subject: "00u1234567890abcdef", Tenant: "acme.okta.com", Scopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}}, nil
	})
	adapter, _ := NewOktaAdapter(Config{Issuer: "https://acme.okta.com", ClientID: "0oa1234567890abcdef", ClientSecretReference: "ref:okta/client-secret-0001", CallbackURL: "https://zasp.example/api/v1/integrations/oauth/callback"}, client, time.Second)
	connection, err := adapter.Complete(context.Background(), "pid_70000003-0000-4000-8000-000000000003", "provider-code", []byte("abcdefghijklmnopqrstuvwxyzABCDEFGH123456789"))
	if err != nil || connection.Reference != "ref:okta/refresh/subject-0001" {
		t.Fatalf("connection=%#v err=%v", connection, err)
	}
	client = exchangeFunc(func(context.Context, ExchangeRequest) (Connection, error) {
		return Connection{Reference: "raw-refresh-token", Subject: "00u1234567890abcdef", Tenant: "acme.okta.com", Scopes: []string{"okta.users.read"}}, nil
	})
	adapter.client = client
	if _, err := adapter.Complete(context.Background(), "pid_70000003-0000-4000-8000-000000000003", "provider-code", []byte("abcdefghijklmnopqrstuvwxyzABCDEFGH123456789")); !errors.Is(err, ErrProvider) || err.Error() != ErrProvider.Error() {
		t.Fatalf("hostile result error=%v", err)
	}
}
