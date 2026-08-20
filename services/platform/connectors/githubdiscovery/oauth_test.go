package githubdiscovery

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

func TestFirstPartyGitHubAuthorizationUsesFixedHostCallbackScopesAndPKCE(t *testing.T) {
	adapter, err := NewAdapter(Config{ClientID: "Iv1.1234567890abcdef", ClientSecretReference: "ref:github/app-secret-0001", CallbackURL: "https://zasp.example/api/v1/integrations/oauth/callback"}, exchangeFunc(func(context.Context, ExchangeRequest) (Connection, error) { return Connection{}, nil }), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	target, err := adapter.AuthorizationURL("abcdefghijklmnopqrstuvwxyzABCDEFGH123456789", "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(target)
	if parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.Path != "/login/oauth/authorize" || parsed.Query().Get("redirect_uri") != "https://zasp.example/api/v1/integrations/oauth/callback" || parsed.Query().Get("scope") != "read:org repo" || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL %q", target)
	}
	if _, err := NewAdapter(Config{ClientID: "id", ClientSecretReference: "plaintext", CallbackURL: "https://evil.example/callback"}, exchangeFunc(func(context.Context, ExchangeRequest) (Connection, error) { return Connection{}, nil }), time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hostile config error=%v", err)
	}
}

func TestFirstPartyGitHubCompletionReturnsOnlyOpaqueInstallationReference(t *testing.T) {
	client := exchangeFunc(func(_ context.Context, request ExchangeRequest) (Connection, error) {
		if request.Code != "provider-code" || string(request.PKCEVerifier) != "abcdefghijklmnopqrstuvwxyzABCDEFGH123456789" || request.ClientSecretReference != "ref:github/app-secret-0001" {
			t.Fatalf("exchange request %#v", request)
		}
		return Connection{Reference: "ref:github/install/123456", InstallationID: 123456, AccountLogin: "acme", RepositorySelection: "selected", Permissions: map[string]string{"contents": "read", "metadata": "read"}}, nil
	})
	adapter, _ := NewAdapter(Config{ClientID: "Iv1.1234567890abcdef", ClientSecretReference: "ref:github/app-secret-0001", CallbackURL: "https://zasp.example/api/v1/integrations/oauth/callback"}, client, time.Second)
	connection, err := adapter.Complete(context.Background(), "pid_70000003-0000-4000-8000-000000000003", "provider-code", []byte("abcdefghijklmnopqrstuvwxyzABCDEFGH123456789"))
	if err != nil || connection.Reference != "ref:github/install/123456" || connection.InstallationID != 123456 {
		t.Fatalf("connection=%#v err=%v", connection, err)
	}
	client = exchangeFunc(func(context.Context, ExchangeRequest) (Connection, error) {
		return Connection{Reference: "ghp_plaintext", InstallationID: 1, AccountLogin: "acme", RepositorySelection: "all", Permissions: map[string]string{"contents": "write"}}, nil
	})
	adapter, _ = NewAdapter(Config{ClientID: "Iv1.1234567890abcdef", ClientSecretReference: "ref:github/app-secret-0001", CallbackURL: "https://zasp.example/api/v1/integrations/oauth/callback"}, client, time.Second)
	if _, err := adapter.Complete(context.Background(), "pid_70000003-0000-4000-8000-000000000003", "provider-code", []byte("abcdefghijklmnopqrstuvwxyzABCDEFGH123456789")); !errors.Is(err, ErrProvider) || err.Error() != ErrProvider.Error() {
		t.Fatalf("hostile provider result=%v", err)
	}
}
