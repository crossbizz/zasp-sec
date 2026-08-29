package apiserver

import (
	"context"
	"errors"
	"testing"
)

func TestConnectorProviderRegistryIsOneProviderCapabilityAuthority(t *testing.T) {
	githubReady := true
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"github": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"},
		"okta":   {Provider: &connectorProviderStub{}, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"},
	}, map[string]ConnectorCapabilityCheck{
		"github": func(context.Context) error {
			if !githubReady {
				return errors.New("github secret unavailable")
			}
			return nil
		},
		"okta": func(context.Context) error { return errors.New("okta secret unavailable") },
	})
	if err != nil || !registry.ConnectorAvailable(context.Background(), "github") || registry.ConnectorAvailable(context.Background(), "okta") {
		t.Fatalf("initial capabilities = github:%t okta:%t err:%v", registry.ConnectorAvailable(context.Background(), "github"), registry.ConnectorAvailable(context.Background(), "okta"), err)
	}
	githubReady = false
	if registry.ConnectorAvailable(context.Background(), "github") {
		t.Fatal("degraded GitHub capability remained available")
	}
	if _, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"aws": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"sts:GetCallerIdentity"}, CredentialClass: "aws_external_id"},
	}, nil); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("unserved AWS registry error = %v", err)
	}
}

func TestConnectorProviderRegistryMapsPublicLongTailKeyToPrivateNangoAuthority(t *testing.T) {
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"github": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"},
		"slack": {
			Provider: &connectorProviderStub{}, RequestedScopes: []string{"nango:auth", "nango:proxy"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:slack",
		},
	}, map[string]ConnectorCapabilityCheck{"github": func(context.Context) error { return nil }, "slack": func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	public, ready := registry.Provider(context.Background(), "slack")
	if !ready || public.AuthorityProvider != "nango:slack" {
		t.Fatalf("public definition=%#v ready=%t", public, ready)
	}
	private, key, ready := registry.ProviderForAuthority(context.Background(), "nango:slack")
	if !ready || key != "slack" || private.AuthorityProvider != "nango:slack" {
		t.Fatalf("private definition=%#v key=%q ready=%t", private, key, ready)
	}
	if _, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"slack": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"nango:auth"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:other"},
	}, nil); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("mismatched authority error=%v", err)
	}
}
