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
