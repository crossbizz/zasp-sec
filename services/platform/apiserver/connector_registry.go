package apiserver

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/launch"
)

type ConnectorCapabilities interface {
	ConnectorAvailable(context.Context, string) bool
}

type ConnectorCapabilityCheck func(context.Context) error

type ConnectorProviderRegistry struct {
	providers map[string]ConnectorOAuthProviderDefinition
	checks    map[string]ConnectorCapabilityCheck
}

func NewConnectorProviderRegistry(providers map[string]ConnectorOAuthProviderDefinition, checks map[string]ConnectorCapabilityCheck) (*ConnectorProviderRegistry, error) {
	launchRegistry, err := launch.NewRegistry(launch.DefaultManifests(), launch.DefaultCredentialClasses())
	if err != nil || len(providers) < 1 || len(providers) > 2 || len(checks) != 0 && len(checks) != len(providers) {
		return nil, ErrRepositoryConfiguration
	}
	registry := &ConnectorProviderRegistry{providers: make(map[string]ConnectorOAuthProviderDefinition, len(providers)), checks: make(map[string]ConnectorCapabilityCheck, len(providers))}
	for key, definition := range providers {
		manifest, launchReady := launchRegistry.FirstParty(key)
		if !launchReady || !manifest.AuthorizationReady || !stringIn(key, "github", "okta") || nilInterface(definition.Provider) == nilInterface(definition.Factory) || !validConnectorScopes(definition.RequestedScopes) || key == "github" && definition.CredentialClass != "github_installation_reference" || key == "okta" && definition.CredentialClass != "okta_refresh_reference" {
			return nil, ErrRepositoryConfiguration
		}
		check, hasCheck := checks[key]
		if len(checks) != 0 && (!hasCheck || check == nil) {
			return nil, ErrRepositoryConfiguration
		}
		definition.RequestedScopes = append([]string(nil), definition.RequestedScopes...)
		registry.providers[key] = definition
		registry.checks[key] = check
	}
	for key := range checks {
		if _, exists := providers[key]; !exists {
			return nil, ErrRepositoryConfiguration
		}
	}
	return registry, nil
}

func (registry *ConnectorProviderRegistry) Provider(ctx context.Context, key string) (ConnectorOAuthProviderDefinition, bool) {
	if registry == nil || ctx == nil || ctx.Err() != nil {
		return ConnectorOAuthProviderDefinition{}, false
	}
	definition, exists := registry.providers[key]
	if !exists {
		return ConnectorOAuthProviderDefinition{}, false
	}
	if check := registry.checks[key]; check != nil && check(ctx) != nil {
		return ConnectorOAuthProviderDefinition{}, false
	}
	definition.RequestedScopes = append([]string(nil), definition.RequestedScopes...)
	return definition, true
}

func (registry *ConnectorProviderRegistry) ConnectorAvailable(ctx context.Context, key string) bool {
	_, ready := registry.Provider(ctx, key)
	return ready
}

type fixedConnectorCapabilities map[string]struct{}

func (capabilities fixedConnectorCapabilities) ConnectorAvailable(_ context.Context, key string) bool {
	_, ready := capabilities[key]
	return ready
}

func defaultWorkflowConnectorCapabilities() ConnectorCapabilities {
	return fixedConnectorCapabilities{"github": {}, "okta": {}}
}
