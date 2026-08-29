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
	providers      map[string]ConnectorOAuthProviderDefinition
	authorityToKey map[string]string
	checks         map[string]ConnectorCapabilityCheck
}

func NewConnectorProviderRegistry(providers map[string]ConnectorOAuthProviderDefinition, checks map[string]ConnectorCapabilityCheck) (*ConnectorProviderRegistry, error) {
	launchRegistry, err := launch.NewRegistry(launch.DefaultManifests(), launch.DefaultCredentialClasses())
	if err != nil || len(providers) < 1 || len(providers) > 64 || len(checks) != 0 && len(checks) != len(providers) {
		return nil, ErrRepositoryConfiguration
	}
	registry := &ConnectorProviderRegistry{providers: make(map[string]ConnectorOAuthProviderDefinition, len(providers)), authorityToKey: make(map[string]string, len(providers)), checks: make(map[string]ConnectorCapabilityCheck, len(providers))}
	for key, definition := range providers {
		manifest, launchReady := launchRegistry.FirstParty(key)
		if definition.AuthorityProvider == "" {
			definition.AuthorityProvider = key
		}
		core := launchReady && manifest.AuthorizationReady && stringIn(key, "github", "okta") && definition.AuthorityProvider == key && (key != "github" || definition.CredentialClass == "github_installation_reference") && (key != "okta" || definition.CredentialClass == "okta_refresh_reference")
		longTail := keyPatternForCatalog(key) && !stringIn(key, "aws", "kubernetes", "github", "okta") && definition.AuthorityProvider == "nango:"+key && definition.CredentialClass == "nango_connection_reference"
		if (!core && !longTail) || nilInterface(definition.Provider) == nilInterface(definition.Factory) || !validConnectorScopes(definition.RequestedScopes) {
			return nil, ErrRepositoryConfiguration
		}
		if _, exists := registry.authorityToKey[definition.AuthorityProvider]; exists {
			return nil, ErrRepositoryConfiguration
		}
		check, hasCheck := checks[key]
		if len(checks) != 0 && (!hasCheck || check == nil) {
			return nil, ErrRepositoryConfiguration
		}
		definition.RequestedScopes = append([]string(nil), definition.RequestedScopes...)
		registry.providers[key] = definition
		registry.authorityToKey[definition.AuthorityProvider] = key
		registry.checks[key] = check
	}
	for key := range checks {
		if _, exists := providers[key]; !exists {
			return nil, ErrRepositoryConfiguration
		}
	}
	return registry, nil
}

func (registry *ConnectorProviderRegistry) ProviderForAuthority(ctx context.Context, authority string) (ConnectorOAuthProviderDefinition, string, bool) {
	if registry == nil || ctx == nil || ctx.Err() != nil {
		return ConnectorOAuthProviderDefinition{}, "", false
	}
	key, exists := registry.authorityToKey[authority]
	if !exists {
		return ConnectorOAuthProviderDefinition{}, "", false
	}
	definition, ready := registry.Provider(ctx, key)
	return definition, key, ready
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

func keyPatternForCatalog(value string) bool {
	if len(value) < 2 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}
