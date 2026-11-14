package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// saasSignInProvider runs the sign-in to a SaaS platform at Nango, the way
// the managed OAuth connector does: the API asks Nango for the provider's
// authorization address and refuses any address that is not the page the
// platform definition declares; the provider returns the browser to the
// product's own callback; the API hands the code to Nango, which exchanges
// it and keeps the token. What comes back is the reference of the connection
// Nango created.
//
// Before that reference leaves, the platform is asked through the proxy
// which tenant the connection reaches. A connection that does not reach the
// tenant the integration names is removed from Nango and the sign-in fails:
// a person cannot connect one tenant under the name of another.
type saasSignInProvider struct {
	registry                                     *saasdiscovery.Registry
	client                                       nangoConnectionAPI
	proxy                                        saasdiscovery.Proxy
	baseURL, serviceSecretReference, environment string
	callbackURL                                  string
	clock                                        func() time.Time
}

func (provider *saasSignInProvider) platform(token, tenantID string) (saasdiscovery.Platform, bool) {
	if provider == nil || provider.registry == nil {
		return saasdiscovery.Platform{}, false
	}
	platform, known := provider.registry.Platform(token)
	return platform, known && platform.SignIn != nil && (tenantID == "" || platform.ValidTenant(tenantID))
}

func (provider *saasSignInProvider) Available(ctx context.Context, platform string) bool {
	_, available := provider.platform(platform, "")
	return available && ctx != nil && ctx.Err() == nil
}

func (provider *saasSignInProvider) Start(ctx context.Context, request apiserver.SaaSSignInRequest) (apiserver.ConnectorAuthorizationTarget, error) {
	platform, ok := provider.platform(request.Platform, request.TenantID)
	if !ok || ctx == nil || ctx.Err() != nil || request.Scope.Validate() != nil || !validNangoProductID(request.IntegrationID) || !validNangoProductID(request.AttemptID) {
		return apiserver.ConnectorAuthorizationTarget{}, errRuntimeUnavailable
	}
	// The authorization page is the one the definition names, or the page
	// on the tenant's own host, which the definition's host rule admits.
	host := platform.SignIn.AuthorizationHost
	if host == "" {
		tenantHost, allowed := platform.TenantHost(request.TenantID)
		if !allowed || tenantHost == "" {
			return apiserver.ConnectorAuthorizationTarget{}, errRuntimeUnavailable
		}
		host = tenantHost
	}
	params := make(map[string]string, len(platform.SignIn.ConnectionParams))
	for name, value := range platform.SignIn.ConnectionParams {
		params[name] = strings.ReplaceAll(value, saasdiscovery.TenantValue, request.TenantID)
	}
	result, err := provider.client.StartOAuth(ctx, nango.OAuthStartRequest{
		NangoBaseURL: provider.baseURL, ServiceSecretReference: provider.serviceSecretReference, Environment: provider.environment,
		ConnectorKey: platform.Nango.Key, AuthorizationHost: host, AuthorizationPath: platform.SignIn.AuthorizationPath, CallbackURL: provider.callbackURL,
		Binding: nangoConnectionBinding(request.Scope, request.IntegrationID, request.AttemptID), ConnectionParams: params,
	})
	if err != nil {
		return apiserver.ConnectorAuthorizationTarget{}, errRuntimeUnavailable
	}
	return apiserver.ConnectorAuthorizationTarget{URL: result.URL, State: result.State, ExpiresAt: result.ExpiresAt}, nil
}

func (provider *saasSignInProvider) Complete(ctx context.Context, request apiserver.SaaSSignInCompletion) (string, error) {
	platform, ok := provider.platform(request.Platform, request.TenantID)
	if !ok || ctx == nil || ctx.Err() != nil || request.Scope.Validate() != nil || !validNangoProductID(request.IntegrationID) || !validNangoProductID(request.AttemptID) {
		return "", errRuntimeUnavailable
	}
	connection, err := provider.client.CompleteOAuth(ctx, nango.OAuthCompleteRequest{
		NangoBaseURL: provider.baseURL, ServiceSecretReference: provider.serviceSecretReference, Environment: provider.environment,
		ConnectorKey: platform.Nango.Key, State: request.State, Code: request.Code, Binding: nangoConnectionBinding(request.Scope, request.IntegrationID, request.AttemptID),
	})
	if err != nil || connection.ConnectorKey != platform.Nango.Key || !saasdiscovery.ValidConnectionReference(connection.Reference) {
		return "", errRuntimeUnavailable
	}
	if _, err := saasdiscovery.LookupTenant(ctx, provider.proxy, platform, connection.Reference, request.TenantID, provider.clock()); err != nil {
		// The connection is not kept: nothing in the product names it.
		_ = provider.client.RevokeConnection(ctx, nango.ConnectionRevocationRequest{
			NangoBaseURL: provider.baseURL, ServiceSecretReference: provider.serviceSecretReference, Environment: provider.environment,
			ConnectorKey: platform.Nango.Key, ConnectionReference: connection.Reference,
			Binding: nango.RevocationBinding{OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String(), IntegrationID: request.IntegrationID},
		})
		var failure *collection.Failure
		if errors.As(err, &failure) && failure.Code() == collection.FailureDenied {
			// Another tenant, or an account that may not read this one.
			return "", apiserver.ErrSaaSSignInTenantMismatch
		}
		return "", errRuntimeUnavailable
	}
	return connection.Reference, nil
}

var _ apiserver.SaaSSignInProvider = (*saasSignInProvider)(nil)

// newProductionSaaSSignIn builds the sign-in over the probe's allow-listed
// proxy and its own Nango connection client. It returns nil when the
// database does not have the sign-in section (or cannot say): saas
// integrations are then connected by reference only, as before.
func newProductionSaaSSignIn(ctx context.Context, config RuntimeConfig, resolver nango.ServiceSecretResolver, probe *saasReferenceProbe, database apiserver.JSONDatabase) (*apiserver.SaaSSignIn, io.Closer, error) {
	if probe == nil || probe.registry == nil || probe.proxy == nil || resolver == nil || !validOptionalNangoConfig(config) || config.NangoBaseURL == "" || !strings.HasPrefix(config.PublicOrigin, "https://") {
		return nil, nil, errRuntimeUnavailable
	}
	store, err := apiserver.NewSaaSSignInRepository(ctx, database)
	if err != nil {
		// The section is not installed, or the catalog could not be asked.
		// Sign-in is an addition to reference authorization, which every
		// saas integration still has: the API starts without it.
		return nil, nil, nil
	}
	client, err := nango.NewProductionConnectionClient(resolver, config.ProviderTimeout)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	provider := &saasSignInProvider{registry: probe.registry, client: client, proxy: probe.proxy, baseURL: config.NangoBaseURL, serviceSecretReference: config.NangoServiceSecretReference, environment: config.NangoEnvironment,
		callbackURL: config.PublicOrigin + "/api/v1/integrations/oauth/callback", clock: func() time.Time { return time.Now().UTC() }}
	return &apiserver.SaaSSignIn{Store: store, Provider: provider}, client, nil
}
