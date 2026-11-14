package main

import (
	"context"
	"io"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
)

// saasReferenceProbe authorizes an integration of the generic saas provider.
// The integration names a Nango connection by reference; the probe asks the
// platform, through the allow-listed Nango proxy, which tenant that
// connection reaches and requires it to be the configured tenant. The
// subject is "<platform>/<tenant id>". The probe never holds a provider
// token: Nango adds it on its side.
type saasReferenceProbe struct {
	registry *saasdiscovery.Registry
	proxy    saasdiscovery.Proxy
	clock    func() time.Time
}

func (probe *saasReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target apiserver.ReferenceAuthorizationTarget) (apiserver.ReferenceAuthorizationSubject, error) {
	var config struct {
		ConnectionReference string `json:"connection_reference"`
		Platform            string `json:"platform"`
		TenantID            string `json:"tenant_id"`
	}
	if probe == nil || probe.registry == nil || probe.proxy == nil || probe.clock == nil || ctx == nil || ctx.Err() != nil || !decodeStrictReferenceJSON(target.Configuration, &config, 4096) ||
		config.ConnectionReference != target.ConnectionReference || !saasdiscovery.ValidConnectionReference(config.ConnectionReference) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	platform, known := probe.registry.Platform(config.Platform)
	if !known || !platform.ValidTenant(config.TenantID) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	tenant, err := saasdiscovery.LookupTenant(ctx, probe.proxy, platform, config.ConnectionReference, config.TenantID, probe.clock())
	// A connection of another tenant is refused: the integration would
	// otherwise inventory a tenant its configuration does not name.
	if err != nil || tenant.ID != config.TenantID {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	return apiserver.ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: platform.SubjectID(config.TenantID)}, nil
}

var _ apiserver.ReferenceAuthorizationProbe = (*saasReferenceProbe)(nil)

// newProductionSaaSReferenceProbe builds the probe over its own Nango proxy
// adapter, whose entries are the proxy rules of the registered platforms.
// The saas provider cannot be served without Nango.
func newProductionSaaSReferenceProbe(config RuntimeConfig, resolver nango.ServiceSecretResolver) (*saasReferenceProbe, io.Closer, error) {
	if config.SaaSCollectorVersion == "" || config.NangoBaseURL == "" || !validOptionalNangoConfig(config) || resolver == nil {
		return nil, nil, errRuntimeUnavailable
	}
	registry, err := platforms.Registry()
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	client, err := nango.NewProductionProxyClient(resolver, config.ProviderTimeout)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	adapter, err := nango.NewAdapter(nango.Config{BaseURL: config.NangoBaseURL, ServiceSecretReference: config.NangoServiceSecretReference, Environment: config.NangoEnvironment, Entries: registry.NangoEntries()}, nangoProviderDNSResolver{}, client, config.ProviderTimeout)
	if err != nil {
		_ = client.Close()
		return nil, nil, errRuntimeUnavailable
	}
	return &saasReferenceProbe{registry: registry, proxy: adapter, clock: func() time.Time { return time.Now().UTC() }}, client, nil
}
