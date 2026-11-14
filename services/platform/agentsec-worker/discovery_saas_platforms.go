package main

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	saasplatforms "github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
)

// The generic saas provider. An integration of it names a platform, a tenant
// and a Nango connection by reference:
//
//	{"connection_reference":"ref:nango/connection/<uuid>","platform":"databricks","tenant_id":"…"}
//
// Nango holds the provider token. The worker resolves no secret for a saas
// collection: what it gives the collector is the connection reference, and
// the collector reads the provider through the Nango proxy.
const discoveryNangoServiceKeyPath = "/var/run/secrets/zasp-nango/service-key"

var (
	discoverySaaSSubjectPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}/[A-Za-z0-9][A-Za-z0-9._-]{0,94}$`)
	discoveryNangoReferencePattern   = regexp.MustCompile(`^ref:nango/[a-z0-9][a-z0-9_./:-]{7,507}$`)
	discoveryNangoEnvironmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
)

type discoveryNangoConfig struct {
	BaseURL, ServiceSecretReference, Environment string
}

// validDiscoveryNangoConfig requires the three Nango settings exactly when
// the saas collector is configured. A worker that does not serve saas has no
// Nango access at all.
func validDiscoveryNangoConfig(saasCollectorVersion, baseURL, serviceSecretReference, environment string) bool {
	if saasCollectorVersion == "" {
		return baseURL == "" && serviceSecretReference == "" && environment == ""
	}
	parsed, err := url.Parse(baseURL)
	return err == nil && parsed.Scheme == "http" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "" && parsed.Port() != "" &&
		strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".svc.cluster.local") && net.ParseIP(parsed.Hostname()) == nil &&
		discoveryNangoReferencePattern.MatchString(serviceSecretReference) && discoveryNangoEnvironmentPattern.MatchString(environment)
}

type discoveryProviderDNSResolver struct{}

func (discoveryProviderDNSResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// newProductionDiscoverySaaSProxy builds the allow-listed Nango proxy of the
// saas collector. Its entries are the proxy rules of the registered
// platforms: a request no platform definition allows is never sent.
func newProductionDiscoverySaaSProxy(config discoveryNangoConfig, providerTimeout time.Duration) (saasdiscovery.Proxy, error) {
	if !validDiscoveryNangoConfig("configured", config.BaseURL, config.ServiceSecretReference, config.Environment) {
		return nil, errRuntimeUnavailable
	}
	registry, err := saasplatforms.Registry()
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	secrets, err := nango.NewFileServiceSecretResolver(discoveryNangoServiceKeyPath, config.ServiceSecretReference)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	// The Nango client bounds one proxied request at ten seconds.
	timeout := min(providerTimeout, 10*time.Second)
	client, err := nango.NewProductionProxyClient(secrets, timeout)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	adapter, err := nango.NewAdapter(nango.Config{BaseURL: config.BaseURL, ServiceSecretReference: config.ServiceSecretReference, Environment: config.Environment, Entries: registry.NangoEntries()}, discoveryProviderDNSResolver{}, client, timeout)
	if err != nil {
		_ = client.Close()
		return nil, errRuntimeUnavailable
	}
	return adapter, nil
}

// resolveSaaS builds the credential envelope of a saas collection. It reads
// no secret and calls no provider: it checks that the integration's
// configuration names the connection the job is bound to and the tenant the
// job expects, and hands the connection reference to the collector. The
// collector's first request asks the platform which tenant the connection
// reaches and refuses any other.
func (resolver *productionDiscoveryCredentialResolver) resolveSaaS(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		ConnectionReference string `json:"connection_reference"`
		Platform            string `json:"platform"`
		TenantID            string `json:"tenant_id"`
	}
	if !decodeCanonicalDiscoveryCredentialJSON(bound.configuration(), &config, 4096) || !saasdiscovery.ValidPlatformToken(config.Platform) || !saasdiscovery.ValidTenantID(config.TenantID) ||
		config.Platform+"/"+config.TenantID != bound.Credential.ExpectedSubject.ID || bound.Credential.ExpectedSubject.Kind != "saas_tenant" || !discoverySaaSSubjectPattern.MatchString(bound.Credential.ExpectedSubject.ID) ||
		config.ConnectionReference != bound.Credential.Reference || !saasdiscovery.ValidConnectionReference(config.ConnectionReference) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	if err := bound.checkCurrent(ctx); err != nil {
		return discoveryCredentialEnvelope{}, err
	}
	reference := []byte(config.ConnectionReference)
	return newDiscoveryCredentialEnvelope(bound, now.Add(discoveryStaticCredentialTTL), func(value *discoveryCredentialEnvelope) { value.BearerToken = reference }), nil
}
