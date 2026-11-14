package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	saasplatforms "github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	testSaaSConnection = saastest.ConnectionReference
	testSaaSSubject    = "databricks/1234567890123456"
	testSaaSConfig     = `{"connection_reference":"` + saastest.ConnectionReference + `","platform":"databricks","tenant_id":"1234567890123456"}`
)

func saasPlatformCredentialInput(scope domain.Scope, configuration string, now time.Time) apiserver.ExecutionJobInput {
	return discoveryCredentialInput(scope, collection.ProviderSaaS, collection.CredentialNangoConnection, testSaaSConnection, collection.SubjectBinding{Kind: "saas_tenant", ID: testSaaSSubject}, configuration, now)
}

func saasPlatformStandIn(t *testing.T) *saastest.Nango {
	t.Helper()
	registry, err := saasplatforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	return saastest.NewNango(t, registry, map[string]saastest.Route{
		"/api/2.1/unity-catalog/current-metastore-assignment": saastest.Static(`{"metastore_id":"m","workspace_id":1234567890123456}`),
		"/api/2.0/serving-endpoints":                          saastest.Static(`{"endpoints":[{"name":"support-agent","id":"0a1b2c3d4e5f","state":{"ready":"READY"},"task":"agent/v1/responses"}]}`),
	})
}

// The credential of a saas collection is the Nango connection reference. The
// worker reads no secret and calls no provider to build it.
func TestSaaSCredentialIsTheNangoConnectionReference(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	endpoint := healthySaaSTokenEndpoint()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{}}
	resolver := saasCredentialResolver(t, endpoint, secrets, now, false, false)
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, saasPlatformCredentialInput(scope, testSaaSConfig, now)))
	defer envelope.Destroy()
	if envelope.Provider != collection.ProviderSaaS || envelope.SubjectKind != "saas_tenant" || envelope.SubjectID != testSaaSSubject || string(envelope.BearerToken) != testSaaSConnection {
		t.Fatalf("envelope = %#v bearer=%s", envelope, envelope.BearerToken)
	}
	if !envelope.ExpiresAt.Equal(now.Add(discoveryStaticCredentialTTL)) {
		t.Fatalf("expiry = %s", envelope.ExpiresAt)
	}
	if len(secrets.calls) != 0 || len(endpoint.requests) != 0 {
		t.Fatalf("a saas credential read %d secrets and made %d provider requests", len(secrets.calls), len(endpoint.requests))
	}

	replace := func(old, new string) string { return strings.Replace(testSaaSConfig, old, new, 1) }
	for name, configuration := range map[string]string{
		"another tenant than the job's subject":  replace("1234567890123456", "9999999999999999"),
		"another platform than the job's":        replace(`"databricks"`, `"slack"`),
		"another connection than the job's":      replace("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"),
		"a reference that is not a connection":   replace(testSaaSConnection, "ref:nango/service-key-0001"),
		"a token where the reference belongs":    replace(testSaaSConnection, "dapi" + "0123456789abcdef0123456789abcdef"),
		"a member the configuration cannot hold": replace(`"platform"`, `"access_token":"dapi","platform"`),
		"members out of canonical order":         `{"platform":"databricks","connection_reference":"` + testSaaSConnection + `","tenant_id":"1234567890123456"}`,
	} {
		_, err := resolver.ResolveDiscoveryCredential(context.Background(), saasCredentialRequest(t, scope, saasPlatformCredentialInput(scope, configuration, now)))
		var failure *collection.Failure
		if !errors.As(err, &failure) || failure.Code() != collection.FailureMalformed {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// An envelope may carry only a connection reference as saas material.
	for name, mutate := range map[string]func(*discoveryCredentialEnvelope){
		"a provider token": func(value *discoveryCredentialEnvelope) {
			value.BearerToken = []byte("dapi" + "0123456789abcdef0123456789abcdef")
		},
		"another provider's subject":  func(value *discoveryCredentialEnvelope) { value.SubjectKind = "salesforce_org" },
		"a subject without platform":  func(value *discoveryCredentialEnvelope) { value.SubjectID = "1234567890123456" },
		"an issuer":                   func(value *discoveryCredentialEnvelope) { value.Issuer = "https://acme.okta.com" },
		"cloud credentials alongside": func(value *discoveryCredentialEnvelope) { value.Region = "us-east-1" },
	} {
		hostile := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderSaaS, SubjectKind: "saas_tenant", SubjectID: testSaaSSubject, ExpiresAt: now.Add(time.Minute), BearerToken: []byte(testSaaSConnection)}
		if !validDiscoveryCredentialEnvelope(hostile) {
			t.Fatal("the valid saas envelope was refused")
		}
		mutate(&hostile)
		if validDiscoveryCredentialEnvelope(hostile) {
			t.Fatalf("%s: envelope accepted", name)
		}
	}
}

// A deployment that sets the saas collector version registers the generic
// provider, and its collector reads the platform through the Nango proxy with
// the connection reference from the worker's credential envelope.
func TestSaaSProviderIsRegisteredAndCollectsThroughTheNangoProxy(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	standIn := saasPlatformStandIn(t)

	// Not served by default: no registration, and a saas job builds nothing.
	unserved, err := newProductionLiveDiscoveryCollectorFactory(saasCompositionConfig(t, now))
	if err != nil {
		t.Fatal(err)
	}
	input := saasPlatformCredentialInput(scope, testSaaSConfig, now)
	input.ObservationTime = now.Truncate(time.Second)
	input.CollectorVersion = "collector_v1"
	binding := discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"}
	if _, registered := saasCompositionRegistrations(t, unserved, scope, now)[collection.ProviderSaaS]; registered || unserved.collectorVersion(collection.ProviderSaaS) != "" {
		t.Fatal("saas is registered without a collector version")
	}
	if collector, err := unserved.BuildDiscoveryCollector(context.Background(), binding); err == nil || collector != nil {
		t.Fatal("a saas job built a collector where saas is not served")
	}
	// The version and the proxy come together.
	for name, mutate := range map[string]func(*productionDiscoveryClientConfig){
		"a version without a proxy": func(config *productionDiscoveryClientConfig) { config.SaaSCollectorVersion = "collector_v1" },
		"a proxy without a version": func(config *productionDiscoveryClientConfig) { config.SaaSProxy = standIn.Proxy() },
		"a malformed version": func(config *productionDiscoveryClientConfig) {
			config.SaaSCollectorVersion, config.SaaSProxy = "Collector V1", standIn.Proxy()
		},
	} {
		config := saasCompositionConfig(t, now)
		mutate(&config)
		if factory, err := newProductionLiveDiscoveryCollectorFactory(config); err == nil || factory != nil {
			t.Fatalf("%s: factory built", name)
		}
	}

	config := saasCompositionConfig(t, now)
	config.SaaSCollectorVersion, config.SaaSProxy = "collector_v1", standIn.Proxy()
	factory, err := newProductionLiveDiscoveryCollectorFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	registrations := saasCompositionRegistrations(t, factory, scope, now)
	registration, registered := registrations[collection.ProviderSaaS]
	if !registered || len(registrations) != 5 || registration.CredentialClass != collection.CredentialNangoConnection || registration.CollectorVersion != "collector_v1" || registration.Client == nil || registration.Readiness == nil || factory.collectorVersion(collection.ProviderSaaS) != "collector_v1" {
		t.Fatalf("saas registration = %#v, %t, of %d", registration, registered, len(registrations))
	}
	collector, err := factory.BuildDiscoveryCollector(context.Background(), binding)
	if err != nil || collector == nil {
		t.Fatalf("saas collector=%v err=%v", collector != nil, err)
	}
	collector.Destroy()
	drifted := binding
	drifted.Input.CollectorVersion = "collector_v2"
	if collector, err := factory.BuildDiscoveryCollector(context.Background(), drifted); err == nil || collector != nil {
		t.Fatal("saas version drift built a collector")
	}

	// The worker's bearer binding hands the collector the connection
	// reference out of the envelope; the first page is the tenant.
	registry, err := saasplatforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	api, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: standIn.Proxy()})
	if err != nil {
		t.Fatal(err)
	}
	bound := &discoveryBearerCollectionAPI{provider: collection.ProviderSaaS, saas: api, timeout: time.Second}
	if err := bound.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	subject := collection.SubjectBinding{Kind: "saas_tenant", ID: testSaaSSubject}
	envelope, err := encodeDiscoveryCredentialEnvelope(discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderSaaS, SubjectKind: subject.Kind, SubjectID: subject.ID, ExpiresAt: time.Now().UTC().Add(time.Minute), BearerToken: []byte(testSaaSConnection)})
	if err != nil {
		t.Fatal(err)
	}
	request := saasdiscovery.CollectionPageRequest{Provider: collection.ProviderSaaS, Subject: subject, Page: 1, RemainingItems: 100, RemainingRelationships: 100, RemainingBytes: 1 << 20}
	page, err := bound.FetchCollectionPage(context.Background(), envelope, request)
	if err != nil || len(page.Entities) != 1 || page.Complete || !bytes.Contains(page.Entities[0], []byte(`"kind":"saas_tenant"`)) || bytes.Contains(page.Raw, []byte(testSaaSConnection)) {
		t.Fatalf("tenant page = %s, %v", page.Raw, err)
	}
	calls := standIn.Calls()
	if len(calls) != 1 || calls[0].Key != "databricks" || calls[0].Path != "/api/2.1/unity-catalog/current-metastore-assignment" {
		t.Fatalf("calls = %+v", calls)
	}
	// An envelope of another tenant than the page asks for is refused before
	// any request.
	other := request
	other.Subject.ID = "databricks/9999999999999999"
	if _, err := bound.FetchCollectionPage(context.Background(), envelope, other); err == nil || len(standIn.Calls()) != 1 {
		t.Fatalf("another tenant: %v after %d calls", err, len(standIn.Calls()))
	}
}

func TestWorkerRuntimeConfigServesSaaSOnlyWithNango(t *testing.T) {
	for name, test := range map[string]struct {
		version, baseURL, reference, environment string
		want                                     bool
	}{
		"neither":                       {"", "", "", "", true},
		"saas with Nango":               {"collector_v1", "http://nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "prod", true},
		"saas without Nango":            {"collector_v1", "", "", "", false},
		"Nango without saas":            {"", "http://nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "prod", false},
		"Nango outside the cluster":     {"collector_v1", "http://nango.example.com:3003", "ref:nango/service-key-0001", "prod", false},
		"Nango by address":              {"collector_v1", "http://10.0.0.7:3003", "ref:nango/service-key-0001", "prod", false},
		"Nango with a path":             {"collector_v1", "http://nango.zasp.svc.cluster.local:3003/proxy", "ref:nango/service-key-0001", "prod", false},
		"a key instead of a reference":  {"collector_v1", "http://nango.zasp.svc.cluster.local:3003", "00000000-0000-4000-8000-000000000001", "prod", false},
		"an environment in upper case":  {"collector_v1", "http://nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "Prod", false},
		"credentials in the Nango URL":  {"collector_v1", "http://user:pass@nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "prod", false},
		"a Nango URL without its port":  {"collector_v1", "http://nango.zasp.svc.cluster.local", "ref:nango/service-key-0001", "prod", false},
		"a Nango URL with a query":      {"collector_v1", "http://nango.zasp.svc.cluster.local:3003?x=1", "ref:nango/service-key-0001", "prod", false},
		"an HTTPS Nango URL":            {"collector_v1", "https://nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "prod", false},
		"a reference of another system": {"collector_v1", "http://nango.zasp.svc.cluster.local:3003", "ref:okta/client-secret-0001", "prod", false},
	} {
		if got := validDiscoveryNangoConfig(test.version, test.baseURL, test.reference, test.environment); got != test.want {
			t.Fatalf("%s: valid = %t", name, got)
		}
	}
	// The worker reads the same variables as the API and passes them on.
	values := validDiscoveryRuntimeEnvironment()
	values["ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION"] = "collector_v1"
	values["ZASP_NANGO_BASE_URL"], values["ZASP_NANGO_SERVICE_SECRET_REFERENCE"], values["ZASP_NANGO_ENVIRONMENT"] = "http://nango.zasp.svc.cluster.local:3003", "ref:nango/service-key-0001", "prod"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.SaaSCollectorVersion != "collector_v1" {
		t.Fatalf("saas worker config = %q, %v", config.SaaSCollectorVersion, err)
	}
	dependencies := productionDiscoveryDependenciesConfig(config)
	if dependencies.SaaSCollectorVersion != "collector_v1" || dependencies.Nango != (discoveryNangoConfig{BaseURL: "http://nango.zasp.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "prod"}) {
		t.Fatalf("dependencies = %q %#v", dependencies.SaaSCollectorVersion, dependencies.Nango)
	}
	delete(values, "ZASP_NANGO_BASE_URL")
	if _, err := loadWorkerRuntimeConfig(mapLookup(values)); err == nil {
		t.Fatal("saas without the Nango URL was accepted")
	}
	// The proxy is built from the platform registry and the mounted key path.
	proxy, err := newProductionDiscoverySaaSProxy(dependencies.Nango, 30*time.Second)
	if err != nil || proxy == nil {
		t.Fatalf("production saas proxy: %v", err)
	}
	if _, err := newProductionDiscoverySaaSProxy(discoveryNangoConfig{}, time.Second); err == nil {
		t.Fatal("a proxy was built without Nango settings")
	}
}
