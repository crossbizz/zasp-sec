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
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	testGCPScope               = "organizations/123456789012"
	testGCPFederationReference = "ref:gcp/workload-identity/acme-security/zasp-reader"
	testGCPKeyReference        = "ref:gcp/service-account-key/customer-0001"
	testGCPAudience            = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws"
	testGCPToken               = "gcp-access-token-value-0001"
	testGCPFederationConfig    = `{"audience":"` + testGCPAudience + `","identity_reference":"` + testGCPFederationReference + `","scope":"` + testGCPScope + `"}`
	testGCPKeyConfig           = `{"identity_reference":"` + testGCPKeyReference + `","scope":"` + testGCPScope + `"}`
)

// testGCPKeyFile stands in for a key file: the resolver hands it to the
// token exchanger without reading it.
var testGCPKeyFile = []byte(`{"type":"service_account","client_email":"zasp-reader@acme-security.iam.gserviceaccount.com","private_key":"SENTINEL-gcp-private-key"}`)

// discoveryGCPTokenStub records what the resolver asks of the exchanger.
type discoveryGCPTokenStub struct {
	audience, serviceAccount string
	keyFile                  []byte
	keyFileSeen              []byte
	calls                    int
	err                      error
	expiresIn                time.Duration
	now                      time.Time
}

func (stub *discoveryGCPTokenStub) token() (gcpdiscovery.AccessToken, error) {
	stub.calls++
	if stub.err != nil {
		return gcpdiscovery.AccessToken{}, stub.err
	}
	return gcpdiscovery.AccessToken{Token: []byte(testGCPToken), ExpiresAt: stub.now.Add(stub.expiresIn)}, nil
}

func (stub *discoveryGCPTokenStub) FederatedToken(_ context.Context, audience, serviceAccount string) (gcpdiscovery.AccessToken, error) {
	stub.audience, stub.serviceAccount = audience, serviceAccount
	return stub.token()
}

func (stub *discoveryGCPTokenStub) KeyToken(_ context.Context, keyFile []byte) (gcpdiscovery.AccessToken, error) {
	// keyFileSeen is the resolver's own buffer, to see that it is cleared.
	stub.keyFile, stub.keyFileSeen = bytes.Clone(keyFile), keyFile
	return stub.token()
}

func gcpCredentialResolver(t *testing.T, tokens discoveryGCPTokenAPI, secrets discoverySecretReader, now time.Time) *productionDiscoveryCredentialResolver {
	t.Helper()
	resolver := saasCredentialResolver(t, healthySaaSTokenEndpoint(), secrets, now, false, false)
	resolver.config.GCP = tokens
	return resolver
}

func gcpCredentialInput(scope domain.Scope, reference, configuration string, now time.Time) apiserver.ExecutionJobInput {
	return discoveryCredentialInput(scope, collection.ProviderGCP, collection.CredentialGCPAccessToken, reference, collection.SubjectBinding{Kind: "gcp_scope", ID: testGCPScope}, configuration, now)
}

// With federation the worker stores and reads nothing: the reference names
// the service account, and the exchanger is asked for a token of it.
func TestGCPCredentialFederatesWithoutReadingASecret(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	secrets := &discoverySecretReaderStub{values: map[string][]byte{}}
	tokens := &discoveryGCPTokenStub{now: now, expiresIn: time.Hour}
	resolver := gcpCredentialResolver(t, tokens, secrets, now)
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, gcpCredentialInput(scope, testGCPFederationReference, testGCPFederationConfig, now)))
	defer envelope.Destroy()
	if envelope.Provider != collection.ProviderGCP || envelope.SubjectKind != "gcp_scope" || envelope.SubjectID != testGCPScope || string(envelope.BearerToken) != `{"access_token":"`+testGCPToken+`"}` || !gcpdiscovery.ValidCredential(envelope.BearerToken) {
		t.Fatalf("envelope = %#v", envelope)
	}
	if tokens.calls != 1 || tokens.audience != testGCPAudience || tokens.serviceAccount != "zasp-reader@acme-security.iam.gserviceaccount.com" || tokens.keyFile != nil {
		t.Fatalf("exchange = %#v", tokens)
	}
	if envelope.ExpiresAt.After(now.Add(time.Hour)) || !envelope.ExpiresAt.After(now) {
		t.Fatalf("expiry = %s", envelope.ExpiresAt)
	}
}

// With a key the file is read from the secret store by its reference, used
// once and cleared.
func TestGCPCredentialUsesAStoredKeyAndClearsIt(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testGCPKeyReference: testGCPKeyFile}}
	tokens := &discoveryGCPTokenStub{now: now, expiresIn: 30 * time.Minute}
	resolver := gcpCredentialResolver(t, tokens, secrets, now)
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, gcpCredentialInput(scope, testGCPKeyReference, testGCPKeyConfig, now)))
	defer envelope.Destroy()
	if tokens.calls != 1 || !bytes.Equal(tokens.keyFile, testGCPKeyFile) || tokens.audience != "" || string(envelope.BearerToken) != `{"access_token":"`+testGCPToken+`"}` {
		t.Fatalf("exchange = %#v", tokens)
	}
	if bytes.Contains(tokens.keyFileSeen, []byte("SENTINEL")) {
		t.Fatal("the key file was not cleared after the exchange")
	}
	if bytes.Contains(envelope.BearerToken, []byte("SENTINEL")) {
		t.Fatal("the envelope holds key material")
	}
}

// A configuration that does not match its connection is refused before the
// exchanger or the secret store is touched.
func TestGCPCredentialRejectsBindingAndConfigurationBeforeIO(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	for name, test := range map[string]struct{ reference, configuration string }{
		"another scope":               {testGCPFederationReference, strings.Replace(testGCPFederationConfig, testGCPScope, "organizations/999999999999", 1)},
		"reference of another job":    {testGCPKeyReference, testGCPFederationConfig},
		"federation without audience": {testGCPFederationReference, `{"identity_reference":"` + testGCPFederationReference + `","scope":"` + testGCPScope + `"}`},
		"key with an audience":        {testGCPKeyReference, `{"audience":"` + testGCPAudience + `","identity_reference":"` + testGCPKeyReference + `","scope":"` + testGCPScope + `"}`},
		"unsorted members":            {testGCPKeyReference, `{"scope":"` + testGCPScope + `","identity_reference":"` + testGCPKeyReference + `"}`},
		"an extra member":             {testGCPKeyReference, `{"identity_reference":"` + testGCPKeyReference + `","key":"x","scope":"` + testGCPScope + `"}`},
		"audience of another host":    {testGCPFederationReference, strings.Replace(testGCPFederationConfig, "//iam.googleapis.com", "//iam.example.com", 1)},
	} {
		secrets := &discoverySecretReaderStub{values: map[string][]byte{testGCPKeyReference: testGCPKeyFile}}
		tokens := &discoveryGCPTokenStub{now: now, expiresIn: time.Hour}
		resolver := gcpCredentialResolver(t, tokens, secrets, now)
		_, err := resolver.ResolveDiscoveryCredential(context.Background(), saasCredentialRequest(t, scope, gcpCredentialInput(scope, test.reference, test.configuration, now)))
		if saasFailureCode(err) != collection.FailureMalformed || tokens.calls != 0 || len(secrets.calls) != 0 {
			t.Fatalf("%s: error = %v, exchanges = %d, secret reads = %d", name, err, tokens.calls, len(secrets.calls))
		}
	}
}

func TestGCPCredentialFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	request := func() discoveryCredentialMaterialRequest {
		return saasCredentialRequest(t, scope, gcpCredentialInput(scope, testGCPFederationReference, testGCPFederationConfig, now))
	}
	// Where Google Cloud is not served there is no exchanger.
	unserved := saasCredentialResolver(t, healthySaaSTokenEndpoint(), &discoverySecretReaderStub{values: map[string][]byte{}}, now, false, false)
	if _, err := unserved.ResolveDiscoveryCredential(context.Background(), request()); saasFailureCode(err) != collection.FailureMalformed {
		t.Fatalf("unserved provider = %v", err)
	}
	// An exchange that fails returns one constant failure, not its cause.
	failing := &discoveryGCPTokenStub{now: now, err: errors.New("SENTINEL provider detail")}
	if _, err := gcpCredentialResolver(t, failing, &discoverySecretReaderStub{values: map[string][]byte{}}, now).ResolveDiscoveryCredential(context.Background(), request()); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("failed exchange = %v", err)
	}
	// A token that is already expired is not a credential.
	expired := &discoveryGCPTokenStub{now: now, expiresIn: -time.Minute}
	if _, err := gcpCredentialResolver(t, expired, &discoverySecretReaderStub{values: map[string][]byte{}}, now).ResolveDiscoveryCredential(context.Background(), request()); err == nil {
		t.Fatal("an expired token was accepted")
	}
	// A key reference with no stored key.
	missing := &discoveryGCPTokenStub{now: now, expiresIn: time.Hour}
	keyRequest := saasCredentialRequest(t, scope, gcpCredentialInput(scope, testGCPKeyReference, testGCPKeyConfig, now))
	if _, err := gcpCredentialResolver(t, missing, &discoverySecretReaderStub{values: map[string][]byte{}}, now).ResolveDiscoveryCredential(context.Background(), keyRequest); err == nil || missing.calls != 0 {
		t.Fatalf("missing key = %v, exchanges = %d", err, missing.calls)
	}
}

func TestGCPCredentialEnvelopeIsProviderExact(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	valid := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderGCP, SubjectKind: "gcp_scope", SubjectID: "projects/alpha-prod", ExpiresAt: expires, BearerToken: []byte(`{"access_token":"` + testGCPToken + `"}`)}
	if !validDiscoveryCredentialEnvelope(valid) {
		t.Fatal("the resolver's own envelope is refused")
	}
	for name, mutate := range map[string]func(*discoveryCredentialEnvelope){
		"another subject kind": func(value *discoveryCredentialEnvelope) { value.SubjectKind = "aws_account" },
		"an invalid scope":     func(value *discoveryCredentialEnvelope) { value.SubjectID = "projects/Alpha" },
		"a bare token":         func(value *discoveryCredentialEnvelope) { value.BearerToken = []byte(testGCPToken) },
		"an issuer":            func(value *discoveryCredentialEnvelope) { value.Issuer = "https://accounts.google.com" },
		"aws material":         func(value *discoveryCredentialEnvelope) { value.Region = "us-east-1" },
	} {
		hostile := valid
		mutate(&hostile)
		if validDiscoveryCredentialEnvelope(hostile) {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// The worker's wrapper hands the collector its own JSON credential and
// nothing bound to another scope or provider.
func TestGCPCollectionAPIHandsTheCollectorItsOwnCredential(t *testing.T) {
	subject := collection.SubjectBinding{Kind: "gcp_scope", ID: testGCPScope}
	credential := `{"access_token":"` + testGCPToken + `"}`
	recorder := &saasCollectionAPIRecorder{}
	api := &discoveryBearerCollectionAPI{provider: collection.ProviderGCP, gcp: recorder}
	if err := api.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("readiness: %v", err)
	}
	encoded, err := encodeDiscoveryCredentialEnvelope(discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderGCP, SubjectKind: subject.Kind, SubjectID: subject.ID, ExpiresAt: time.Now().UTC().Add(time.Hour), BearerToken: []byte(credential)})
	if err != nil {
		t.Fatal(err)
	}
	request := githubdiscovery.CollectionPageRequest{Provider: collection.ProviderGCP, Subject: subject, Page: 1}
	if _, err := api.FetchCollectionPage(context.Background(), encoded, request); err != nil || string(recorder.credential) != credential || recorder.request.Subject != subject {
		t.Fatalf("collector received %s for %#v: %v", recorder.credential, recorder.request.Subject, err)
	}
	recorder.credential = nil
	other := request
	other.Subject.ID = "organizations/999999999999"
	if _, err := api.FetchCollectionPage(context.Background(), encoded, other); err == nil || recorder.credential != nil {
		t.Fatal("a credential for another scope reached the collector")
	}
	other = request
	other.Provider = collection.ProviderAWS
	if _, err := api.FetchCollectionPage(context.Background(), encoded, other); err == nil || recorder.credential != nil {
		t.Fatal("a request of another provider reached the collector")
	}
	if err := (&discoveryBearerCollectionAPI{provider: collection.ProviderGCP}).CheckCollectionReadiness(context.Background()); err == nil {
		t.Fatal("a Google Cloud API without a collector reported ready")
	}
}

// Google Cloud is registered only where its collector version is set, with
// its own credential class, and a job must name the configured version.
func TestProductionLiveDiscoveryCollectorFactoryRegistersGoogleCloudWhenConfigured(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	input := gcpCredentialInput(scope, testGCPFederationReference, testGCPFederationConfig, now)
	input.ObservationTime = now.Truncate(time.Second)
	input.CollectorVersion = "gcp_v1"
	binding := discoveryCollectorBinding{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: "lease-token-0000000000000001"}

	unconfigured, err := newProductionLiveDiscoveryCollectorFactory(saasCompositionConfig(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if collector, err := unconfigured.BuildDiscoveryCollector(context.Background(), binding); err == nil || collector != nil || unconfigured.collectorVersion(collection.ProviderGCP) != "" {
		t.Fatal("Google Cloud collects where it is not served")
	}

	config := saasCompositionConfig(t, now)
	config.GCPCollectorVersion = "gcp_v1"
	factory, err := newProductionLiveDiscoveryCollectorFactory(config)
	if err != nil {
		t.Fatal(err)
	}
	registrations := saasCompositionRegistrations(t, factory, scope, now)
	registration, registered := registrations[collection.ProviderGCP]
	if len(registrations) != 5 || !registered || registration.CredentialClass != collection.CredentialGCPAccessToken || registration.CollectorVersion != "gcp_v1" || registration.Client == nil || registration.Readiness == nil || factory.collectorVersion(collection.ProviderGCP) != "gcp_v1" {
		t.Fatalf("registrations = %d, gcp = %#v, %t", len(registrations), registration, registered)
	}
	collector, err := factory.BuildDiscoveryCollector(context.Background(), binding)
	if err != nil || collector == nil {
		t.Fatalf("collector=%v err=%v", collector != nil, err)
	}
	collector.Destroy()
	binding.Input.CollectorVersion = "gcp_v2"
	if drifted, err := factory.BuildDiscoveryCollector(context.Background(), binding); err == nil || drifted != nil {
		t.Fatal("version drift built a collector")
	}
	config.GCPCollectorVersion = "GCP V1"
	if _, err := newProductionLiveDiscoveryCollectorFactory(config); err == nil {
		t.Fatal("an invalid collector version was accepted")
	}
}

func TestWorkerRuntimeConfigReadsTheGoogleCloudCollectorVersion(t *testing.T) {
	unset, err := loadWorkerRuntimeConfig(mapLookup(validDiscoveryRuntimeEnvironment()))
	if err != nil || unset.GCPCollectorVersion != "" || productionDiscoveryDependenciesConfig(unset).GCPCollectorVersion != "" {
		t.Fatalf("config without the version: %q %v", unset.GCPCollectorVersion, err)
	}
	values := validDiscoveryRuntimeEnvironment()
	values["ZASP_DISCOVERY_GCP_COLLECTOR_VERSION"] = "gcp-collector-v1"
	config, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || config.GCPCollectorVersion != "gcp-collector-v1" || productionDiscoveryDependenciesConfig(config).GCPCollectorVersion != "gcp-collector-v1" {
		t.Fatalf("version = %q, %v", config.GCPCollectorVersion, err)
	}
	for _, invalid := range []string{"Collector_V1", "1", "collector v1", "v"} {
		values["ZASP_DISCOVERY_GCP_COLLECTOR_VERSION"] = invalid
		if _, err := loadWorkerRuntimeConfig(mapLookup(values)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatalf("%q error = %v", invalid, err)
		}
	}
}
