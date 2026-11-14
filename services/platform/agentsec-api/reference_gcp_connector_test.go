package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery"
)

const (
	gcpProbeScope     = "folders/700"
	gcpProbeReference = "ref:gcp/workload-identity/acme-security/zasp-reader"
	gcpProbeAudience  = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws"
	gcpProbeToken     = "gcp-probe-access-token-value-0001"
)

type gcpProbeTokens struct {
	audience, serviceAccount string
	keyCalls                 int
	err                      error
}

func (tokens *gcpProbeTokens) FederatedToken(_ context.Context, audience, serviceAccount string) (gcpdiscovery.AccessToken, error) {
	tokens.audience, tokens.serviceAccount = audience, serviceAccount
	if tokens.err != nil {
		return gcpdiscovery.AccessToken{}, tokens.err
	}
	return gcpdiscovery.AccessToken{Token: []byte(gcpProbeToken), ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
}

func (tokens *gcpProbeTokens) KeyToken(context.Context, []byte) (gcpdiscovery.AccessToken, error) {
	tokens.keyCalls++
	return gcpdiscovery.AccessToken{}, errors.New("no key in this test")
}

// gcpProbeResourceManager answers the one read the probe makes.
type gcpProbeResourceManager struct {
	status   int
	body     string
	requests []string
	bearer   string
}

func (fake *gcpProbeResourceManager) RoundTrip(request *http.Request) (*http.Response, error) {
	fake.requests = append(fake.requests, request.Method+" "+request.URL.String())
	fake.bearer = request.Header.Get("Authorization")
	return &http.Response{StatusCode: fake.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(fake.body)), Request: request}, nil
}

func gcpProbeTarget(configuration, reference string) apiserver.ReferenceAuthorizationTarget {
	return apiserver.ReferenceAuthorizationTarget{Configuration: []byte(configuration), ConnectionReference: reference}
}

// The probe obtains a token for the service account the reference names and
// reads the named scope with it; the subject of the connection is the scope.
func TestGCPReferenceProbeReadsTheNamedScopeWithTheServiceAccountToken(t *testing.T) {
	configuration := `{"audience":"` + gcpProbeAudience + `","identity_reference":"` + gcpProbeReference + `","scope":"` + gcpProbeScope + `"}`
	tokens := &gcpProbeTokens{}
	resourceManager := &gcpProbeResourceManager{status: 200, body: `{"name":"folders/700","displayName":"Engineering","state":"ACTIVE"}`}
	scopes, err := gcpdiscovery.NewGCPCollectionAPI(gcpdiscovery.CollectionAPIConfig{Transport: resourceManager, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	probe := &gcpReferenceProbe{tokens: tokens, scopes: scopes}
	subject, err := probe.ProbeReferenceAuthorization(context.Background(), gcpProbeTarget(configuration, gcpProbeReference))
	if err != nil || subject.Kind != "gcp_scope" || subject.ID != gcpProbeScope {
		t.Fatalf("subject = %#v, %v", subject, err)
	}
	if tokens.audience != gcpProbeAudience || tokens.serviceAccount != "zasp-reader@acme-security.iam.gserviceaccount.com" || tokens.keyCalls != 0 {
		t.Fatalf("token request = %#v", tokens)
	}
	if len(resourceManager.requests) != 1 || resourceManager.requests[0] != "GET https://cloudresourcemanager.googleapis.com/v3/folders/700" || resourceManager.bearer != "Bearer "+gcpProbeToken {
		t.Fatalf("scope read = %v", resourceManager.requests)
	}

	// A scope the service account cannot read, or another scope's answer.
	for name, answer := range map[string]gcpProbeResourceManager{
		"refused":       {status: 403, body: `{"error":{"code":403}}`},
		"another scope": {status: 200, body: `{"name":"folders/701","state":"ACTIVE"}`},
		"being deleted": {status: 200, body: `{"name":"folders/700","state":"DELETE_REQUESTED"}`},
	} {
		fake := answer
		refusing, _ := gcpdiscovery.NewGCPCollectionAPI(gcpdiscovery.CollectionAPIConfig{Transport: &fake, Timeout: time.Second})
		if _, err := (&gcpReferenceProbe{tokens: &gcpProbeTokens{}, scopes: refusing}).ProbeReferenceAuthorization(context.Background(), gcpProbeTarget(configuration, gcpProbeReference)); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// No token, no read.
	failing := &gcpProbeTokens{err: errors.New("SENTINEL exchange detail")}
	quiet := &gcpProbeResourceManager{status: 200, body: `{"name":"folders/700"}`}
	unread, _ := gcpdiscovery.NewGCPCollectionAPI(gcpdiscovery.CollectionAPIConfig{Transport: quiet, Timeout: time.Second})
	if _, err := (&gcpReferenceProbe{tokens: failing, scopes: unread}).ProbeReferenceAuthorization(context.Background(), gcpProbeTarget(configuration, gcpProbeReference)); !errors.Is(err, errRuntimeUnavailable) || strings.Contains(err.Error(), "SENTINEL") || len(quiet.requests) != 0 {
		t.Fatalf("failed exchange = %v, reads = %d", err, len(quiet.requests))
	}
}

// A configuration that does not match its connection, or mixes the two
// shapes, is refused before a token is requested.
func TestGCPReferenceProbeRefusesAConfigurationThatIsNotItsConnection(t *testing.T) {
	keyReference := "ref:gcp/service-account-key/customer-0001"
	for name, target := range map[string]apiserver.ReferenceAuthorizationTarget{
		"reference of another connection": gcpProbeTarget(`{"audience":"`+gcpProbeAudience+`","identity_reference":"`+gcpProbeReference+`","scope":"`+gcpProbeScope+`"}`, "ref:gcp/workload-identity/acme-security/other-reader"),
		"federation without an audience":  gcpProbeTarget(`{"identity_reference":"`+gcpProbeReference+`","scope":"`+gcpProbeScope+`"}`, gcpProbeReference),
		"key with an audience":            gcpProbeTarget(`{"audience":"`+gcpProbeAudience+`","identity_reference":"`+keyReference+`","scope":"`+gcpProbeScope+`"}`, keyReference),
		"invalid scope":                   gcpProbeTarget(`{"audience":"`+gcpProbeAudience+`","identity_reference":"`+gcpProbeReference+`","scope":"folders/abc"}`, gcpProbeReference),
		"a key in the configuration":      gcpProbeTarget(`{"identity_reference":"`+keyReference+`","private_key":"x","scope":"`+gcpProbeScope+`"}`, keyReference),
		"not JSON":                        gcpProbeTarget(`scope=folders/700`, gcpProbeReference),
	} {
		tokens := &gcpProbeTokens{}
		resourceManager := &gcpProbeResourceManager{status: 200, body: `{"name":"folders/700"}`}
		scopes, _ := gcpdiscovery.NewGCPCollectionAPI(gcpdiscovery.CollectionAPIConfig{Transport: resourceManager, Timeout: time.Second})
		if _, err := (&gcpReferenceProbe{tokens: tokens, scopes: scopes}).ProbeReferenceAuthorization(context.Background(), target); !errors.Is(err, errRuntimeUnavailable) || tokens.audience != "" || tokens.keyCalls != 0 || len(resourceManager.requests) != 0 {
			t.Fatalf("%s: err=%v tokens=%#v reads=%d", name, err, tokens, len(resourceManager.requests))
		}
	}
	// A key reference needs the secret store.
	if _, err := (&gcpReferenceProbe{tokens: &gcpProbeTokens{}, scopes: &gcpdiscovery.GCPCollectionAPI{}}).ProbeReferenceAuthorization(context.Background(), gcpProbeTarget(`{"identity_reference":"`+keyReference+`","scope":"`+gcpProbeScope+`"}`, keyReference)); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("key without a secret store = %v", err)
	}
}

// Google Cloud is offered only where the deployment names its collector.
func TestRuntimeConfigReadsTheGoogleCloudCollectorVersion(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	unset, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || unset.GCPCollectorVersion != "" {
		t.Fatalf("default config: %q %v", unset.GCPCollectorVersion, err)
	}
	values["ZASP_DISCOVERY_GCP_COLLECTOR_VERSION"] = "gcp-collector-v1"
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || config.GCPCollectorVersion != "gcp-collector-v1" {
		t.Fatalf("configured version: %q %v", config.GCPCollectorVersion, err)
	}
	values["ZASP_DISCOVERY_GCP_COLLECTOR_VERSION"] = "GCP Collector"
	if _, err := loadRuntimeConfig(func(key string) string { return values[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
		t.Fatalf("malformed version: %v", err)
	}
}
