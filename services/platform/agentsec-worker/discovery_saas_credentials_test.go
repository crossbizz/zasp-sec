package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/microsoftdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/salesforcediscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	testMicrosoftTenant       = "0a1b2c3d-1111-2222-3333-444455556666"
	testMicrosoftClient       = "11111111-2222-3333-4444-555555555555"
	testMicrosoftReference    = "ref:microsoft/client-secret/customer-0001"
	testMicrosoftDataverse    = "https://org1234.crm4.dynamics.com"
	testMicrosoftSecret       = "SENTINEL-microsoft-client-secret-value"
	testMicrosoftGraphToken   = "graph-access-token-value-0001"
	testMicrosoftDataverseTok = "dataverse-access-token-value-0001"
	testSalesforceInstance    = "https://acme.my.salesforce.com"
	testSalesforceOrg         = "00D5e000000abcdEAA"
	testSalesforceClient      = "3MVG9abcdefghijklmnopqrstuvwxyz.ABCDEF_0123456789"
	testSalesforceReference   = "ref:salesforce/client-secret/customer-0001"
	testSalesforceSecret      = "SENTINEL-salesforce-consumer-secret-value"
	testSalesforceToken       = "00D5e000000abcd!AQ0AQsalesforce.access.token"
	testMicrosoftConfig       = `{"client_id":"` + testMicrosoftClient + `","client_secret_reference":"` + testMicrosoftReference + `","tenant_id":"` + testMicrosoftTenant + `"}`
	testMicrosoftDataverseCfg = `{"client_id":"` + testMicrosoftClient + `","client_secret_reference":"` + testMicrosoftReference + `","dataverse_url":"` + testMicrosoftDataverse + `","tenant_id":"` + testMicrosoftTenant + `"}`
	testSalesforceConfig      = `{"client_id":"` + testSalesforceClient + `","client_secret_reference":"` + testSalesforceReference + `","instance_url":"` + testSalesforceInstance + `","organization_id":"` + testSalesforceOrg + `"}`
)

// discoverySaaSTokenEndpoint is a fake token endpoint: it records every
// request and answers by host and scope.
type discoverySaaSTokenEndpoint struct {
	mu       sync.Mutex
	requests []discoverySaaSTokenRequest
	respond  func(host, path string, form url.Values) (int, string, string)
}

type discoverySaaSTokenRequest struct {
	Method, URL string
	Header      http.Header
	Form        url.Values
}

func (endpoint *discoverySaaSTokenEndpoint) RoundTrip(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	form, _ := url.ParseQuery(string(body))
	endpoint.mu.Lock()
	endpoint.requests = append(endpoint.requests, discoverySaaSTokenRequest{Method: request.Method, URL: request.URL.String(), Header: request.Header.Clone(), Form: form})
	endpoint.mu.Unlock()
	status, contentType, payload := endpoint.respond(request.URL.Host, request.URL.Path, form)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(payload)), Request: request}, nil
}

func microsoftTokenBody(token string, expiresIn string) string {
	return `{"token_type":"Bearer","expires_in":` + expiresIn + `,"ext_expires_in":` + expiresIn + `,"access_token":"` + token + `"}`
}

func salesforceTokenBody(token, instanceURL, identity string) string {
	return `{"access_token":"` + token + `","signature":"c2lnbmF0dXJl","scope":"api","instance_url":"` + instanceURL + `","id":"` + identity + `","token_type":"Bearer","issued_at":"1700000000000"}`
}

func healthySaaSTokenEndpoint() *discoverySaaSTokenEndpoint {
	return &discoverySaaSTokenEndpoint{respond: func(host, _ string, form url.Values) (int, string, string) {
		switch {
		case host == "login.microsoftonline.com" && form.Get("scope") == discoveryMicrosoftGraphScope:
			return http.StatusOK, "application/json; charset=utf-8", microsoftTokenBody(testMicrosoftGraphToken, "3599")
		case host == "login.microsoftonline.com":
			return http.StatusOK, "application/json; charset=utf-8", microsoftTokenBody(testMicrosoftDataverseTok, "1800")
		default:
			return http.StatusOK, "application/json;charset=UTF-8", salesforceTokenBody(testSalesforceToken, testSalesforceInstance, "https://login.salesforce.com/id/"+testSalesforceOrg+"/0055e000000userAAA")
		}
	}}
}

func saasCredentialResolver(t *testing.T, endpoint http.RoundTripper, secrets discoverySecretReader, now time.Time, microsoftEnabled, salesforceEnabled bool) *productionDiscoveryCredentialResolver {
	t.Helper()
	client := &http.Client{Transport: endpoint, Timeout: time.Second, CheckRedirect: rejectDiscoveryProviderRedirect}
	config := productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: &discoveryAssumeRoleStub{}, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }}
	if microsoftEnabled {
		microsoft, err := newProductionDiscoveryMicrosoftTokenClient(client, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		config.Microsoft = microsoft
	}
	if salesforceEnabled {
		salesforce, err := newProductionDiscoverySalesforceTokenClient(client)
		if err != nil {
			t.Fatal(err)
		}
		config.Salesforce = salesforce
	}
	resolver, err := newProductionDiscoveryCredentialResolver(config)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	return resolver
}

func microsoftCredentialInput(scope domain.Scope, configuration string, now time.Time) apiserver.ExecutionJobInput {
	return discoveryCredentialInput(scope, collection.ProviderMicrosoft, collection.CredentialMicrosoftClient, testMicrosoftReference, collection.SubjectBinding{Kind: "microsoft_tenant", ID: testMicrosoftTenant}, configuration, now)
}

func salesforceCredentialInput(scope domain.Scope, configuration string, now time.Time) apiserver.ExecutionJobInput {
	return discoveryCredentialInput(scope, collection.ProviderSalesforce, collection.CredentialSalesforceClient, testSalesforceReference, collection.SubjectBinding{Kind: "salesforce_org", ID: testSalesforceOrg}, configuration, now)
}

func saasCredentialRequest(t *testing.T, scope domain.Scope, input apiserver.ExecutionJobInput) discoveryCredentialMaterialRequest {
	t.Helper()
	return discoveryCredentialMaterialRequest{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: []byte("lease-token-0000000000000001"), Credential: credentialRequestForJob(mustCollectionRequest(t, scope, input))}
}

func resolvedSaaSEnvelope(t *testing.T, resolver *productionDiscoveryCredentialResolver, request discoveryCredentialMaterialRequest) discoveryCredentialEnvelope {
	t.Helper()
	material, err := resolver.ResolveDiscoveryCredential(context.Background(), request)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	defer material.Destroy()
	var envelope discoveryCredentialEnvelope
	if err := material.Use(request.Credential, func(value []byte) error {
		var decodeErr error
		envelope, decodeErr = decodeDiscoveryCredentialEnvelope(value)
		return decodeErr
	}); err != nil {
		t.Fatalf("use: %v", err)
	}
	return envelope
}

func saasFailureCode(err error) collection.FailureCode {
	var failure *collection.Failure
	if errors.As(err, &failure) && failure != nil {
		return failure.Code()
	}
	return ""
}

func TestMicrosoftCredentialResolvesGraphTokenFromTheTenantEndpoint(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	endpoint := healthySaaSTokenEndpoint()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret)}}
	resolver := saasCredentialResolver(t, endpoint, secrets, now, true, false)
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, microsoftCredentialInput(scope, testMicrosoftConfig, now)))
	defer envelope.Destroy()

	if envelope.Provider != collection.ProviderMicrosoft || envelope.SubjectKind != "microsoft_tenant" || envelope.SubjectID != testMicrosoftTenant || string(envelope.BearerToken) != `{"graph_token":"`+testMicrosoftGraphToken+`"}` {
		t.Fatalf("envelope = %#v bearer=%s", envelope, envelope.BearerToken)
	}
	// 3599 seconds from the provider, less the 30-second margin, cut to a second.
	if want := now.Add(3599 * time.Second).Truncate(time.Second).Add(-30 * time.Second); !envelope.ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %s, want %s", envelope.ExpiresAt, want)
	}
	if !equalStrings(secrets.calls, []string{testMicrosoftReference}) || len(endpoint.requests) != 1 {
		t.Fatalf("secret calls=%v requests=%d", secrets.calls, len(endpoint.requests))
	}
	request := endpoint.requests[0]
	if request.Method != http.MethodPost || request.URL != "https://login.microsoftonline.com/"+testMicrosoftTenant+"/oauth2/v2.0/token" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("Authorization") != "" {
		t.Fatalf("request = %#v", request)
	}
	if len(request.Form) != 4 || request.Form.Get("client_id") != testMicrosoftClient || request.Form.Get("client_secret") != testMicrosoftSecret || request.Form.Get("grant_type") != "client_credentials" || request.Form.Get("scope") != "https://graph.microsoft.com/.default" {
		t.Fatalf("form = %v", request.Form)
	}
}

func TestMicrosoftCredentialAddsADataverseTokenWhenAnEnvironmentIsConfigured(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	endpoint := healthySaaSTokenEndpoint()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret)}}
	resolver := saasCredentialResolver(t, endpoint, secrets, now, true, false)
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, microsoftCredentialInput(scope, testMicrosoftDataverseCfg, now)))
	defer envelope.Destroy()

	want := `{"dataverse_token":"` + testMicrosoftDataverseTok + `","dataverse_url":"` + testMicrosoftDataverse + `","graph_token":"` + testMicrosoftGraphToken + `"}`
	if string(envelope.BearerToken) != want {
		t.Fatalf("collector credential = %s, want %s", envelope.BearerToken, want)
	}
	// The credential lasts as long as its shorter-lived token (1800 seconds).
	if wantExpiry := now.Add(1800 * time.Second).Truncate(time.Second).Add(-30 * time.Second); !envelope.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expiry = %s, want %s", envelope.ExpiresAt, wantExpiry)
	}
	if len(endpoint.requests) != 2 || endpoint.requests[0].Form.Get("scope") != "https://graph.microsoft.com/.default" || endpoint.requests[1].Form.Get("scope") != testMicrosoftDataverse+"/.default" || endpoint.requests[1].URL != endpoint.requests[0].URL {
		t.Fatalf("requests = %#v", endpoint.requests)
	}
	// One secret read serves both exchanges.
	if !equalStrings(secrets.calls, []string{testMicrosoftReference}) {
		t.Fatalf("secret calls = %v", secrets.calls)
	}
}

func TestSalesforceCredentialResolvesATokenForTheConfiguredInstanceAndOrg(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	endpoint := healthySaaSTokenEndpoint()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testSalesforceReference: []byte(testSalesforceSecret)}}
	resolver := saasCredentialResolver(t, endpoint, secrets, now, false, true)
	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, salesforceCredentialInput(scope, testSalesforceConfig, now)))
	defer envelope.Destroy()

	if envelope.Provider != collection.ProviderSalesforce || envelope.SubjectKind != "salesforce_org" || envelope.SubjectID != testSalesforceOrg || string(envelope.BearerToken) != `{"access_token":"`+testSalesforceToken+`","instance_url":"`+testSalesforceInstance+`"}` {
		t.Fatalf("envelope = %#v bearer=%s", envelope, envelope.BearerToken)
	}
	if !envelope.ExpiresAt.Equal(now.Add(discoveryStaticCredentialTTL)) {
		t.Fatalf("expiry = %s", envelope.ExpiresAt)
	}
	if len(endpoint.requests) != 1 {
		t.Fatalf("requests = %d", len(endpoint.requests))
	}
	request := endpoint.requests[0]
	if request.Method != http.MethodPost || request.URL != testSalesforceInstance+"/services/oauth2/token" || len(request.Form) != 3 || request.Form.Get("grant_type") != "client_credentials" || request.Form.Get("client_id") != testSalesforceClient || request.Form.Get("client_secret") != testSalesforceSecret {
		t.Fatalf("request = %#v", request)
	}
}

func TestSalesforceCredentialAcceptsTheShortOrgIDAndAMissingIdentity(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	for _, identity := range []string{"https://login.salesforce.com/id/" + testSalesforceOrg[:15] + "/0055e000000user", ""} {
		body := salesforceTokenBody(testSalesforceToken, testSalesforceInstance, identity)
		if identity == "" {
			body = `{"access_token":"` + testSalesforceToken + `","instance_url":"` + testSalesforceInstance + `","token_type":"Bearer"}`
		}
		endpoint := &discoverySaaSTokenEndpoint{respond: func(string, string, url.Values) (int, string, string) { return http.StatusOK, "application/json", body }}
		secrets := &discoverySecretReaderStub{values: map[string][]byte{testSalesforceReference: []byte(testSalesforceSecret)}}
		envelope := resolvedSaaSEnvelope(t, saasCredentialResolver(t, endpoint, secrets, now, false, true), saasCredentialRequest(t, scope, salesforceCredentialInput(scope, testSalesforceConfig, now)))
		if !validDiscoverySalesforceCollectorCredential(envelope.BearerToken) {
			t.Fatalf("identity %q: credential = %s", identity, envelope.BearerToken)
		}
		envelope.Destroy()
	}
}

// Every refused token response fails the same way: no credential, a stable
// error, and neither the secret nor anything the provider said in it.
func TestSaaSCredentialsRefuseHostileTokenResponsesWithoutLeaking(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	const providerSentinel = "PROVIDER-ERROR-BODY-SENTINEL"
	microsoftRequest := func() apiserver.ExecutionJobInput { return microsoftCredentialInput(scope, testMicrosoftConfig, now) }
	microsoftDataverseRequest := func() apiserver.ExecutionJobInput {
		return microsoftCredentialInput(scope, testMicrosoftDataverseCfg, now)
	}
	salesforceRequest := func() apiserver.ExecutionJobInput {
		return salesforceCredentialInput(scope, testSalesforceConfig, now)
	}
	fixed := func(status int, contentType, body string) func(string, string, url.Values) (int, string, string) {
		return func(string, string, url.Values) (int, string, string) { return status, contentType, body }
	}
	tests := []struct {
		name     string
		input    func() apiserver.ExecutionJobInput
		respond  func(string, string, url.Values) (int, string, string)
		wantCode collection.FailureCode
	}{
		{"microsoft wrong token type", microsoftRequest, fixed(http.StatusOK, "application/json", `{"token_type":"MAC","expires_in":3599,"access_token":"`+providerSentinel+`-token"}`), collection.FailureRetryable},
		{"microsoft token type is case insensitive only", microsoftRequest, fixed(http.StatusOK, "application/json", `{"token_type":"bearer ","expires_in":3599,"access_token":"`+providerSentinel+`-token"}`), collection.FailureRetryable},
		{"microsoft oversize body", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody(testMicrosoftGraphToken, "3599")+strings.Repeat(" ", 64<<10)), collection.FailureRetryable},
		{"microsoft unauthorized", microsoftRequest, fixed(http.StatusUnauthorized, "application/json", `{"error":"invalid_client","error_description":"`+providerSentinel+` AADSTS7000215"}`), collection.FailureRetryable},
		{"microsoft server error", microsoftRequest, fixed(http.StatusInternalServerError, "text/html", providerSentinel), collection.FailureRetryable},
		{"microsoft wrong media type", microsoftRequest, fixed(http.StatusOK, "text/html", microsoftTokenBody(testMicrosoftGraphToken, "3599")), collection.FailureRetryable},
		{"microsoft short token", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody("short", "3599")), collection.FailureRetryable},
		{"microsoft oversize token", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody(strings.Repeat("t", 8193), "3599")), collection.FailureRetryable},
		{"microsoft token with a quote", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody(`graph-token\"injected-member`, "3599")), collection.FailureRetryable},
		{"microsoft lifetime below a minute", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody(testMicrosoftGraphToken, "59")), collection.FailureRetryable},
		{"microsoft lifetime above a day", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody(testMicrosoftGraphToken, "86401")), collection.FailureRetryable},
		{"microsoft refresh token", microsoftRequest, fixed(http.StatusOK, "application/json", `{"token_type":"Bearer","expires_in":3599,"access_token":"`+testMicrosoftGraphToken+`","refresh_token":"`+providerSentinel+`"}`), collection.FailureRetryable},
		{"microsoft trailing document", microsoftRequest, fixed(http.StatusOK, "application/json", microsoftTokenBody(testMicrosoftGraphToken, "3599")+`{}`), collection.FailureRetryable},
		{"microsoft dataverse token refused", microsoftDataverseRequest, func(_, _ string, form url.Values) (int, string, string) {
			if form.Get("scope") == discoveryMicrosoftGraphScope {
				return http.StatusOK, "application/json", microsoftTokenBody(testMicrosoftGraphToken, "3599")
			}
			return http.StatusBadRequest, "application/json", `{"error":"invalid_resource","error_description":"` + providerSentinel + `"}`
		}, collection.FailureRetryable},
		{"salesforce wrong token type", salesforceRequest, fixed(http.StatusOK, "application/json", strings.Replace(salesforceTokenBody(testSalesforceToken, testSalesforceInstance, ""), `"Bearer"`, `"Basic"`, 1)), collection.FailureRetryable},
		{"salesforce oversize body", salesforceRequest, fixed(http.StatusOK, "application/json", salesforceTokenBody(testSalesforceToken, testSalesforceInstance, "")+strings.Repeat(" ", 64<<10)), collection.FailureRetryable},
		{"salesforce bad request", salesforceRequest, fixed(http.StatusBadRequest, "application/json", `{"error":"invalid_client","error_description":"`+providerSentinel+`"}`), collection.FailureRetryable},
		{"salesforce malformed identity", salesforceRequest, fixed(http.StatusOK, "application/json", salesforceTokenBody(testSalesforceToken, testSalesforceInstance, "https://evil.example/id/"+testSalesforceOrg+"/0055e000000userAAA")), collection.FailureRetryable},
		// A token for another instance or another org is a refusal, not a
		// transient failure: retrying cannot change whom it was issued to.
		{"salesforce instance mismatch", salesforceRequest, fixed(http.StatusOK, "application/json", salesforceTokenBody(testSalesforceToken, "https://other.my.salesforce.com", "https://login.salesforce.com/id/"+testSalesforceOrg+"/0055e000000userAAA")), collection.FailureDenied},
		{"salesforce org mismatch", salesforceRequest, fixed(http.StatusOK, "application/json", salesforceTokenBody(testSalesforceToken, testSalesforceInstance, "https://login.salesforce.com/id/00D5e000000zzzzEAA/0055e000000userAAA")), collection.FailureDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logged bytes.Buffer
			previousLog, previousSlog := log.Writer(), slog.Default()
			log.SetOutput(&logged)
			slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer func() { log.SetOutput(previousLog); slog.SetDefault(previousSlog) }()

			endpoint := &discoverySaaSTokenEndpoint{respond: test.respond}
			secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret), testSalesforceReference: []byte(testSalesforceSecret)}}
			resolver := saasCredentialResolver(t, endpoint, secrets, now, true, true)
			material, err := resolver.ResolveDiscoveryCredential(context.Background(), saasCredentialRequest(t, scope, test.input()))
			if err == nil || material != nil {
				t.Fatalf("hostile token response produced material=%v err=%v", material != nil, err)
			}
			if code := saasFailureCode(err); code != test.wantCode {
				t.Fatalf("failure code = %q, want %q (%v)", code, test.wantCode, err)
			}
			for _, secret := range []string{"SENTINEL", providerSentinel, testMicrosoftGraphToken, testSalesforceToken, testMicrosoftTenant, "salesforce.com"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(logged.String(), secret) {
					t.Fatalf("%q leaked: err=%q log=%q", secret, err, logged.String())
				}
			}
		})
	}
}

func TestSaaSCredentialsRejectBindingAndConfigurationBeforeIO(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	otherTenant := "ffffffff-1111-2222-3333-444455556666"
	tests := []struct {
		name  string
		input apiserver.ExecutionJobInput
	}{
		{"microsoft tenant is not a GUID", microsoftCredentialInput(scope, strings.Replace(testMicrosoftConfig, testMicrosoftTenant, "contoso.onmicrosoft.com", 1), now)},
		{"microsoft tenant is not the bound subject", microsoftCredentialInput(scope, strings.Replace(testMicrosoftConfig, testMicrosoftTenant, otherTenant, 1), now)},
		{"microsoft client is not a GUID", microsoftCredentialInput(scope, strings.Replace(testMicrosoftConfig, testMicrosoftClient, "client", 1), now)},
		{"microsoft reference is not the bound reference", microsoftCredentialInput(scope, strings.Replace(testMicrosoftConfig, "customer-0001", "customer-0002", 1), now)},
		{"microsoft dataverse over plain HTTP", microsoftCredentialInput(scope, strings.Replace(testMicrosoftDataverseCfg, "https://org1234", "http://org1234", 1), now)},
		{"microsoft dataverse on another host", microsoftCredentialInput(scope, strings.Replace(testMicrosoftDataverseCfg, "dynamics.com", "dynamics.com.evil.example", 1), now)},
		{"microsoft dataverse with a path", microsoftCredentialInput(scope, strings.Replace(testMicrosoftDataverseCfg, "dynamics.com", "dynamics.com/api", 1), now)},
		{"microsoft empty dataverse member", microsoftCredentialInput(scope, strings.Replace(testMicrosoftDataverseCfg, testMicrosoftDataverse, "", 1), now)},
		{"microsoft unknown member", microsoftCredentialInput(scope, strings.Replace(testMicrosoftConfig, `"tenant_id"`, `"client_secret":"`+testMicrosoftSecret+`","tenant_id"`, 1), now)},
		{"microsoft unsorted members", microsoftCredentialInput(scope, `{"tenant_id":"`+testMicrosoftTenant+`","client_id":"`+testMicrosoftClient+`","client_secret_reference":"`+testMicrosoftReference+`"}`, now)},
		{"salesforce instance over plain HTTP", salesforceCredentialInput(scope, strings.Replace(testSalesforceConfig, "https://acme", "http://acme", 1), now)},
		{"salesforce instance on another host", salesforceCredentialInput(scope, strings.Replace(testSalesforceConfig, "my.salesforce.com", "my.salesforce.com.evil.example", 1), now)},
		{"salesforce instance is the login host", salesforceCredentialInput(scope, strings.Replace(testSalesforceConfig, testSalesforceInstance, "https://login.salesforce.com", 1), now)},
		{"salesforce consumer key too short", salesforceCredentialInput(scope, strings.Replace(testSalesforceConfig, testSalesforceClient, "short", 1), now)},
		{"salesforce reference is not the bound reference", salesforceCredentialInput(scope, strings.Replace(testSalesforceConfig, "customer-0001", "customer-0002", 1), now)},
	}
	// The bound subject, class and reference grammar are part of the binding.
	wrongOrg := salesforceCredentialInput(scope, strings.Replace(testSalesforceConfig, testSalesforceOrg, "00D5e000000zzzzEAA", 1), now)
	tests = append(tests, struct {
		name  string
		input apiserver.ExecutionJobInput
	}{"salesforce org is not the bound subject", wrongOrg})
	crossProvider := discoveryCredentialInput(scope, collection.ProviderMicrosoft, collection.CredentialMicrosoftClient, "ref:microsoft/refresh/customer-0001", collection.SubjectBinding{Kind: "microsoft_tenant", ID: testMicrosoftTenant}, strings.Replace(testMicrosoftConfig, testMicrosoftReference, "ref:microsoft/refresh/customer-0001", 1), now)
	tests = append(tests, struct {
		name  string
		input apiserver.ExecutionJobInput
	}{"microsoft reference of another class", crossProvider})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := healthySaaSTokenEndpoint()
			secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret), testSalesforceReference: []byte(testSalesforceSecret)}}
			resolver := saasCredentialResolver(t, endpoint, secrets, now, true, true)
			material, err := resolver.ResolveDiscoveryCredential(context.Background(), saasCredentialRequest(t, scope, test.input))
			if material != nil || saasFailureCode(err) != collection.FailureMalformed {
				t.Fatalf("material=%v err=%v", material != nil, err)
			}
			if len(secrets.calls) != 0 || len(endpoint.requests) != 0 {
				t.Fatalf("I/O before validation: secrets=%v requests=%d", secrets.calls, len(endpoint.requests))
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("secret leaked: %v", err)
			}
		})
	}
}

func TestSaaSCredentialsAreRefusedWhereTheProviderIsNotServed(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	endpoint := healthySaaSTokenEndpoint()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret), testSalesforceReference: []byte(testSalesforceSecret)}}
	resolver := saasCredentialResolver(t, endpoint, secrets, now, false, false)
	for _, input := range []apiserver.ExecutionJobInput{microsoftCredentialInput(scope, testMicrosoftConfig, now), salesforceCredentialInput(scope, testSalesforceConfig, now)} {
		material, err := resolver.ResolveDiscoveryCredential(context.Background(), saasCredentialRequest(t, scope, input))
		if material != nil || saasFailureCode(err) != collection.FailureMalformed {
			t.Fatalf("%s: material=%v err=%v", input.Provider, material != nil, err)
		}
	}
	if len(secrets.calls) != 0 || len(endpoint.requests) != 0 {
		t.Fatalf("an unserved provider read a secret or called out: %v %d", secrets.calls, len(endpoint.requests))
	}
}

func TestSaaSCredentialsRefuseAMissingOrMalformedSecret(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	for name, stored := range map[string][]byte{"missing": nil, "too short": []byte("short"), "has whitespace": []byte("client secret with spaces"), "has a newline": []byte("client-secret-value\n")} {
		endpoint := healthySaaSTokenEndpoint()
		values := map[string][]byte{}
		if stored != nil {
			values[testMicrosoftReference], values[testSalesforceReference] = stored, stored
		}
		resolver := saasCredentialResolver(t, endpoint, &discoverySecretReaderStub{values: values}, now, true, true)
		for _, input := range []apiserver.ExecutionJobInput{microsoftCredentialInput(scope, testMicrosoftConfig, now), salesforceCredentialInput(scope, testSalesforceConfig, now)} {
			material, err := resolver.ResolveDiscoveryCredential(context.Background(), saasCredentialRequest(t, scope, input))
			if material != nil || err == nil || len(endpoint.requests) != 0 {
				t.Fatalf("%s %s: material=%v err=%v requests=%d", name, input.Provider, material != nil, err, len(endpoint.requests))
			}
		}
	}
}

// The token APIs below keep the very slices the resolver hands them, so the
// test can see whether the resolver cleared them afterwards.
type microsoftExchangeRecorder struct {
	secrets [][]byte
	tokens  [][]byte
	expires time.Time
}

func (recorder *microsoftExchangeRecorder) ExchangeDiscoveryMicrosoftClientCredentials(_ context.Context, _, _ string, clientSecret []byte, scope string) (discoverySaaSAccessToken, error) {
	recorder.secrets = append(recorder.secrets, clientSecret)
	token := []byte(testMicrosoftGraphToken)
	if scope != discoveryMicrosoftGraphScope {
		token = []byte(testMicrosoftDataverseTok)
	}
	recorder.tokens = append(recorder.tokens, token)
	return discoverySaaSAccessToken{Token: token, ExpiresAt: recorder.expires}, nil
}

type salesforceExchangeRecorder struct {
	secret []byte
	token  []byte
}

func (recorder *salesforceExchangeRecorder) ExchangeDiscoverySalesforceClientCredentials(_ context.Context, instanceURL, _ string, clientSecret []byte) (discoverySaaSAccessToken, error) {
	recorder.secret = clientSecret
	recorder.token = []byte(testSalesforceToken)
	return discoverySaaSAccessToken{Token: recorder.token, InstanceURL: instanceURL, OrganizationID: testSalesforceOrg}, nil
}

func TestSaaSCredentialsClearTheSecretAndTheProviderTokensAfterResolution(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	secrets := &discoverySecretReaderStub{values: map[string][]byte{testMicrosoftReference: []byte(testMicrosoftSecret), testSalesforceReference: []byte(testSalesforceSecret)}}
	microsoft := &microsoftExchangeRecorder{expires: now.Add(time.Hour)}
	salesforce := &salesforceExchangeRecorder{}
	resolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: &discoveryAssumeRoleStub{}, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, Microsoft: microsoft, Salesforce: salesforce, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	zero := func(value []byte) bool { return len(value) > 0 && bytes.Equal(value, make([]byte, len(value))) }

	envelope := resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, microsoftCredentialInput(scope, testMicrosoftDataverseCfg, now)))
	if len(microsoft.secrets) != 2 || !zero(microsoft.secrets[0]) || !zero(microsoft.secrets[1]) || len(microsoft.tokens) != 2 || !zero(microsoft.tokens[0]) || !zero(microsoft.tokens[1]) {
		t.Fatalf("microsoft secret or tokens survived resolution: %q %q", microsoft.secrets, microsoft.tokens)
	}
	// The material keeps its own copy; destroying the envelope clears it.
	bearer := envelope.BearerToken
	if !bytes.Contains(bearer, []byte(testMicrosoftGraphToken)) {
		t.Fatalf("credential = %s", bearer)
	}
	envelope.Destroy()
	if !zero(bearer) {
		t.Fatal("destroyed envelope kept the collector credential")
	}

	envelope = resolvedSaaSEnvelope(t, resolver, saasCredentialRequest(t, scope, salesforceCredentialInput(scope, testSalesforceConfig, now)))
	if !zero(salesforce.secret) || !zero(salesforce.token) {
		t.Fatalf("salesforce secret or token survived resolution: %q %q", salesforce.secret, salesforce.token)
	}
	envelope.Destroy()
}

func TestSaaSCollectorCredentialsAreExactlyTheCollectorsShape(t *testing.T) {
	graphOnly, ok := encodeDiscoveryMicrosoftCollectorCredential([]byte(testMicrosoftGraphToken), nil, "")
	if !ok || string(graphOnly) != `{"graph_token":"graph-access-token-value-0001"}` || !validDiscoveryMicrosoftCollectorCredential(graphOnly) {
		t.Fatalf("graph-only credential = %s", graphOnly)
	}
	both, ok := encodeDiscoveryMicrosoftCollectorCredential([]byte(testMicrosoftGraphToken), []byte(testMicrosoftDataverseTok), testMicrosoftDataverse)
	if !ok || string(both) != `{"dataverse_token":"dataverse-access-token-value-0001","dataverse_url":"https://org1234.crm4.dynamics.com","graph_token":"graph-access-token-value-0001"}` || !validDiscoveryMicrosoftCollectorCredential(both) {
		t.Fatalf("dataverse credential = %s", both)
	}
	salesforce, ok := encodeDiscoverySalesforceCollectorCredential([]byte(testSalesforceToken), testSalesforceInstance)
	if !ok || string(salesforce) != `{"access_token":"`+testSalesforceToken+`","instance_url":"https://acme.my.salesforce.com"}` || !validDiscoverySalesforceCollectorCredential(salesforce) {
		t.Fatalf("salesforce credential = %s", salesforce)
	}
	for _, refused := range []struct{ graph, dataverse, url string }{
		{"short", "", ""},
		{`token-with-"quote-0001`, "", ""},
		{`token-with-\backslash-01`, "", ""},
		{"token with space 00001", "", ""},
		{testMicrosoftGraphToken, testMicrosoftDataverseTok, ""},
		{testMicrosoftGraphToken, "", testMicrosoftDataverse},
		{testMicrosoftGraphToken, testMicrosoftDataverseTok, "https://org1234.crm4.dynamics.com.evil.example"},
	} {
		if encoded, ok := encodeDiscoveryMicrosoftCollectorCredential([]byte(refused.graph), []byte(refused.dataverse), refused.url); ok {
			t.Fatalf("hostile microsoft credential encoded: %s", encoded)
		}
	}
	for _, hostile := range []string{
		`{"graph_token":"graph-access-token-value-0001","extra":"x"}`,
		`{"graph_token": "graph-access-token-value-0001"}`,
		`{"graph_token":"graph-access-token-value-0001","dataverse_token":"dataverse-access-token-value-0001","dataverse_url":"https://org1234.crm4.dynamics.com"}`,
		`{"dataverse_token":"dataverse-access-token-value-0001","graph_token":"graph-access-token-value-0001"}`,
		`{"access_token":"` + testSalesforceToken + `","instance_url":"https://acme.my.salesforce.com"}`,
	} {
		if validDiscoveryMicrosoftCollectorCredential([]byte(hostile)) {
			t.Fatalf("hostile microsoft credential accepted: %s", hostile)
		}
	}
	for _, hostile := range []string{
		`{"access_token":"` + testSalesforceToken + `","instance_url":"http://acme.my.salesforce.com"}`,
		`{"access_token":"` + testSalesforceToken + `","instance_url":"https://acme.my.salesforce.com","extra":"x"}`,
		`{"instance_url":"https://acme.my.salesforce.com","access_token":"` + testSalesforceToken + `"}`,
		`{"graph_token":"graph-access-token-value-0001"}`,
	} {
		if validDiscoverySalesforceCollectorCredential([]byte(hostile)) {
			t.Fatalf("hostile salesforce credential accepted: %s", hostile)
		}
	}
}

// The envelope of one provider is not an envelope of another.
func TestSaaSCredentialEnvelopesAreProviderExact(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	microsoft := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderMicrosoft, SubjectKind: "microsoft_tenant", SubjectID: testMicrosoftTenant, ExpiresAt: expires, BearerToken: []byte(`{"graph_token":"` + testMicrosoftGraphToken + `"}`)}
	salesforce := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderSalesforce, SubjectKind: "salesforce_org", SubjectID: testSalesforceOrg, ExpiresAt: expires, BearerToken: []byte(`{"access_token":"` + testSalesforceToken + `","instance_url":"` + testSalesforceInstance + `"}`)}
	if !validDiscoveryCredentialEnvelope(microsoft) || !validDiscoveryCredentialEnvelope(salesforce) {
		t.Fatal("valid SaaS envelope refused")
	}
	for name, mutate := range map[string]func(*discoveryCredentialEnvelope){
		"subject kind":   func(value *discoveryCredentialEnvelope) { value.SubjectKind = "okta_tenant" },
		"subject id":     func(value *discoveryCredentialEnvelope) { value.SubjectID = "acme.okta.com" },
		"plain bearer":   func(value *discoveryCredentialEnvelope) { value.BearerToken = []byte("a-plain-bearer-token-value") },
		"issuer":         func(value *discoveryCredentialEnvelope) { value.Issuer = "https://acme.okta.com" },
		"region":         func(value *discoveryCredentialEnvelope) { value.Region = "us-east-1" },
		"endpoint":       func(value *discoveryCredentialEnvelope) { value.Endpoint = "https://cluster.example.test" },
		"other provider": func(value *discoveryCredentialEnvelope) { value.Provider = collection.ProviderOkta },
	} {
		for _, valid := range []discoveryCredentialEnvelope{microsoft, salesforce} {
			hostile := valid
			hostile.BearerToken = bytes.Clone(valid.BearerToken)
			mutate(&hostile)
			if validDiscoveryCredentialEnvelope(hostile) {
				t.Fatalf("%s: hostile %s envelope accepted", name, valid.Provider)
			}
		}
	}
	swapped := microsoft
	swapped.BearerToken = salesforce.BearerToken
	if validDiscoveryCredentialEnvelope(swapped) {
		t.Fatal("microsoft envelope accepted a salesforce credential")
	}
}

type saasCollectionAPIRecorder struct {
	credential []byte
	request    githubdiscovery.CollectionPageRequest
	ready      error
}

func (recorder *saasCollectionAPIRecorder) FetchCollectionPage(_ context.Context, credential []byte, request githubdiscovery.CollectionPageRequest) (githubdiscovery.CollectionPage, error) {
	recorder.credential = bytes.Clone(credential)
	recorder.request = request
	return githubdiscovery.CollectionPage{Subject: request.Subject, Complete: true}, nil
}

func (recorder *saasCollectionAPIRecorder) CheckCollectionReadiness(context.Context) error {
	return recorder.ready
}

func TestSaaSCollectionAPIHandsTheCollectorItsOwnCredential(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	tests := []struct {
		provider   collection.Provider
		subject    collection.SubjectBinding
		credential string
	}{
		{collection.ProviderMicrosoft, collection.SubjectBinding{Kind: "microsoft_tenant", ID: testMicrosoftTenant}, `{"dataverse_token":"` + testMicrosoftDataverseTok + `","dataverse_url":"` + testMicrosoftDataverse + `","graph_token":"` + testMicrosoftGraphToken + `"}`},
		{collection.ProviderSalesforce, collection.SubjectBinding{Kind: "salesforce_org", ID: testSalesforceOrg}, `{"access_token":"` + testSalesforceToken + `","instance_url":"` + testSalesforceInstance + `"}`},
	}
	for _, test := range tests {
		recorder := &saasCollectionAPIRecorder{}
		api := newDiscoveryMicrosoftCollectionAPI(recorder)
		if test.provider == collection.ProviderSalesforce {
			api = newDiscoverySalesforceCollectionAPI(recorder)
		}
		if err := api.CheckCollectionReadiness(context.Background()); err != nil {
			t.Fatalf("%s readiness: %v", test.provider, err)
		}
		encoded, err := encodeDiscoveryCredentialEnvelope(discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: test.provider, SubjectKind: test.subject.Kind, SubjectID: test.subject.ID, ExpiresAt: expires, BearerToken: []byte(test.credential)})
		if err != nil {
			t.Fatal(err)
		}
		request := githubdiscovery.CollectionPageRequest{Provider: test.provider, Subject: test.subject, Page: 1}
		if _, err := api.FetchCollectionPage(context.Background(), encoded, request); err != nil {
			t.Fatalf("%s page: %v", test.provider, err)
		}
		if string(recorder.credential) != test.credential || recorder.request.Subject != test.subject {
			t.Fatalf("%s collector received %s for %#v", test.provider, recorder.credential, recorder.request.Subject)
		}
		// A credential bound to another subject or provider never reaches the collector.
		recorder.credential = nil
		other := request
		other.Subject.ID = strings.Replace(test.subject.ID, "0", "9", 1)
		if _, err := api.FetchCollectionPage(context.Background(), encoded, other); err == nil || recorder.credential != nil {
			t.Fatalf("%s: credential for another subject reached the collector", test.provider)
		}
		other = request
		other.Provider = collection.ProviderOkta
		if _, err := api.FetchCollectionPage(context.Background(), encoded, other); err == nil || recorder.credential != nil {
			t.Fatalf("%s: request of another provider reached the collector", test.provider)
		}
		recorder.ready = errors.New("provider unreachable SENTINEL")
		if err := api.CheckCollectionReadiness(context.Background()); err == nil || strings.Contains(err.Error(), "SENTINEL") {
			t.Fatalf("%s readiness error = %v", test.provider, err)
		}
	}
	if err := (&discoveryBearerCollectionAPI{provider: collection.ProviderMicrosoft}).CheckCollectionReadiness(context.Background()); err == nil {
		t.Fatal("microsoft API without a collector reported ready")
	}
}

func TestMicrosoftTokenClientRequestsOnlyGraphOrOneDataverseEnvironment(t *testing.T) {
	now := time.Now().UTC()
	endpoint := healthySaaSTokenEndpoint()
	client, err := newProductionDiscoveryMicrosoftTokenClient(&http.Client{Transport: endpoint, Timeout: time.Second}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ExchangeDiscoveryMicrosoftClientCredentials(context.Background(), testMicrosoftTenant, testMicrosoftClient, []byte(testMicrosoftSecret), discoveryMicrosoftGraphScope)
	if err != nil || string(result.Token) != testMicrosoftGraphToken || !result.ExpiresAt.Equal(now.Add(3599*time.Second)) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	result.Destroy()
	if result.Token != nil {
		t.Fatal("destroyed token kept its bytes")
	}
	for _, hostile := range []struct{ tenant, client, secret, scope string }{
		{"common", testMicrosoftClient, testMicrosoftSecret, discoveryMicrosoftGraphScope},
		{testMicrosoftTenant + "/../other", testMicrosoftClient, testMicrosoftSecret, discoveryMicrosoftGraphScope},
		{testMicrosoftTenant, "client", testMicrosoftSecret, discoveryMicrosoftGraphScope},
		{testMicrosoftTenant, testMicrosoftClient, "short", discoveryMicrosoftGraphScope},
		{testMicrosoftTenant, testMicrosoftClient, testMicrosoftSecret, "https://management.azure.com/.default"},
		{testMicrosoftTenant, testMicrosoftClient, testMicrosoftSecret, "https://graph.microsoft.com/.default offline_access"},
		{testMicrosoftTenant, testMicrosoftClient, testMicrosoftSecret, "https://org1234.crm4.dynamics.com.evil.example/.default"},
		{testMicrosoftTenant, testMicrosoftClient, testMicrosoftSecret, "https://org1234.crm4.dynamics.com/user_impersonation"},
	} {
		before := len(endpoint.requests)
		if _, err := client.ExchangeDiscoveryMicrosoftClientCredentials(context.Background(), hostile.tenant, hostile.client, []byte(hostile.secret), hostile.scope); err == nil || len(endpoint.requests) != before {
			t.Fatalf("hostile exchange %#v sent a request or succeeded: %v", hostile, err)
		}
	}
	if _, err := newProductionDiscoveryMicrosoftTokenClient(nil, func() time.Time { return now }); err == nil {
		t.Fatal("token client without an HTTP client accepted")
	}
	if _, err := newProductionDiscoverySalesforceTokenClient(&http.Client{}); err == nil {
		t.Fatal("token client without a transport accepted")
	}
}

func TestSalesforceIdentityURLNamesItsOrganization(t *testing.T) {
	for identity, want := range map[string]string{
		"": "",
		"https://login.salesforce.com/id/00D5e000000abcdEAA/0055e000000userAAA": "00D5e000000abcdEAA",
		"https://acme.my.salesforce.com/id/00D5e000000abcd/0055e000000user":     "00D5e000000abcd",
		"https://test.salesforce.com/id/00D5e000000abcdEAA/0055e000000userAAA":  "00D5e000000abcdEAA",
	} {
		if got, ok := discoverySalesforceIdentityOrganization(identity); !ok || got != want {
			t.Fatalf("identity %q = %q, %t", identity, got, ok)
		}
	}
	for _, hostile := range []string{
		"http://login.salesforce.com/id/00D5e000000abcdEAA/0055e000000userAAA",
		"https://login.salesforce.com.evil.example/id/00D5e000000abcdEAA/0055e000000userAAA",
		"https://login.salesforce.com/id/00D5e000000abcdEAA",
		"https://login.salesforce.com/id/0055e000000userAAA/00D5e000000abcdEAA",
		"https://login.salesforce.com/services/00D5e000000abcdEAA/0055e000000userAAA",
		"https://login.salesforce.com/id/00D5e000000abcdEAA/0055e000000userAAA/extra",
	} {
		if _, ok := discoverySalesforceIdentityOrganization(hostile); ok {
			t.Fatalf("hostile identity accepted: %s", hostile)
		}
	}
}

var _ http.RoundTripper = (*discoverySaaSTokenEndpoint)(nil)
var _ discoveryMicrosoftTokenAPI = (*microsoftExchangeRecorder)(nil)
var _ discoverySalesforceTokenAPI = (*salesforceExchangeRecorder)(nil)
var _ githubdiscovery.CollectionAPI = (*saasCollectionAPIRecorder)(nil)

// The credential the resolver writes is the one the real collectors read:
// each sends the token of its own host and nothing else.
func TestSaaSCollectorsAcceptTheResolvedCredential(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour)
	type sent struct{ host, authorization string }
	var requests []sent
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, sent{request.URL.Host, request.Header.Get("Authorization")})
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
	})
	microsoft, err := microsoftdiscovery.NewMicrosoftCollectionAPI(microsoftdiscovery.CollectionAPIConfig{Transport: transport, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	salesforce, err := salesforcediscovery.NewSalesforceCollectionAPI(salesforcediscovery.CollectionAPIConfig{Transport: transport, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		api        githubdiscovery.CollectionAPI
		provider   collection.Provider
		subject    collection.SubjectBinding
		credential string
		wantHost   string
		wantToken  string
	}{
		{newDiscoveryMicrosoftCollectionAPI(microsoft), collection.ProviderMicrosoft, collection.SubjectBinding{Kind: "microsoft_tenant", ID: testMicrosoftTenant}, `{"dataverse_token":"` + testMicrosoftDataverseTok + `","dataverse_url":"` + testMicrosoftDataverse + `","graph_token":"` + testMicrosoftGraphToken + `"}`, "graph.microsoft.com", testMicrosoftGraphToken},
		{newDiscoverySalesforceCollectionAPI(salesforce), collection.ProviderSalesforce, collection.SubjectBinding{Kind: "salesforce_org", ID: testSalesforceOrg}, `{"access_token":"` + testSalesforceToken + `","instance_url":"` + testSalesforceInstance + `"}`, "acme.my.salesforce.com", testSalesforceToken},
	} {
		requests = nil
		encoded, err := encodeDiscoveryCredentialEnvelope(discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: test.provider, SubjectKind: test.subject.Kind, SubjectID: test.subject.ID, ExpiresAt: expires, BearerToken: []byte(test.credential)})
		if err != nil {
			t.Fatal(err)
		}
		// The fake provider is unavailable, so the page fails; what matters is
		// that the collector accepted the credential and used it.
		_, _ = test.api.FetchCollectionPage(context.Background(), encoded, githubdiscovery.CollectionPageRequest{Provider: test.provider, Subject: test.subject, Page: 1, RemainingItems: 1000, RemainingRelationships: 2000, RemainingFindings: 1000, RemainingBytes: 64 << 20})
		if len(requests) != 1 || requests[0].host != test.wantHost || requests[0].authorization != "Bearer "+test.wantToken {
			t.Fatalf("%s collector sent %#v, want one request to %s with its own token", test.provider, requests, test.wantHost)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
