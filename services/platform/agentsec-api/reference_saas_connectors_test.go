package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

const (
	probeMicrosoftTenant    = "0a1b2c3d-1111-2222-3333-444455556666"
	probeMicrosoftSecret    = "SENTINEL-microsoft-client-secret-value"
	probeSalesforceOrg      = "00D5e000000abcdEAA"
	probeSalesforceSecret   = "SENTINEL-salesforce-consumer-secret-value"
	probeMicrosoftConfig    = `{"client_id":"11111111-2222-3333-4444-555555555555","client_secret_reference":"ref:microsoft/client-secret/customer-0001","tenant_id":"` + probeMicrosoftTenant + `"}`
	probeMicrosoftDataverse = `{"client_id":"11111111-2222-3333-4444-555555555555","client_secret_reference":"ref:microsoft/client-secret/customer-0001","dataverse_url":"https://org1234.crm4.dynamics.com","tenant_id":"` + probeMicrosoftTenant + `"}`
	probeSalesforceConfig   = `{"client_id":"3MVG9abcdefghijklmnopqrstuvwxyz.ABCDEF_0123456789","client_secret_reference":"ref:salesforce/client-secret/customer-0001","instance_url":"https://acme.my.salesforce.com","organization_id":"` + probeSalesforceOrg + `"}`
)

type saasProbeRequest struct {
	url  string
	form url.Values
}

type saasProbeEndpoint struct {
	requests []saasProbeRequest
	respond  func(host string, form url.Values) (int, string, string)
}

func (endpoint *saasProbeEndpoint) RoundTrip(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	form, _ := url.ParseQuery(string(body))
	endpoint.requests = append(endpoint.requests, saasProbeRequest{url: request.URL.String(), form: form})
	status, contentType, payload := endpoint.respond(request.URL.Host, form)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(payload)), Request: request}, nil
}

func saasProbeResolver() *referenceSecretResolver {
	return &referenceSecretResolver{driver: &connectorSecretsDriver{client: &connectorSecretsAPIStub{values: map[string][]byte{
		"zasp/microsoft/client-secret/customer-0001":  []byte(probeMicrosoftSecret),
		"zasp/salesforce/client-secret/customer-0001": []byte(probeSalesforceSecret),
	}}}, root: "zasp"}
}

func healthySaaSProbeEndpoint() *saasProbeEndpoint {
	return &saasProbeEndpoint{respond: func(host string, _ url.Values) (int, string, string) {
		if host == "login.microsoftonline.com" {
			return http.StatusOK, "application/json; charset=utf-8", `{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"microsoft-access-token-value"}`
		}
		return http.StatusOK, "application/json;charset=UTF-8", `{"access_token":"00D5e000000abcd!salesforce.access.token","signature":"c2ln","scope":"api","instance_url":"https://acme.my.salesforce.com","id":"https://login.salesforce.com/id/` + probeSalesforceOrg + `/0055e000000userAAA","token_type":"Bearer","issued_at":"1700000000000"}`
	}}
}

func TestSaaSReferenceSecretsResolveOnlyFromTheirOwnNamespace(t *testing.T) {
	resolver := saasProbeResolver()
	for reference, want := range map[string]string{"ref:microsoft/client-secret/customer-0001": probeMicrosoftSecret, "ref:salesforce/client-secret/customer-0001": probeSalesforceSecret} {
		value, err := resolver.Resolve(context.Background(), reference)
		if err != nil || string(value) != want {
			t.Fatalf("resolve %q = %v", reference, err)
		}
	}
	for _, reference := range []string{"ref:microsoft/client-secret/customer-0001/child", "ref:microsoft/client-secret/../salesforce", "ref:microsoft/refresh/customer-0001", "ref:salesforce/client-secret/short", "ref:microsoft/client-secret/customer-0002"} {
		if _, err := resolver.Resolve(context.Background(), reference); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("hostile reference %q = %v", reference, err)
		}
	}
}

func TestMicrosoftReferenceProbeExchangesTheReferencedSecretAtTheTenantEndpoint(t *testing.T) {
	endpoint := healthySaaSProbeEndpoint()
	probe := &microsoftReferenceProbe{resolver: saasProbeResolver(), http: &http.Client{Transport: endpoint}}
	target := apiserver.ReferenceAuthorizationTarget{Provider: "microsoft", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(probeMicrosoftConfig)}
	subject, err := probe.ProbeReferenceAuthorization(context.Background(), target)
	if err != nil || subject != (apiserver.ReferenceAuthorizationSubject{Kind: "microsoft_tenant", ID: probeMicrosoftTenant}) {
		t.Fatalf("subject=%#v err=%v", subject, err)
	}
	if len(endpoint.requests) != 1 || endpoint.requests[0].url != "https://login.microsoftonline.com/"+probeMicrosoftTenant+"/oauth2/v2.0/token" {
		t.Fatalf("requests = %#v", endpoint.requests)
	}
	form := endpoint.requests[0].form
	if len(form) != 4 || form.Get("grant_type") != "client_credentials" || form.Get("client_secret") != probeMicrosoftSecret || form.Get("scope") != "https://graph.microsoft.com/.default" || form.Get("client_id") != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("form = %v", form)
	}
	// A configured Dataverse environment is proven with its own token.
	endpoint.requests = nil
	target.Configuration = json.RawMessage(probeMicrosoftDataverse)
	if _, err := probe.ProbeReferenceAuthorization(context.Background(), target); err != nil || len(endpoint.requests) != 2 || endpoint.requests[1].form.Get("scope") != "https://org1234.crm4.dynamics.com/.default" {
		t.Fatalf("dataverse probe err=%v requests=%#v", err, endpoint.requests)
	}
	endpoint.respond = func(_ string, form url.Values) (int, string, string) {
		if form.Get("scope") == "https://graph.microsoft.com/.default" {
			return http.StatusOK, "application/json", `{"token_type":"Bearer","expires_in":3599,"access_token":"microsoft-access-token-value"}`
		}
		return http.StatusBadRequest, "application/json", `{"error":"invalid_resource"}`
	}
	if _, err := probe.ProbeReferenceAuthorization(context.Background(), target); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("refused Dataverse token error = %v", err)
	}
}

func TestSalesforceReferenceProbeRequiresTheConfiguredInstanceAndOrg(t *testing.T) {
	endpoint := healthySaaSProbeEndpoint()
	probe := &salesforceReferenceProbe{resolver: saasProbeResolver(), http: &http.Client{Transport: endpoint}}
	target := apiserver.ReferenceAuthorizationTarget{Provider: "salesforce", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(probeSalesforceConfig)}
	subject, err := probe.ProbeReferenceAuthorization(context.Background(), target)
	if err != nil || subject != (apiserver.ReferenceAuthorizationSubject{Kind: "salesforce_org", ID: probeSalesforceOrg}) {
		t.Fatalf("subject=%#v err=%v", subject, err)
	}
	if len(endpoint.requests) != 1 || endpoint.requests[0].url != "https://acme.my.salesforce.com/services/oauth2/token" || len(endpoint.requests[0].form) != 3 || endpoint.requests[0].form.Get("client_secret") != probeSalesforceSecret || endpoint.requests[0].form.Get("grant_type") != "client_credentials" {
		t.Fatalf("requests = %#v", endpoint.requests)
	}
	body := func(instance, identity string) string {
		return `{"access_token":"00D5e000000abcd!salesforce.access.token","instance_url":"` + instance + `","id":"` + identity + `","token_type":"Bearer"}`
	}
	for name, response := range map[string]string{
		"another instance":   body("https://other.my.salesforce.com", "https://login.salesforce.com/id/"+probeSalesforceOrg+"/0055e000000userAAA"),
		"another org":        body("https://acme.my.salesforce.com", "https://login.salesforce.com/id/00D5e000000zzzzEAA/0055e000000userAAA"),
		"a foreign identity": body("https://acme.my.salesforce.com", "https://evil.example/id/"+probeSalesforceOrg+"/0055e000000userAAA"),
		"no instance":        `{"access_token":"00D5e000000abcd!salesforce.access.token","token_type":"Bearer"}`,
	} {
		endpoint.respond = func(string, url.Values) (int, string, string) { return http.StatusOK, "application/json", response }
		if _, err := probe.ProbeReferenceAuthorization(context.Background(), target); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	// The 15-character form of the same org is the same org.
	endpoint.respond = func(string, url.Values) (int, string, string) {
		return http.StatusOK, "application/json", body("https://acme.my.salesforce.com", "https://login.salesforce.com/id/"+probeSalesforceOrg[:15]+"/0055e000000user")
	}
	if _, err := probe.ProbeReferenceAuthorization(context.Background(), target); err != nil {
		t.Fatalf("15-character org id refused: %v", err)
	}
}

func TestSaaSReferenceProbesRefuseHostileInputsAndResponsesWithoutLeaking(t *testing.T) {
	const providerSentinel = "PROVIDER-ERROR-BODY-SENTINEL"
	microsoftTarget := apiserver.ReferenceAuthorizationTarget{Provider: "microsoft", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(probeMicrosoftConfig)}
	salesforceTarget := apiserver.ReferenceAuthorizationTarget{Provider: "salesforce", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(probeSalesforceConfig)}
	run := func(endpoint *saasProbeEndpoint, target apiserver.ReferenceAuthorizationTarget) error {
		client := &http.Client{Transport: endpoint}
		if target.Provider == "microsoft" {
			_, err := (&microsoftReferenceProbe{resolver: saasProbeResolver(), http: client}).ProbeReferenceAuthorization(context.Background(), target)
			return err
		}
		_, err := (&salesforceReferenceProbe{resolver: saasProbeResolver(), http: client}).ProbeReferenceAuthorization(context.Background(), target)
		return err
	}
	for name, response := range map[string][3]string{
		"unauthorized":     {"401", "application/json", `{"error":"invalid_client","error_description":"` + providerSentinel + `"}`},
		"wrong token type": {"200", "application/json", `{"token_type":"MAC","expires_in":3599,"access_token":"` + providerSentinel + `-token","instance_url":"https://acme.my.salesforce.com"}`},
		"oversize body":    {"200", "application/json", `{"token_type":"Bearer","access_token":"microsoft-access-token-value","instance_url":"https://acme.my.salesforce.com"}` + strings.Repeat(" ", 64<<10)},
		"wrong media type": {"200", "text/html", `{"token_type":"Bearer","access_token":"microsoft-access-token-value","instance_url":"https://acme.my.salesforce.com"}`},
		"short token":      {"200", "application/json", `{"token_type":"Bearer","access_token":"short","instance_url":"https://acme.my.salesforce.com"}`},
		"refresh token":    {"200", "application/json", `{"token_type":"Bearer","access_token":"microsoft-access-token-value","refresh_token":"` + providerSentinel + `","instance_url":"https://acme.my.salesforce.com"}`},
		"trailing data":    {"200", "application/json", `{"token_type":"Bearer","access_token":"microsoft-access-token-value","instance_url":"https://acme.my.salesforce.com"}{}`},
	} {
		for _, target := range []apiserver.ReferenceAuthorizationTarget{microsoftTarget, salesforceTarget} {
			status := http.StatusOK
			if response[0] == "401" {
				status = http.StatusUnauthorized
			}
			endpoint := &saasProbeEndpoint{respond: func(string, url.Values) (int, string, string) { return status, response[1], response[2] }}
			err := run(endpoint, target)
			if !errors.Is(err, errRuntimeUnavailable) || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("%s %s: error = %v", target.Provider, name, err)
			}
		}
	}
	// Nothing is read or sent for a configuration the probe does not accept.
	for name, target := range map[string]apiserver.ReferenceAuthorizationTarget{
		"microsoft reference is not the connection's": {Provider: "microsoft", ConnectionReference: "ref:microsoft/client-secret/customer-0002", Configuration: json.RawMessage(probeMicrosoftConfig)},
		"microsoft tenant is not a GUID":              {Provider: "microsoft", ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(strings.Replace(probeMicrosoftConfig, probeMicrosoftTenant, "common", 1))},
		"microsoft dataverse on another host":         {Provider: "microsoft", ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(strings.Replace(probeMicrosoftDataverse, "dynamics.com", "dynamics.com.evil.example", 1))},
		"microsoft unknown member":                    {Provider: "microsoft", ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(strings.Replace(probeMicrosoftConfig, `"tenant_id"`, `"client_secret":"x","tenant_id"`, 1))},
		"salesforce instance over HTTP":               {Provider: "salesforce", ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(strings.Replace(probeSalesforceConfig, "https://acme", "http://acme", 1))},
		"salesforce instance on another host":         {Provider: "salesforce", ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(strings.Replace(probeSalesforceConfig, "my.salesforce.com", "my.salesforce.com.evil.example", 1))},
		"salesforce 15-character organization":        {Provider: "salesforce", ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(strings.Replace(probeSalesforceConfig, probeSalesforceOrg, probeSalesforceOrg[:15], 1))},
	} {
		endpoint := healthySaaSProbeEndpoint()
		if err := run(endpoint, target); !errors.Is(err, errRuntimeUnavailable) || len(endpoint.requests) != 0 {
			t.Fatalf("%s: error=%v requests=%d", name, err, len(endpoint.requests))
		}
	}
	// A reference without a stored secret, or with a malformed one, is refused before any request.
	for _, stored := range [][]byte{nil, []byte("short"), []byte("client secret with spaces")} {
		values := map[string][]byte{}
		if stored != nil {
			values["zasp/microsoft/client-secret/customer-0001"] = stored
		}
		endpoint := healthySaaSProbeEndpoint()
		probe := &microsoftReferenceProbe{resolver: &referenceSecretResolver{driver: &connectorSecretsDriver{client: &connectorSecretsAPIStub{values: values}}, root: "zasp"}, http: &http.Client{Transport: endpoint}}
		if _, err := probe.ProbeReferenceAuthorization(context.Background(), microsoftTarget); !errors.Is(err, errRuntimeUnavailable) || len(endpoint.requests) != 0 {
			t.Fatalf("stored secret %q: error=%v requests=%d", stored, err, len(endpoint.requests))
		}
	}
}

// The API offers Microsoft and Salesforce only where the deployment sets the
// collector version the discovery worker reads.
func TestRuntimeConfigReadsTheOptionalSaaSCollectorVersions(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	unset, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || unset.MicrosoftCollectorVersion != "" || unset.SalesforceCollectorVersion != "" {
		t.Fatalf("config without the optional versions: %q %q %v", unset.MicrosoftCollectorVersion, unset.SalesforceCollectorVersion, err)
	}
	values["ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION"], values["ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION"] = "collector_v1", "salesforce-collector-v1"
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil || config.MicrosoftCollectorVersion != "collector_v1" || config.SalesforceCollectorVersion != "salesforce-collector-v1" {
		t.Fatalf("optional versions = %q %q %v", config.MicrosoftCollectorVersion, config.SalesforceCollectorVersion, err)
	}
	for _, name := range []string{"ZASP_DISCOVERY_MICROSOFT_COLLECTOR_VERSION", "ZASP_DISCOVERY_SALESFORCE_COLLECTOR_VERSION"} {
		for _, invalid := range []string{"Collector_V1", "v", "collector v1", "1collector"} {
			hostile := fixtureRuntimeEnvironment()
			hostile[name] = invalid
			if _, err := loadRuntimeConfig(func(key string) string { return hostile[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
				t.Fatalf("%s=%q error = %v", name, invalid, err)
			}
		}
	}
}

var _ http.RoundTripper = (*saasProbeEndpoint)(nil)
