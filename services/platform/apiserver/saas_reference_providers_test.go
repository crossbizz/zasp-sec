package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	saasMicrosoftConfiguration          = `{"client_id":"11111111-2222-3333-4444-555555555555","client_secret_reference":"ref:microsoft/client-secret/customer-0001","tenant_id":"0a1b2c3d-1111-2222-3333-444455556666"}`
	saasMicrosoftDataverseConfiguration = `{"client_id":"11111111-2222-3333-4444-555555555555","client_secret_reference":"ref:microsoft/client-secret/customer-0001","dataverse_url":"https://org1234.crm4.dynamics.com","tenant_id":"0a1b2c3d-1111-2222-3333-444455556666"}`
	saasSalesforceConfiguration         = `{"client_id":"3MVG9abcdefghijklmnopqrstuvwxyz.ABCDEF_0123456789","client_secret_reference":"ref:salesforce/client-secret/customer-0001","instance_url":"https://acme.my.salesforce.com","organization_id":"00D5e000000abcdEAA"}`
	saasMicrosoftTenant                 = "0a1b2c3d-1111-2222-3333-444455556666"
	saasSalesforceOrganization          = "00D5e000000abcdEAA"
)

func TestReferenceConfigurationOfMicrosoftAndSalesforceIsExact(t *testing.T) {
	for provider, tests := range map[string]map[string]string{
		"microsoft":  {saasMicrosoftConfiguration: "ref:microsoft/client-secret/customer-0001", saasMicrosoftDataverseConfiguration: "ref:microsoft/client-secret/customer-0001"},
		"salesforce": {saasSalesforceConfiguration: "ref:salesforce/client-secret/customer-0001"},
	} {
		for configuration, wantReference := range tests {
			canonical, reference, valid := parseReferenceAuthorizationConfiguration(provider, json.RawMessage(configuration))
			// The canonical form is the sorted-member form the worker reads.
			if !valid || reference != wantReference || string(canonical) != configuration {
				t.Fatalf("%s configuration %s = %s, %q, %t", provider, configuration, canonical, reference, valid)
			}
		}
	}
	// Members in any order are accepted and written back sorted.
	reordered := `{"tenant_id":"0a1b2c3d-1111-2222-3333-444455556666","client_secret_reference":"ref:microsoft/client-secret/customer-0001","client_id":"11111111-2222-3333-4444-555555555555"}`
	if canonical, _, valid := parseReferenceAuthorizationConfiguration("microsoft", json.RawMessage(reordered)); !valid || string(canonical) != saasMicrosoftConfiguration {
		t.Fatalf("reordered microsoft configuration = %s, %t", canonical, valid)
	}

	replace := func(configuration, old, new string) string { return strings.Replace(configuration, old, new, 1) }
	for name, test := range map[string][2]string{
		"microsoft tenant is not a GUID":              {"microsoft", replace(saasMicrosoftConfiguration, saasMicrosoftTenant, "contoso.onmicrosoft.com")},
		"microsoft tenant in upper case":              {"microsoft", replace(saasMicrosoftConfiguration, saasMicrosoftTenant, strings.ToUpper(saasMicrosoftTenant))},
		"microsoft client is not a GUID":              {"microsoft", replace(saasMicrosoftConfiguration, "11111111-2222-3333-4444-555555555555", "client")},
		"microsoft secret instead of a reference":     {"microsoft", replace(saasMicrosoftConfiguration, "ref:microsoft/client-secret/customer-0001", "Abc~1234567890.secret-value_abcdefgh")},
		"microsoft reference of another provider":     {"microsoft", replace(saasMicrosoftConfiguration, "ref:microsoft/", "ref:salesforce/")},
		"microsoft reference of another class":        {"microsoft", replace(saasMicrosoftConfiguration, "/client-secret/", "/refresh/")},
		"microsoft reference in upper case":           {"microsoft", replace(saasMicrosoftConfiguration, "customer-0001", "Customer-0001")},
		"microsoft missing reference":                 {"microsoft", `{"client_id":"11111111-2222-3333-4444-555555555555","tenant_id":"0a1b2c3d-1111-2222-3333-444455556666"}`},
		"microsoft dataverse over HTTP":               {"microsoft", replace(saasMicrosoftDataverseConfiguration, "https://org1234", "http://org1234")},
		"microsoft dataverse on another host":         {"microsoft", replace(saasMicrosoftDataverseConfiguration, "dynamics.com", "dynamics.com.evil.example")},
		"microsoft dataverse with a path":             {"microsoft", replace(saasMicrosoftDataverseConfiguration, "dynamics.com", "dynamics.com/api/data")},
		"microsoft empty dataverse":                   {"microsoft", replace(saasMicrosoftDataverseConfiguration, "https://org1234.crm4.dynamics.com", "")},
		"microsoft unknown member":                    {"microsoft", replace(saasMicrosoftConfiguration, `"tenant_id"`, `"client_secret":"value","tenant_id"`)},
		"microsoft configuration for salesforce":      {"salesforce", saasMicrosoftConfiguration},
		"salesforce instance over HTTP":               {"salesforce", replace(saasSalesforceConfiguration, "https://acme", "http://acme")},
		"salesforce instance on another host":         {"salesforce", replace(saasSalesforceConfiguration, "my.salesforce.com", "my.salesforce.com.evil.example")},
		"salesforce login host":                       {"salesforce", replace(saasSalesforceConfiguration, "https://acme.my.salesforce.com", "https://login.salesforce.com")},
		"salesforce 15-character organization":        {"salesforce", replace(saasSalesforceConfiguration, saasSalesforceOrganization, "00D5e000000abcd")},
		"salesforce organization with another prefix": {"salesforce", replace(saasSalesforceConfiguration, saasSalesforceOrganization, "0055e000000abcdEAA")},
		"salesforce short consumer key":               {"salesforce", replace(saasSalesforceConfiguration, "3MVG9abcdefghijklmnopqrstuvwxyz.ABCDEF_0123456789", "short")},
		"salesforce reference of another provider":    {"salesforce", replace(saasSalesforceConfiguration, "ref:salesforce/", "ref:microsoft/")},
		"salesforce missing reference":                {"salesforce", `{"client_id":"3MVG9abcdefghijklmnopqrstuvwxyz.ABCDEF_0123456789","instance_url":"https://acme.my.salesforce.com","organization_id":"00D5e000000abcdEAA"}`},
		"salesforce configuration for microsoft":      {"microsoft", saasSalesforceConfiguration},
		"an unknown provider":                         {"servicenow", saasSalesforceConfiguration},
	} {
		if canonical, reference, valid := parseReferenceAuthorizationConfiguration(test[0], json.RawMessage(test[1])); valid || canonical != nil || reference != "" {
			t.Fatalf("%s: accepted as %s", name, canonical)
		}
	}
}

func TestReferenceOnlyConfigurationAdmitsAClientSecretOnlyByReference(t *testing.T) {
	for _, configuration := range []string{saasMicrosoftConfiguration, saasMicrosoftDataverseConfiguration, saasSalesforceConfiguration} {
		if !validReferenceOnlyJSON(json.RawMessage(configuration)) {
			t.Fatalf("reference configuration refused: %s", configuration)
		}
	}
	for _, hostile := range []string{
		`{"client_secret_reference":"Abc~1234567890.secret-value_abcdefgh"}`,
		`{"client_secret_reference":"ref:okta/client-secret/customer-0001"}`,
		`{"client_secret_reference":{"value":"nested"}}`,
		`{"client_secret_reference":["ref:microsoft/client-secret/customer-0001"]}`,
		`{"client_secret":"ref:microsoft/client-secret/customer-0001"}`,
		`{"client_secret_reference_value":"ref:microsoft/client-secret/customer-0001"}`,
		`{"nested":{"access_token":"value"},"client_secret_reference":"ref:microsoft/client-secret/customer-0001"}`,
	} {
		if validReferenceOnlyJSON(json.RawMessage(hostile)) {
			t.Fatalf("secret-bearing configuration accepted: %s", hostile)
		}
	}
}

type saasReferenceProbe struct {
	subject ReferenceAuthorizationSubject
	target  ReferenceAuthorizationTarget
	calls   int
	err     error
}

func (probe *saasReferenceProbe) ProbeReferenceAuthorization(_ context.Context, target ReferenceAuthorizationTarget) (ReferenceAuthorizationSubject, error) {
	probe.calls++
	probe.target = target
	return probe.subject, probe.err
}

func TestReferenceConnectorRegistryServesMicrosoftAndSalesforceOnlyWhereRegistered(t *testing.T) {
	ready := func(context.Context) error { return nil }
	aws := &saasReferenceProbe{subject: ReferenceAuthorizationSubject{Kind: "aws_account", ID: "123456789012"}}
	microsoft := &saasReferenceProbe{subject: ReferenceAuthorizationSubject{Kind: "microsoft_tenant", ID: saasMicrosoftTenant}}
	salesforce := &saasReferenceProbe{subject: ReferenceAuthorizationSubject{Kind: "salesforce_org", ID: saasSalesforceOrganization}}
	integrationID := "pid_74000001-0000-4000-8000-000000000001"

	// The default deployment: AWS only. The SaaS providers are not available
	// and a probe for one is refused without calling anything.
	defaultRegistry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": aws}, map[string]ConnectorCapabilityCheck{"aws": ready})
	if err != nil {
		t.Fatal(err)
	}
	capabilities := CombinedConnectorCapabilities{OAuth: fixedConnectorCapabilities{"github": {}, "okta": {}}, Reference: defaultRegistry}
	for _, key := range []string{"microsoft", "salesforce"} {
		if defaultRegistry.ConnectorAvailable(context.Background(), key) || capabilities.ConnectorAvailable(context.Background(), key) {
			t.Fatalf("%s is available without a registered probe", key)
		}
	}
	if _, err := defaultRegistry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "microsoft", IntegrationID: integrationID, ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(saasMicrosoftConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unregistered microsoft probe error = %v", err)
	}
	manifests := locallyCompleteWorkflowManifests(context.Background(), capabilities, false)
	for _, manifest := range manifests {
		if manifest.Key == "microsoft" || manifest.Key == "salesforce" {
			t.Fatalf("%s is in the catalog of a deployment that does not serve it", manifest.Key)
		}
	}

	registry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": aws, "microsoft": microsoft, "salesforce": salesforce}, map[string]ConnectorCapabilityCheck{"aws": ready, "microsoft": ready, "salesforce": ready})
	if err != nil {
		t.Fatal(err)
	}
	capabilities.Reference = registry
	served := map[string]bool{}
	for _, manifest := range locallyCompleteWorkflowManifests(context.Background(), capabilities, false) {
		served[manifest.Key] = true
	}
	if !served["microsoft"] || !served["salesforce"] || !served["aws"] || served["kubernetes"] {
		t.Fatalf("catalog = %v", served)
	}
	subject, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "microsoft", IntegrationID: integrationID, ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(saasMicrosoftDataverseConfiguration)})
	if err != nil || subject != (ReferenceAuthorizationSubject{Kind: "microsoft_tenant", ID: saasMicrosoftTenant}) || string(microsoft.target.Configuration) != saasMicrosoftDataverseConfiguration {
		t.Fatalf("microsoft probe = %#v, %v, configuration %s", subject, err, microsoft.target.Configuration)
	}
	subject, err = registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "salesforce", IntegrationID: integrationID, ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(saasSalesforceConfiguration)})
	if err != nil || subject != (ReferenceAuthorizationSubject{Kind: "salesforce_org", ID: saasSalesforceOrganization}) {
		t.Fatalf("salesforce probe = %#v, %v", subject, err)
	}
	// The connection reference must be the one the configuration names.
	calls := microsoft.calls
	if _, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "microsoft", IntegrationID: integrationID, ConnectionReference: "ref:microsoft/client-secret/customer-0002", Configuration: json.RawMessage(saasMicrosoftConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) || microsoft.calls != calls {
		t.Fatalf("mismatched reference: err=%v calls=%d", err, microsoft.calls-calls)
	}
	// A probe may only report its own provider's subject shape.
	for _, hostile := range []ReferenceAuthorizationSubject{{Kind: "salesforce_org", ID: saasSalesforceOrganization}, {Kind: "microsoft_tenant", ID: "contoso.onmicrosoft.com"}, {Kind: "aws_account", ID: "123456789012"}, {}} {
		microsoft.subject = hostile
		if _, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "microsoft", IntegrationID: integrationID, ConnectionReference: "ref:microsoft/client-secret/customer-0001", Configuration: json.RawMessage(saasMicrosoftConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("microsoft probe subject %#v accepted: %v", hostile, err)
		}
	}
	for _, hostile := range []ReferenceAuthorizationSubject{{Kind: "salesforce_org", ID: "00D5e000000abcd"}, {Kind: "microsoft_tenant", ID: saasMicrosoftTenant}} {
		salesforce.subject = hostile
		if _, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "salesforce", IntegrationID: integrationID, ConnectionReference: "ref:salesforce/client-secret/customer-0001", Configuration: json.RawMessage(saasSalesforceConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("salesforce probe subject %#v accepted: %v", hostile, err)
		}
	}
	// Only the four reference-authorized providers may be registered.
	if _, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"okta": aws}, map[string]ConnectorCapabilityCheck{"okta": ready}); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("okta reference probe error = %v", err)
	}
	if _, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"microsoft": microsoft}, map[string]ConnectorCapabilityCheck{}); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("probe without a check error = %v", err)
	}
}

func TestReferenceAuthorizationHandlerCompletesMicrosoftAndSalesforceWithTheirSubject(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	ready := func(context.Context) error { return nil }
	for provider, test := range map[string]struct {
		configuration, reference string
		subject                  ReferenceAuthorizationSubject
	}{
		"microsoft":  {saasMicrosoftConfiguration, "ref:microsoft/client-secret/customer-0001", ReferenceAuthorizationSubject{Kind: "microsoft_tenant", ID: saasMicrosoftTenant}},
		"salesforce": {saasSalesforceConfiguration, "ref:salesforce/client-secret/customer-0001", ReferenceAuthorizationSubject{Kind: "salesforce_org", ID: saasSalesforceOrganization}},
	} {
		probe := &saasReferenceProbe{subject: test.subject}
		registry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{provider: probe}, map[string]ConnectorCapabilityCheck{provider: ready})
		if err != nil {
			t.Fatal(err)
		}
		authority := &referenceAuthorizationAuthorityStub{}
		workflow := WorkflowValue{Version: 3, Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"` + provider + `","name":"Reference","configuration":` + test.configuration + `,"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)}
		handler, err := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: authority, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, referenceAuthorizationRequest(t, identity, integrationID, 3, `{}`))
		if recorder.Code != http.StatusOK || probe.calls != 1 || authority.completeCalls != 1 {
			t.Fatalf("%s: status=%d probes=%d completions=%d body=%s", provider, recorder.Code, probe.calls, authority.completeCalls, recorder.Body.String())
		}
		completion := authority.completion
		if completion.Provider != provider || completion.ConnectionReference != test.reference || completion.SubjectKind != test.subject.Kind || completion.SubjectID != test.subject.ID || string(completion.Configuration) != test.configuration || completion.ConnectionID != referenceConnectionID(identity.Scope, integrationID, provider) {
			t.Fatalf("%s completion = %#v", provider, completion)
		}
		if !validReferenceAuthorizationCompletion(completion, true) {
			t.Fatalf("%s completion is not a valid reference completion", provider)
		}
		// The response never carries the reference's value or a provider token.
		for _, forbidden := range []string{"client_secret\"", "access_token", "graph_token"} {
			if strings.Contains(recorder.Body.String(), forbidden) {
				t.Fatalf("%s response leaked %q: %s", provider, forbidden, recorder.Body.String())
			}
		}
	}
}

func TestPublicSetupStatusOfMicrosoftAndSalesforceIsTheBoundSubject(t *testing.T) {
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	status := func(connector, scopeKind, label string) IntegrationSetupStatus {
		value := IntegrationSetupStatus{IntegrationID: integrationID, ConnectorKey: connector, UpdatedAt: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)}
		value.Authorization = IntegrationSetupAuthorization{State: "verified", ScopeKind: scopeKind, ScopeLabel: &label, Permissions: []string{}}
		value.RuntimeCoverage.State, value.RuntimeCoverage.Reason = "not_applicable", "not_applicable"
		return value
	}
	for _, valid := range []IntegrationSetupStatus{status("microsoft", "microsoft_tenant", saasMicrosoftTenant), status("salesforce", "salesforce_org", saasSalesforceOrganization)} {
		if !validPublicIntegrationSetupStatus(valid, integrationID) {
			t.Fatalf("%s setup status refused: %#v", valid.ConnectorKey, valid)
		}
		pending := valid
		pending.Authorization = IntegrationSetupAuthorization{State: "pending", ScopeKind: "none", Permissions: []string{}}
		if !validPublicIntegrationSetupStatus(pending, integrationID) {
			t.Fatalf("%s pending setup status refused", valid.ConnectorKey)
		}
		withPermissions := valid
		withPermissions.Authorization.Permissions = []string{"Application.Read.All"}
		selection := "all"
		withSelection := valid
		withSelection.Authorization.RepositorySelection = &selection
		for name, hostile := range map[string]IntegrationSetupStatus{"permissions": withPermissions, "repository selection": withSelection} {
			if validPublicIntegrationSetupStatus(hostile, integrationID) {
				t.Fatalf("%s setup status with %s accepted", valid.ConnectorKey, name)
			}
		}
	}
	for _, hostile := range []IntegrationSetupStatus{
		status("microsoft", "salesforce_org", saasSalesforceOrganization),
		status("microsoft", "microsoft_tenant", "contoso.onmicrosoft.com"),
		status("microsoft", "okta_tenant", "acme.okta.com"),
		status("salesforce", "salesforce_org", "00D5e000000abcd"),
		status("salesforce", "microsoft_tenant", saasMicrosoftTenant),
		status("servicenow", "salesforce_org", saasSalesforceOrganization),
	} {
		if validPublicIntegrationSetupStatus(hostile, integrationID) {
			t.Fatalf("hostile setup status accepted: %s %s %s", hostile.ConnectorKey, hostile.Authorization.ScopeKind, *hostile.Authorization.ScopeLabel)
		}
	}
}

func TestDiscoveryProviderListsNameSixProvidersAndFourReferenceAuthorizedOnes(t *testing.T) {
	for _, provider := range []string{"aws", "kubernetes", "github", "okta", "microsoft", "salesforce"} {
		if !isDiscoveryProvider(provider) || !validConnectorProvider(provider) {
			t.Fatalf("%s is not a discovery provider", provider)
		}
		// A first-party provider is never a Nango long-tail key.
		if validOAuthProvider("nango:" + provider) {
			t.Fatalf("nango:%s accepted as a long-tail provider", provider)
		}
	}
	for _, provider := range []string{"azure", "entra", "microsoft-entra", "Microsoft", "", "salesforce "} {
		if isDiscoveryProvider(provider) {
			t.Fatalf("%q accepted as a discovery provider", provider)
		}
	}
	for provider, want := range map[string]bool{"aws": true, "kubernetes": true, "microsoft": true, "salesforce": true, "github": false, "okta": false, "slack": false} {
		if isReferenceAuthorizedProvider(provider) != want {
			t.Fatalf("reference-authorized %s = %t", provider, !want)
		}
	}
	// Microsoft and Salesforce are not browser OAuth providers.
	if validOAuthProvider("microsoft") || validOAuthProvider("salesforce") {
		t.Fatal("a reference-authorized SaaS provider accepted as an OAuth provider")
	}
}
