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

	saasplatforms "github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
	platformintegration "github.com/zasp-ai/zasp-sec/services/platform/integration"
)

const (
	saasGenericConnection    = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	saasGenericConfiguration = `{"connection_reference":"ref:nango/connection/11111111-1111-4111-8111-111111111111","platform":"databricks","tenant_id":"1234567890123456"}`
	saasGenericSubject       = "databricks/1234567890123456"
)

func TestReferenceConfigurationOfTheSaaSProviderIsExact(t *testing.T) {
	canonical, reference, valid := parseReferenceAuthorizationConfiguration("saas", json.RawMessage(saasGenericConfiguration))
	if !valid || reference != saasGenericConnection || string(canonical) != saasGenericConfiguration {
		t.Fatalf("saas configuration = %s, %q, %t", canonical, reference, valid)
	}
	// Members in any order are accepted and written back sorted, the form
	// the worker compares byte for byte.
	reordered := `{"tenant_id":"1234567890123456","platform":"databricks","connection_reference":"` + saasGenericConnection + `"}`
	if canonical, _, valid := parseReferenceAuthorizationConfiguration("saas", json.RawMessage(reordered)); !valid || string(canonical) != saasGenericConfiguration {
		t.Fatalf("reordered saas configuration = %s, %t", canonical, valid)
	}
	if !validReferenceOnlyJSON(json.RawMessage(saasGenericConfiguration)) {
		t.Fatal("saas configuration refused as reference-only")
	}
	replace := func(old, new string) string { return strings.Replace(saasGenericConfiguration, old, new, 1) }
	for name, configuration := range map[string]string{
		"a platform in upper case":             replace(`"databricks"`, `"Databricks"`),
		"a platform with a path":               replace(`"databricks"`, `"data/bricks"`),
		"a tenant with a path":                 replace("1234567890123456", "12/34"),
		"a tenant with a parent reference":     replace("1234567890123456", "a..b"),
		"an empty tenant":                      replace("1234567890123456", ""),
		"a tenant longer than a scope label":   replace("1234567890123456", strings.Repeat("a", 96)),
		"a reference of another provider":      replace("ref:nango/connection/", "ref:kubernetes/connection/"),
		"the Nango service key":                replace(saasGenericConnection, "ref:nango/service-key-0001"),
		"a connection id that is not a UUID":   replace("11111111-1111-4111-8111-111111111111", "customer-0001"),
		"a token instead of a reference":       replace(saasGenericConnection, "dapi" + "0123456789abcdef0123456789abcdef"),
		"a missing platform":                   `{"connection_reference":"` + saasGenericConnection + `","tenant_id":"1234567890123456"}`,
		"an unknown member":                    replace(`"platform"`, `"access_token":"value","platform"`),
		"a number where the tenant id belongs": replace(`"1234567890123456"`, `1234567890123456`),
	} {
		if canonical, reference, valid := parseReferenceAuthorizationConfiguration("saas", json.RawMessage(configuration)); valid || canonical != nil || reference != "" {
			t.Fatalf("%s: accepted as %s", name, canonical)
		}
	}
	// A saas configuration is not another provider's, and the reverse.
	for _, provider := range []string{"kubernetes", "microsoft", "salesforce", "aws"} {
		if _, _, valid := parseReferenceAuthorizationConfiguration(provider, json.RawMessage(saasGenericConfiguration)); valid {
			t.Fatalf("saas configuration accepted for %s", provider)
		}
	}
	if _, _, valid := parseReferenceAuthorizationConfiguration("saas", json.RawMessage(saasSalesforceConfiguration)); valid {
		t.Fatal("salesforce configuration accepted for saas")
	}
}

func TestSaaSIsAReferenceAuthorizedDiscoveryProviderWithATenantSubject(t *testing.T) {
	if !isDiscoveryProvider("saas") || !isReferenceAuthorizedProvider("saas") || !validConnectorProvider("saas") {
		t.Fatal("saas is not a reference-authorized discovery provider")
	}
	// saas is a provider, not a Nango key, and not a browser OAuth provider.
	if validOAuthProvider("saas") || validOAuthProvider("nango:saas") {
		t.Fatal("saas accepted as an OAuth provider")
	}
	// The platforms are not providers.
	for _, platform := range []string{"databricks", "slack"} {
		if isDiscoveryProvider(platform) || isReferenceAuthorizedProvider(platform) {
			t.Fatalf("platform %s accepted as a discovery provider", platform)
		}
	}
	for subject, want := range map[ReferenceAuthorizationSubject]bool{
		{Kind: "saas_tenant", ID: saasGenericSubject}:                      true,
		{Kind: "saas_tenant", ID: "slack/T024BE7LD"}:                       true,
		{Kind: "saas_tenant", ID: "slack"}:                                 false,
		{Kind: "saas_tenant", ID: "Slack/T024BE7LD"}:                       false,
		{Kind: "saas_tenant", ID: "slack/T024/BE7LD"}:                      false,
		{Kind: "saas_tenant", ID: "slack/T0..LD"}:                          false,
		{Kind: "saas_tenant", ID: "slack/" + strings.Repeat("a", 96)}:      false,
		{Kind: "salesforce_org", ID: saasSalesforceOrganization}:           false,
		{Kind: "okta_tenant", ID: saasGenericSubject}:                      false,
		{Kind: "saas_tenant", ID: "databricks/1234567890123456\n"}:         false,
		{Kind: "saas_tenant", ID: "databricks/1234567890123456 "}:          false,
		{Kind: "saas_tenant", ID: ""}:                                      false,
		{Kind: "saas_tenant", ID: "databricks/" + strings.Repeat("9", 95)}: true,
	} {
		if validReferenceAuthorizationSubject("saas", subject) != want {
			t.Fatalf("saas subject %#v valid = %t", subject, !want)
		}
	}
	if validReferenceAuthorizationSubject("salesforce", ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: saasGenericSubject}) {
		t.Fatal("a saas subject accepted for salesforce")
	}
}

// B4: the catalog lists every registered platform where the deployment
// serves the saas provider, and none where it does not.
func TestConnectorCatalogListsTheRegisteredSaaSPlatforms(t *testing.T) {
	ready := func(context.Context) error { return nil }
	aws := &saasReferenceProbe{subject: ReferenceAuthorizationSubject{Kind: "aws_account", ID: "123456789012"}}
	saas := &saasReferenceProbe{subject: ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: saasGenericSubject}}
	without, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": aws}, map[string]ConnectorCapabilityCheck{"aws": ready})
	if err != nil {
		t.Fatal(err)
	}
	capabilities := CombinedConnectorCapabilities{OAuth: fixedConnectorCapabilities{"github": {}, "okta": {}}, Reference: without}
	for _, manifest := range locallyCompleteWorkflowManifests(context.Background(), capabilities, false) {
		if manifest.Platform != "" || strings.HasPrefix(manifest.Key, "saas") {
			t.Fatalf("%s is in the catalog of a deployment that does not serve saas", manifest.Key)
		}
	}
	if _, err := without.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "saas", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: saasGenericConnection, Configuration: json.RawMessage(saasGenericConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unregistered saas probe error = %v", err)
	}

	registry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": aws, "saas": saas}, map[string]ConnectorCapabilityCheck{"aws": ready, "saas": ready})
	if err != nil {
		t.Fatal(err)
	}
	capabilities.Reference = registry
	manifests := locallyCompleteWorkflowManifests(context.Background(), capabilities, false)
	catalog, err := platformintegration.NewCatalog(manifests)
	if err != nil {
		t.Fatalf("catalog with the saas platforms refused: %v", err)
	}
	entries, err := catalog.Search(platformintegration.CatalogFilter{Category: "saas", AuthMode: "nango_connection"})
	if err != nil {
		t.Fatal(err)
	}
	// One entry per registered platform, read from the platform registry:
	// this test names no platform.
	platforms, err := saasplatforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(platforms.Platforms()) || len(entries) < 2 {
		t.Fatalf("saas catalog entries = %d, registered platforms = %d", len(entries), len(platforms.Platforms()))
	}
	for index, platform := range platforms.Platforms() {
		entry := entries[index]
		if entry.Key != "saas-"+platform.Token || entry.Platform != platform.Token || entry.Provider != platform.DisplayName || entry.Description != platform.Description || entry.AccessGuidance != platform.AccessGuidance ||
			len(entry.SetupSchema) != 2 || entry.SetupSchema[0].Key != "tenant_id" || entry.SetupSchema[0].Label != platform.TenantLabel || !entry.SetupSchema[0].Required || entry.SetupSchema[1].Key != "connection_reference" || entry.SetupSchema[1].Type != "connection_reference" {
			t.Fatalf("catalog entry of %s = %#v", platform.Token, entry)
		}
		// The integration of an entry is created with the connector key
		// "saas" and the entry's platform in its configuration.
		tenant := map[string]string{"databricks": "1234567890123456", "slack": "T024BE7LD"}[platform.Token]
		if tenant == "" {
			continue
		}
		configuration := map[string]string{"platform": platform.Token, "tenant_id": tenant, "connection_reference": saasGenericConnection}
		if err := catalog.ValidateSetup("saas", configuration); err != nil {
			t.Fatalf("%s setup refused: %v", platform.Token, err)
		}
		// The entry key is not a connector key.
		if err := catalog.ValidateSetup(entry.Key, configuration); err == nil {
			t.Fatalf("%s accepted as a connector key", entry.Key)
		}
	}
	for name, configuration := range map[string]map[string]string{
		"an unregistered platform":          {"platform": "servicenow", "tenant_id": "dev12345", "connection_reference": saasGenericConnection},
		"a tenant of another platform":      {"platform": "databricks", "tenant_id": "T024BE7LD", "connection_reference": saasGenericConnection},
		"no platform":                       {"tenant_id": "1234567890123456", "connection_reference": saasGenericConnection},
		"a reference that is no connection": {"platform": "databricks", "tenant_id": "1234567890123456", "connection_reference": "ref:nango/service-key-0001"},
		"a further member":                  {"platform": "databricks", "tenant_id": "1234567890123456", "connection_reference": saasGenericConnection, "workspace_url": "https://example.cloud.databricks.com"},
	} {
		if err := catalog.ValidateSetup("saas", configuration); err == nil {
			t.Fatalf("%s: setup accepted", name)
		}
	}
	// The public form of an entry carries the platform; other entries do not.
	payload, err := json.Marshal(entries[0])
	if err != nil || !strings.Contains(string(payload), `"platform":"`+entries[0].Platform+`"`) {
		t.Fatalf("public saas entry = %s, %v", payload, err)
	}
	others, _ := catalog.Search(platformintegration.CatalogFilter{Category: "cloud"})
	if payload, _ := json.Marshal(others); len(others) != 1 || strings.Contains(string(payload), `"platform"`) {
		t.Fatalf("a first-party entry carries a platform: %s", payload)
	}

	// The registry runs the probe and accepts only a saas tenant subject.
	subject, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "saas", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: saasGenericConnection, Configuration: json.RawMessage(saasGenericConfiguration)})
	if err != nil || subject != (ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: saasGenericSubject}) || string(saas.target.Configuration) != saasGenericConfiguration {
		t.Fatalf("saas probe = %#v, %v", subject, err)
	}
	calls := saas.calls
	if _, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "saas", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: "ref:nango/connection/22222222-2222-4222-8222-222222222222", Configuration: json.RawMessage(saasGenericConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) || saas.calls != calls {
		t.Fatalf("mismatched reference: err=%v calls=%d", err, saas.calls-calls)
	}
	for _, hostile := range []ReferenceAuthorizationSubject{{Kind: "salesforce_org", ID: saasSalesforceOrganization}, {Kind: "saas_tenant", ID: "databricks"}, {}} {
		saas.subject = hostile
		if _, err := registry.Probe(context.Background(), ReferenceAuthorizationTarget{Provider: "saas", IntegrationID: "pid_74000001-0000-4000-8000-000000000001", ConnectionReference: saasGenericConnection, Configuration: json.RawMessage(saasGenericConfiguration)}); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("saas probe subject %#v accepted: %v", hostile, err)
		}
	}
}

func TestReferenceAuthorizationHandlerCompletesASaaSIntegrationWithItsTenant(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	probe := &saasReferenceProbe{subject: ReferenceAuthorizationSubject{Kind: "saas_tenant", ID: saasGenericSubject}}
	registry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"saas": probe}, map[string]ConnectorCapabilityCheck{"saas": func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	authority := &referenceAuthorizationAuthorityStub{}
	workflow := WorkflowValue{Version: 3, Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"saas","name":"Databricks","configuration":` + saasGenericConfiguration + `,"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)}
	handler, err := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: authority, Workflows: connectorWorkflowStub{value: workflow}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, referenceAuthorizationRequest(t, identity, integrationID, 3, `{}`))
	if recorder.Code != http.StatusOK || probe.calls != 1 || authority.completeCalls != 1 {
		t.Fatalf("status=%d probes=%d completions=%d body=%s", recorder.Code, probe.calls, authority.completeCalls, recorder.Body.String())
	}
	completion := authority.completion
	if completion.Provider != "saas" || completion.ConnectionReference != saasGenericConnection || completion.SubjectKind != "saas_tenant" || completion.SubjectID != saasGenericSubject || string(completion.Configuration) != saasGenericConfiguration || completion.ConnectionID != referenceConnectionID(identity.Scope, integrationID, "saas") {
		t.Fatalf("completion = %#v", completion)
	}
	if !validReferenceAuthorizationCompletion(completion, true) {
		t.Fatal("completion is not a valid reference completion")
	}
}

func TestPublicSetupStatusOfASaaSIntegrationIsItsTenant(t *testing.T) {
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	status := func(connector, scopeKind, label string) IntegrationSetupStatus {
		value := IntegrationSetupStatus{IntegrationID: integrationID, ConnectorKey: connector, UpdatedAt: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)}
		value.Authorization = IntegrationSetupAuthorization{State: "verified", ScopeKind: scopeKind, ScopeLabel: &label, Permissions: []string{}}
		value.RuntimeCoverage.State, value.RuntimeCoverage.Reason = "not_applicable", "not_applicable"
		return value
	}
	if !validPublicIntegrationSetupStatus(status("saas", "saas_tenant", saasGenericSubject), integrationID) {
		t.Fatal("saas setup status refused")
	}
	pending := status("saas", "saas_tenant", saasGenericSubject)
	pending.Authorization = IntegrationSetupAuthorization{State: "pending", ScopeKind: "none", Permissions: []string{}}
	if !validPublicIntegrationSetupStatus(pending, integrationID) {
		t.Fatal("pending saas setup status refused")
	}
	withPermissions := status("saas", "saas_tenant", saasGenericSubject)
	withPermissions.Authorization.Permissions = []string{"all-apis"}
	for name, hostile := range map[string]IntegrationSetupStatus{
		"a permission list":         withPermissions,
		"another provider's scope":  status("saas", "salesforce_org", saasSalesforceOrganization),
		"a tenant without platform": status("saas", "saas_tenant", "1234567890123456"),
		"a saas scope on microsoft": status("microsoft", "saas_tenant", saasGenericSubject),
		"a platform as a connector": status("databricks", "saas_tenant", saasGenericSubject),
	} {
		if validPublicIntegrationSetupStatus(hostile, integrationID) {
			t.Fatalf("%s: setup status accepted", name)
		}
	}
}
