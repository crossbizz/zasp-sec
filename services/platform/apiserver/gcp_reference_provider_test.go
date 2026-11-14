package apiserver

import (
	"encoding/json"
	"strings"
	"testing"

	platformintegration "github.com/zasp-ai/zasp-sec/services/platform/integration"
)

const (
	gcpReferenceFederation    = "ref:gcp/workload-identity/acme-security/zasp-reader"
	gcpReferenceKey           = "ref:gcp/service-account-key/customer-0001"
	gcpReferenceAudience      = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws"
	gcpFederatedConfiguration = `{"audience":"` + gcpReferenceAudience + `","identity_reference":"` + gcpReferenceFederation + `","scope":"organizations/123456789012"}`
	gcpKeyConfiguration       = `{"identity_reference":"` + gcpReferenceKey + `","scope":"folders/42"}`
)

// A Google Cloud configuration is one of two exact shapes, and never holds
// key material.
func TestReferenceConfigurationOfGoogleCloudIsExact(t *testing.T) {
	for configuration, reference := range map[string]string{gcpFederatedConfiguration: gcpReferenceFederation, gcpKeyConfiguration: gcpReferenceKey} {
		canonical, got, valid := parseReferenceAuthorizationConfiguration("gcp", json.RawMessage(configuration))
		if !valid || got != reference || string(canonical) != configuration {
			t.Fatalf("gcp configuration = %s, %q, %t", canonical, got, valid)
		}
		if !validReferenceOnlyJSON(json.RawMessage(configuration)) {
			t.Fatalf("%s refused as reference-only", configuration)
		}
		for _, provider := range []string{"aws", "kubernetes", "microsoft", "salesforce", "saas"} {
			if _, _, valid := parseReferenceAuthorizationConfiguration(provider, json.RawMessage(configuration)); valid {
				t.Fatalf("gcp configuration accepted for %s", provider)
			}
		}
	}
	// Members in any order are written back sorted, the form the worker
	// compares byte for byte.
	reordered := `{"scope":"organizations/123456789012","identity_reference":"` + gcpReferenceFederation + `","audience":"` + gcpReferenceAudience + `"}`
	if canonical, _, valid := parseReferenceAuthorizationConfiguration("gcp", json.RawMessage(reordered)); !valid || string(canonical) != gcpFederatedConfiguration {
		t.Fatalf("reordered configuration = %s, %t", canonical, valid)
	}
	replace := func(old, new string) string { return strings.Replace(gcpFederatedConfiguration, old, new, 1) }
	for name, configuration := range map[string]string{
		"federation without an audience":    `{"identity_reference":"` + gcpReferenceFederation + `","scope":"organizations/123456789012"}`,
		"an empty audience":                 replace(gcpReferenceAudience, ""),
		"a key with an audience":            replace(gcpReferenceFederation, gcpReferenceKey),
		"an audience of another host":       replace("//iam.googleapis.com", "//iam.example.com"),
		"an audience with a scheme":         replace("//iam.googleapis.com", "https://iam.googleapis.com"),
		"a workforce pool":                  replace("workloadIdentityPools", "workforcePools"),
		"a scope that is a project number":  replace("organizations/123456789012", "projects/123456789012"),
		"a scope with a path":               replace("organizations/123456789012", "organizations/123456789012/folders/1"),
		"a scope in upper case":             replace("organizations/123456789012", "Organizations/123456789012"),
		"a service account address":         replace(gcpReferenceFederation, "zasp-reader@acme-security.iam.gserviceaccount.com"),
		"a reference of another provider":   replace(gcpReferenceFederation, "ref:aws/external-id/customer-0001"),
		"a reference without the account":   replace(gcpReferenceFederation, "ref:gcp/workload-identity/acme-security"),
		"a key file instead of a reference": `{"identity_reference":"` + gcpReferenceKey + `","private_key":"key material","scope":"folders/42"}`,
		"a number where the scope belongs":  `{"identity_reference":"` + gcpReferenceKey + `","scope":42}`,
		"an unknown member":                 `{"identity_reference":"` + gcpReferenceKey + `","region":"us-central1","scope":"folders/42"}`,
		"a short key reference":             `{"identity_reference":"ref:gcp/service-account-key/k","scope":"folders/42"}`,
		"a missing scope":                   `{"identity_reference":"` + gcpReferenceKey + `"}`,
		"an audience written as JSON null":  `{"audience":null,"identity_reference":"` + gcpReferenceKey + `","scope":"folders/42"}`,
		"an empty audience beside a key":    `{"audience":"","identity_reference":"` + gcpReferenceKey + `","scope":"folders/42"}`,
	} {
		if canonical, reference, valid := parseReferenceAuthorizationConfiguration("gcp", json.RawMessage(configuration)); valid || canonical != nil || reference != "" {
			t.Fatalf("%s: accepted as %s", name, canonical)
		}
	}
}

func TestGoogleCloudIsAReferenceAuthorizedDiscoveryProviderWithAScopeSubject(t *testing.T) {
	if !isReferenceAuthorizedProvider("gcp") || !isDiscoveryProvider("gcp") {
		t.Fatal("gcp is not a reference-authorized discovery provider")
	}
	for id, want := range map[string]bool{"organizations/123456789012": true, "folders/42": true, "projects/alpha-prod": true, "projects/123456": false, "organizations/": false, "alpha-prod": false, "folders/42/": false} {
		if got := validReferenceAuthorizationSubject("gcp", ReferenceAuthorizationSubject{Kind: "gcp_scope", ID: id}); got != want {
			t.Fatalf("subject %q = %t", id, got)
		}
	}
	if validReferenceAuthorizationSubject("gcp", ReferenceAuthorizationSubject{Kind: "aws_account", ID: "projects/alpha-prod"}) || validReferenceAuthorizationSubject("aws", ReferenceAuthorizationSubject{Kind: "gcp_scope", ID: "projects/alpha-prod"}) {
		t.Fatal("a subject of another provider was accepted")
	}
	label := "folders/42"
	if !validPublicSetupAuthorization("gcp", IntegrationSetupAuthorization{State: "verified", ScopeKind: "gcp_scope", ScopeLabel: &label}) {
		t.Fatal("the setup status of a gcp integration is refused")
	}
	other := "42"
	if validPublicSetupAuthorization("gcp", IntegrationSetupAuthorization{State: "verified", ScopeKind: "gcp_scope", ScopeLabel: &other}) || validPublicSetupAuthorization("gcp", IntegrationSetupAuthorization{State: "verified", ScopeKind: "saas_tenant", ScopeLabel: &label}) {
		t.Fatal("a setup status that names no gcp scope was accepted")
	}
}

// The connector catalog entry and its setup form: a scope, the reference of
// the service account, and the provider's audience with federation.
func TestGoogleCloudManifestValidatesItsSetupForm(t *testing.T) {
	var manifest platformintegration.ConnectorManifest
	for _, value := range platformintegration.BuiltinManifests() {
		if value.Key == "gcp" {
			manifest = value
		}
	}
	if manifest.Key != "gcp" || manifest.Category != "cloud" || len(manifest.SetupSchema) != 3 || manifest.SetupSchema[0].Key != "scope" || !manifest.SetupSchema[0].Required ||
		manifest.SetupSchema[1].Key != "identity_reference" || manifest.SetupSchema[1].Type != "secret_reference" || !manifest.SetupSchema[1].Required || manifest.SetupSchema[2].Key != "audience" || manifest.SetupSchema[2].Required {
		t.Fatalf("gcp manifest = %#v", manifest)
	}
	catalog, err := platformintegration.NewCatalog(platformintegration.BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		setup map[string]string
		valid bool
	}{
		"federation":                   {map[string]string{"scope": "organizations/123456789012", "identity_reference": gcpReferenceFederation, "audience": gcpReferenceAudience}, true},
		"a key":                        {map[string]string{"scope": "projects/alpha-prod", "identity_reference": gcpReferenceKey}, true},
		"federation without audience":  {map[string]string{"scope": "folders/42", "identity_reference": gcpReferenceFederation}, false},
		"a key with an audience":       {map[string]string{"scope": "folders/42", "identity_reference": gcpReferenceKey, "audience": gcpReferenceAudience}, false},
		"an invalid scope":             {map[string]string{"scope": "my project", "identity_reference": gcpReferenceKey}, false},
		"a reference of another cloud": {map[string]string{"scope": "folders/42", "identity_reference": "ref:aws/external-id/customer-0001"}, false},
		"no reference":                 {map[string]string{"scope": "folders/42"}, false},
	} {
		if err := catalog.ValidateSetup("gcp", test.setup); (err == nil) != test.valid {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
