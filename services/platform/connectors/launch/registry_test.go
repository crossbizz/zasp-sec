package launch

import (
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestRegistryDeclaresFourFirstPartyLaunchConnectorsWithoutCollectionOverclaim(t *testing.T) {
	registry, err := NewRegistry(DefaultManifests(), DefaultCredentialClasses())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"aws", "github", "kubernetes", "okta"} {
		manifest, ok := registry.FirstParty(key)
		if !ok || manifest.Key != key || manifest.AuthorizationReady != true || manifest.CollectionReady || manifest.Nango {
			t.Fatalf("first-party %q = %#v, %t", key, manifest, ok)
		}
		if len(manifest.RequiredScopes) == 0 || manifest.HealthMode == "" || manifest.DegradationMode != "provider_only" {
			t.Fatalf("first-party contract %q = %#v", key, manifest)
		}
	}
	if _, ok := registry.FirstParty("nango:github"); ok {
		t.Fatal("Nango alias exposed as first-party GitHub")
	}
	for _, class := range []string{"oauth_attempt", "aws_external_id", "kubernetes_cluster_reference", "github_installation_reference", "okta_refresh_reference", "nango_connection_reference"} {
		value, ok := registry.CredentialClass(class)
		if !ok || value.Creator == "" || value.Resolver == "" || value.Storage == "" || len(value.ProhibitedSinks) < 5 {
			t.Fatalf("credential class %q = %#v, %t", class, value, ok)
		}
	}
}

func TestCanonicalIDsBindTheFullScopeAndSourceNativeIdentity(t *testing.T) {
	scope := launchScope(t, 1, 2, 3)
	first, err := CanonicalEntityID(scope, "github_repository", "acme/api")
	if err != nil {
		t.Fatal(err)
	}
	replay, _ := CanonicalEntityID(scope, "github_repository", "acme/api")
	other, _ := CanonicalEntityID(launchScope(t, 1, 2, 4), "github_repository", "acme/api")
	if first != replay || first == other || len(first) != 40 || first[:4] != "pid_" {
		t.Fatalf("canonical ids = %q/%q/%q", first, replay, other)
	}
	if _, err := CanonicalEntityID(scope, "github_repository", ""); err == nil {
		t.Fatal("empty provider-native identity accepted")
	}
}

func launchScope(t *testing.T, organization, workspace, environment int) domain.Scope {
	t.Helper()
	parse := func(value int) domain.ProductID {
		id, err := domain.ParseProductID("pid_1000000" + string(rune('0'+value)) + "-0000-4000-8000-00000000000" + string(rune('0'+value)))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(parse(organization), parse(workspace), parse(environment))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestRegistryRequiresTheFourLaunchConnectorsAndAdmitsTheOptionalSaaSOnes(t *testing.T) {
	all := DefaultManifests()
	byKey := map[string]Manifest{}
	for _, manifest := range all {
		byKey[manifest.Key] = manifest
	}
	pick := func(keys ...string) []Manifest {
		result := make([]Manifest, 0, len(keys))
		for _, key := range keys {
			result = append(result, byKey[key])
		}
		return result
	}
	if len(all) != 7 {
		t.Fatalf("default manifests = %d, want the four launch connectors, two SaaS agent providers and the generic saas provider", len(all))
	}
	for _, valid := range [][]string{
		{"aws", "kubernetes", "github", "okta"},
		{"aws", "kubernetes", "github", "okta", "microsoft"},
		{"aws", "kubernetes", "github", "okta", "salesforce"},
		{"aws", "kubernetes", "github", "okta", "microsoft", "salesforce"},
		{"aws", "kubernetes", "github", "okta", "saas"},
		{"aws", "kubernetes", "github", "okta", "microsoft", "salesforce", "saas"},
	} {
		registry, err := NewRegistry(pick(valid...), DefaultCredentialClasses())
		if err != nil {
			t.Fatalf("manifests %v refused: %v", valid, err)
		}
		for _, key := range []string{"microsoft", "salesforce", "saas"} {
			_, declared := registry.FirstParty(key)
			wanted := false
			for _, present := range valid {
				wanted = wanted || present == key
			}
			if declared != wanted {
				t.Fatalf("manifests %v: first-party %q = %t", valid, key, declared)
			}
		}
	}
	unknown := byKey["okta"]
	unknown.Key = "servicenow"
	for name, hostile := range map[string][]Manifest{
		"three launch connectors":         pick("aws", "kubernetes", "github"),
		"a SaaS provider replaces okta":   pick("aws", "kubernetes", "github", "microsoft"),
		"both SaaS providers replace two": pick("aws", "kubernetes", "microsoft", "salesforce"),
		"a SaaS provider twice":           pick("aws", "kubernetes", "github", "okta", "microsoft", "microsoft"),
		"an unknown fifth connector":      append(pick("aws", "kubernetes", "github", "okta"), unknown),
		"eight manifests":                 append(pick("aws", "kubernetes", "github", "okta", "microsoft", "salesforce", "saas"), unknown),
		"saas without the Nango flag":     append(pick("aws", "kubernetes", "github", "okta"), Manifest{Key: "saas", AuthMode: "nango_connection_reference", RequiredScopes: []string{"nango:proxy"}, HealthMode: "tenant_probe", DegradationMode: "provider_only", AuthorizationReady: true}),
		"a first-party provider on Nango": append(pick("aws", "kubernetes", "github", "okta"), Manifest{Key: "microsoft", AuthMode: "first_party_client_credentials", RequiredScopes: []string{"Application.Read.All"}, HealthMode: "token_and_tenant_probe", DegradationMode: "provider_only", AuthorizationReady: true, Nango: true}),
	} {
		if _, err := NewRegistry(hostile, DefaultCredentialClasses()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	registry, err := NewRegistry(all, DefaultCredentialClasses())
	if err != nil {
		t.Fatal(err)
	}
	for key, scopes := range map[string][]string{"microsoft": {"AgentIdentity.Read.All", "Application.Read.All"}, "salesforce": {"api"}} {
		manifest, ok := registry.FirstParty(key)
		if !ok || manifest.Nango || manifest.CollectionReady || !manifest.AuthorizationReady || manifest.AuthMode != "first_party_client_credentials" || len(manifest.RequiredScopes) != len(scopes) {
			t.Fatalf("first-party %q = %#v, %t", key, manifest, ok)
		}
		for index, scope := range scopes {
			if manifest.RequiredScopes[index] != scope {
				t.Fatalf("%q scopes = %v, want %v", key, manifest.RequiredScopes, scopes)
			}
		}
	}
	for _, class := range []string{"microsoft_client_secret", "salesforce_client_secret"} {
		value, ok := registry.CredentialClass(class)
		if !ok || value.Storage != "secrets_manager_connector_kms" || value.Audit != "reference_only" || value.Resolver != "api_and_discovery_worker" || len(value.ProhibitedSinks) < 5 {
			t.Fatalf("credential class %q = %#v, %t", class, value, ok)
		}
	}
}
