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
