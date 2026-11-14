package integration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
)

const testConnectionReference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"

func saasCatalog(t *testing.T) (*Catalog, []ConnectorManifest) {
	t.Helper()
	registry, err := platforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	saas := SaaSManifests(registry)
	catalog, err := NewCatalog(append(BuiltinManifests(), saas...))
	if err != nil {
		t.Fatalf("catalog with saas entries refused: %v", err)
	}
	return catalog, saas
}

func TestSaaSManifestsListEveryPlatformOnceUnderItsOwnKey(t *testing.T) {
	registry, err := platforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	manifests := SaaSManifests(registry)
	if len(manifests) != len(registry.Platforms()) || len(manifests) == 0 {
		t.Fatalf("SaaSManifests built %d entries for %d platforms", len(manifests), len(registry.Platforms()))
	}
	seen := map[string]bool{}
	for index, manifest := range manifests {
		platform := registry.Platforms()[index]
		if manifest.Key != "saas-"+platform.Token || manifest.Platform != platform.Token || seen[manifest.Key] {
			t.Fatalf("manifest %d key=%q platform=%q for platform %q", index, manifest.Key, manifest.Platform, platform.Token)
		}
		seen[manifest.Key] = true
		if manifest.Provider != platform.DisplayName || manifest.Description != platform.Description || manifest.AccessGuidance != platform.AccessGuidance || manifest.Category != "saas" {
			t.Fatalf("%s descriptive fields = %+v", manifest.Key, manifest)
		}
		if !validManifest(manifest) {
			t.Fatalf("%s is not a valid manifest: %+v", manifest.Key, manifest)
		}
		fields := map[string]SetupField{}
		for _, field := range manifest.SetupSchema {
			fields[field.Key] = field
		}
		if tenant := fields["tenant_id"]; !tenant.Required || tenant.Label != platform.TenantLabel || tenant.Description != platform.TenantHint {
			t.Fatalf("%s tenant field = %+v", manifest.Key, tenant)
		}
		// A sign-in platform asks for the tenant only; the others also ask for
		// the Nango connection made outside the product.
		reference, asksReference := fields["connection_reference"]
		if platform.SignIn != nil {
			if manifest.AuthMode != SaaSAuthModeSignIn || asksReference || len(manifest.SetupSchema) != 1 || !strings.HasPrefix(manifest.TestSemantics, "Sign in") {
				t.Fatalf("%s sign-in manifest = %+v", manifest.Key, manifest)
			}
		} else if manifest.AuthMode != SaaSAuthModeConnection || !asksReference || !reference.Required || reference.Type != "connection_reference" || len(manifest.SetupSchema) != 2 {
			t.Fatalf("%s connection manifest = %+v", manifest.Key, manifest)
		}
	}
}

func TestSaaSCatalogEntriesAreSearchableAndCarryNoImplementationName(t *testing.T) {
	catalog, saas := saasCatalog(t)
	items, err := catalog.Search(CatalogFilter{Category: "saas"})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]PublicManifest{}
	for _, item := range items {
		byKey[item.Key] = item
	}
	for _, manifest := range saas {
		item, ok := byKey[manifest.Key]
		if !ok || item.Platform != manifest.Platform {
			t.Fatalf("catalog search lacks %s: %+v", manifest.Key, items)
		}
		serialized, _ := json.Marshal(item)
		for _, forbidden := range []string{`"adapter`, `"oss`, "saas_nango_v1", "nango-proxy"} {
			if strings.Contains(string(serialized), forbidden) {
				t.Fatalf("%s public manifest leaked %q: %s", item.Key, forbidden, serialized)
			}
		}
	}
	if items, err := catalog.Search(CatalogFilter{AuthMode: SaaSAuthModeSignIn}); err != nil || len(items) == 0 {
		t.Fatalf("sign-in search = %v, %v", items, err)
	}
}

func TestSaaSSetupValidatesPlatformTenantAndConnection(t *testing.T) {
	catalog, _ := saasCatalog(t)
	valid := func(configuration map[string]string) error {
		return catalog.ValidateSetup(SaaSConnectorKey, configuration)
	}

	// A platform without a sign-in needs the connection reference.
	for _, configuration := range []map[string]string{
		{"platform": "openai", "tenant_id": "org-abcdefgh12", "connection_reference": testConnectionReference},
		{"platform": "gitlab", "tenant_id": "12345", "connection_reference": testConnectionReference},
		// A sign-in platform waits for its sign-in with the tenant only.
		{"platform": "gitlab", "tenant_id": "12345"},
		{"platform": "slack", "tenant_id": "T0123ABCD9"},
		{"platform": "servicenow", "tenant_id": "acme-dev"},
	} {
		if err := valid(configuration); err != nil {
			t.Errorf("ValidateSetup(saas, %v) = %v, want accepted", configuration, err)
		}
	}
	for name, configuration := range map[string]map[string]string{
		"no reference without sign-in":   {"platform": "openai", "tenant_id": "org-abcdefgh12"},
		"unknown platform":               {"platform": "acme", "tenant_id": "x", "connection_reference": testConnectionReference},
		"missing platform":               {"tenant_id": "org-abcdefgh12", "connection_reference": testConnectionReference},
		"tenant outside grammar":         {"platform": "openai", "tenant_id": "acme", "connection_reference": testConnectionReference},
		"empty tenant":                   {"platform": "slack", "tenant_id": ""},
		"malformed reference":            {"platform": "openai", "tenant_id": "org-abcdefgh12", "connection_reference": "sk-live-token"},
		"empty reference on sign-in":     {"platform": "slack", "tenant_id": "T0123ABCD9", "connection_reference": ""},
		"extra field":                    {"platform": "slack", "tenant_id": "T0123ABCD9", "connection_reference": testConnectionReference, "token": "x"},
		"unknown field instead of a ref": {"platform": "openai", "tenant_id": "org-abcdefgh12", "api_key": "x"},
		"nothing":                        {},
	} {
		if err := valid(configuration); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ValidateSetup(saas, %v) = %v, want ErrInvalid", name, configuration, err)
		}
	}
	// A catalog entry is never a connector key of its own.
	if err := catalog.ValidateSetup("saas-openai", map[string]string{"platform": "openai", "tenant_id": "org-abcdefgh12", "connection_reference": testConnectionReference}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ValidateSetup(saas-openai) = %v, want ErrInvalid", err)
	}
	// Without saas entries in the catalog no saas setup is accepted.
	builtin, err := NewCatalog(BuiltinManifests())
	if err != nil {
		t.Fatal(err)
	}
	if err := builtin.ValidateSetup(SaaSConnectorKey, map[string]string{"platform": "openai", "tenant_id": "org-abcdefgh12", "connection_reference": testConnectionReference}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("builtin catalog accepted a saas setup: %v", err)
	}
}

func TestCatalogRefusesAHandWrittenSaaSEntry(t *testing.T) {
	_, saas := saasCatalog(t)
	tampered := saas[0]
	tampered.Key = "saas-other"
	if _, err := NewCatalog([]ConnectorManifest{tampered}); err == nil {
		t.Fatal("catalog accepted a saas entry whose key does not name its platform")
	}
	withoutValidator := saas[0]
	withoutValidator.validate = nil
	if _, err := NewCatalog([]ConnectorManifest{withoutValidator}); err == nil {
		t.Fatal("catalog accepted a saas entry without its validator")
	}
	bare := saas[0]
	bare.Key, bare.Platform, bare.validate = SaaSConnectorKey, "", nil
	if _, err := NewCatalog([]ConnectorManifest{bare}); err == nil {
		t.Fatal("catalog accepted the bare saas connector key as an entry")
	}
}
