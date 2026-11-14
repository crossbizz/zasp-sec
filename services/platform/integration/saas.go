package integration

import (
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// SaaSConnectorKey is the connector key of every integration of the generic
// saas discovery provider. The platform is in the configuration.
const SaaSConnectorKey = "saas"

// SaaSManifests builds one catalog entry per platform of the registry. The
// catalog is how a platform reaches the API and the web app: nothing else
// lists platforms, so a new platform definition appears in the catalog with
// no further code.
//
// An entry's key is "saas-<platform>" and its Platform is the platform
// token. Its integration is created with the connector key "saas" and the
// configuration {platform, tenant_id, connection_reference}; the setup form
// asks for the last two.
func SaaSManifests(registry *saasdiscovery.Registry) []ConnectorManifest {
	platforms := registry.Platforms()
	manifests := make([]ConnectorManifest, 0, len(platforms))
	for _, platform := range platforms {
		platform := platform
		manifests = append(manifests, ConnectorManifest{
			Key: SaaSConnectorKey + "-" + platform.Token, Provider: platform.DisplayName, Category: "saas", Description: platform.Description,
			DataTypes: []string{"agent", "application"}, Actions: []string{"inventory_read"}, AuthMode: "nango_connection",
			SetupSchema: []SetupField{
				{Key: "tenant_id", Label: platform.TenantLabel, Type: "string", Required: true, Description: platform.TenantHint},
				{Key: "connection_reference", Label: "Nango connection", Type: "connection_reference", Required: true, Description: "Opaque reference to the Nango connection created for this tenant, ref:nango/connection/<connection id>. Nango holds the provider token; the product stores only this reference."},
			},
			AccessGuidance: platform.AccessGuidance,
			TestSemantics:  "Ask the platform, through the Nango connection, which tenant the connection reaches and require it to be the configured tenant.",
			Platform:       platform.Token, adapterKey: "saas_nango_v1", ossName: "nango-proxy",
			validate: func(configuration map[string]string) bool {
				return len(configuration) == 3 && configuration["platform"] == platform.Token && platform.ValidTenant(configuration["tenant_id"]) && saasdiscovery.ValidConnectionReference(configuration["connection_reference"])
			},
		})
	}
	return manifests
}

// validateSaaSSetup accepts the configuration of a saas integration: exactly
// platform, tenant_id and connection_reference, for a platform in the
// catalog, with that platform's tenant grammar.
func (catalog *Catalog) validateSaaSSetup(configuration map[string]string) error {
	manifest, exists := catalog.values[SaaSConnectorKey+"-"+configuration["platform"]]
	if !exists || manifest.Platform == "" || manifest.validate == nil || !manifest.validate(configuration) {
		return ErrInvalid
	}
	return nil
}
