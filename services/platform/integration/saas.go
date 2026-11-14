package integration

import (
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// SaaSConnectorKey is the connector key of every integration of the generic
// saas discovery provider. The platform is in the configuration.
const SaaSConnectorKey = "saas"

// The two ways a saas integration is connected, as the catalog names them.
const (
	// SaaSAuthModeConnection: the integration names a Nango connection that
	// was created in Nango.
	SaaSAuthModeConnection = "nango_connection"
	// SaaSAuthModeSignIn: a person signs in to the platform from the
	// product; Nango creates the connection.
	SaaSAuthModeSignIn = "nango_sign_in"
)

// SaaSManifests builds one catalog entry per platform of the registry. The
// catalog is how a platform reaches the API and the web app: nothing else
// lists platforms, so a new platform definition appears in the catalog with
// no further code.
//
// An entry's key is "saas-<platform>" and its Platform is the platform
// token. Its integration is created with the connector key "saas".
//
// A platform whose definition declares a sign-in is set up with the tenant
// only: the configuration is {platform, tenant_id}, the person then signs in
// to the platform, and the reference of the connection Nango created is
// added to the configuration before the integration is authorized. Every
// platform also accepts the full configuration {platform, tenant_id,
// connection_reference}, which names a connection made in Nango; a platform
// without a sign-in accepts only that and its setup form asks for it.
func SaaSManifests(registry *saasdiscovery.Registry) []ConnectorManifest {
	platforms := registry.Platforms()
	manifests := make([]ConnectorManifest, 0, len(platforms))
	for _, platform := range platforms {
		platform := platform
		signIn := platform.SignIn != nil
		authMode := SaaSAuthModeConnection
		schema := []SetupField{{Key: "tenant_id", Label: platform.TenantLabel, Type: "string", Required: true, Description: platform.TenantHint}}
		semantics := "Ask the platform, through the Nango connection, which tenant the connection reaches and require it to be the configured tenant."
		if signIn {
			authMode = SaaSAuthModeSignIn
			semantics = "Sign in to the platform, then ask it, through the Nango connection the sign-in created, which tenant the connection reaches and require it to be the configured tenant."
		} else {
			schema = append(schema, SetupField{Key: "connection_reference", Label: "Nango connection", Type: "connection_reference", Required: true, Description: "Opaque reference to the Nango connection created for this tenant, ref:nango/connection/<connection id>. Nango holds the provider token; the product stores only this reference."})
		}
		manifests = append(manifests, ConnectorManifest{
			Key: SaaSConnectorKey + "-" + platform.Token, Provider: platform.DisplayName, Category: "saas", Description: platform.Description,
			DataTypes: []string{"agent", "application"}, Actions: []string{"inventory_read"}, AuthMode: authMode,
			SetupSchema:    schema,
			AccessGuidance: platform.AccessGuidance,
			TestSemantics:  semantics,
			Platform:       platform.Token, adapterKey: "saas_nango_v1", ossName: "nango-proxy",
			validate: func(configuration map[string]string) bool {
				if configuration["platform"] != platform.Token || !platform.ValidTenant(configuration["tenant_id"]) {
					return false
				}
				// Waiting for its sign-in, or naming its connection.
				if len(configuration) == 2 {
					return signIn
				}
				return len(configuration) == 3 && saasdiscovery.ValidConnectionReference(configuration["connection_reference"])
			},
		})
	}
	return manifests
}

// validateSaaSSetup accepts the configuration of a saas integration: platform
// and tenant_id for a platform in the catalog, with that platform's tenant
// grammar, and the connection_reference, which only a platform with a
// sign-in may leave out.
func (catalog *Catalog) validateSaaSSetup(configuration map[string]string) error {
	manifest, exists := catalog.values[SaaSConnectorKey+"-"+configuration["platform"]]
	if !exists || manifest.Platform == "" || manifest.validate == nil || !manifest.validate(configuration) {
		return ErrInvalid
	}
	return nil
}
