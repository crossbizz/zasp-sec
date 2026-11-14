package launch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrInvalid = errors.New("launch connector contract rejected")
var tokenPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

type Manifest struct {
	Key, AuthMode, HealthMode, DegradationMode string
	RequiredScopes                             []string
	AuthorizationReady, CollectionReady, Nango bool
}

type CredentialClass struct {
	Key, Creator, MetadataReader, Resolver, Rotator, Revoker, Storage, TTL, Audit, Deletion string
	ProhibitedSinks                                                                         []string
}

type Registry struct {
	firstParty  map[string]Manifest
	credentials map[string]CredentialClass
}

func NewRegistry(manifests []Manifest, credentials []CredentialClass) (*Registry, error) {
	if len(manifests) < len(requiredFirstParty) || len(manifests) > len(requiredFirstParty)+len(optionalFirstParty) || len(credentials) < 6 || len(credentials) > 32 {
		return nil, ErrInvalid
	}
	registry := &Registry{firstParty: make(map[string]Manifest, len(manifests)), credentials: make(map[string]CredentialClass, len(credentials))}
	for _, manifest := range manifests {
		if !validManifest(manifest) {
			return nil, ErrInvalid
		}
		if _, exists := registry.firstParty[manifest.Key]; exists || !firstPartyKey(manifest.Key) {
			return nil, ErrInvalid
		}
		manifest.RequiredScopes = append([]string(nil), manifest.RequiredScopes...)
		registry.firstParty[manifest.Key] = manifest
	}
	for _, key := range requiredFirstParty {
		if _, exists := registry.firstParty[key]; !exists {
			return nil, ErrInvalid
		}
	}
	for _, class := range credentials {
		if !validCredentialClass(class) {
			return nil, ErrInvalid
		}
		if _, exists := registry.credentials[class.Key]; exists {
			return nil, ErrInvalid
		}
		class.ProhibitedSinks = append([]string(nil), class.ProhibitedSinks...)
		registry.credentials[class.Key] = class
	}
	return registry, nil
}

// requiredFirstParty are the launch connectors every registry declares.
// optionalFirstParty are first-party connectors a registry may also declare:
// the SaaS agent providers, which a deployment serves only where it runs
// their collector.
var (
	requiredFirstParty = []string{"aws", "kubernetes", "github", "okta"}
	optionalFirstParty = []string{"microsoft", "salesforce"}
)

func firstPartyKey(key string) bool {
	for _, known := range append(append([]string(nil), requiredFirstParty...), optionalFirstParty...) {
		if key == known {
			return true
		}
	}
	return false
}

func (registry *Registry) FirstParty(key string) (Manifest, bool) {
	if registry == nil || registry.firstParty == nil {
		return Manifest{}, false
	}
	value, ok := registry.firstParty[key]
	value.RequiredScopes = append([]string(nil), value.RequiredScopes...)
	return value, ok
}

func (registry *Registry) CredentialClass(key string) (CredentialClass, bool) {
	if registry == nil || registry.credentials == nil {
		return CredentialClass{}, false
	}
	value, ok := registry.credentials[key]
	value.ProhibitedSinks = append([]string(nil), value.ProhibitedSinks...)
	return value, ok
}

func DefaultManifests() []Manifest {
	return []Manifest{
		{Key: "aws", AuthMode: "first_party_assume_role", RequiredScopes: []string{"sts:GetCallerIdentity"}, HealthMode: "identity_and_permission_probe", DegradationMode: "provider_only", AuthorizationReady: true},
		{Key: "github", AuthMode: "first_party_github_app", RequiredScopes: []string{"actions:read", "contents:read", "metadata:read"}, HealthMode: "installation_probe", DegradationMode: "provider_only", AuthorizationReady: true},
		{Key: "kubernetes", AuthMode: "first_party_reference_bind", RequiredScopes: []string{"get", "list", "watch"}, HealthMode: "version_and_self_subject_rules", DegradationMode: "provider_only", AuthorizationReady: true},
		{Key: "okta", AuthMode: "first_party_oauth_pkce", RequiredScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, HealthMode: "issuer_and_directory_probe", DegradationMode: "provider_only", AuthorizationReady: true},
		// Application permissions of the customer's Entra app registration.
		// Dataverse access for Copilot Studio is granted in the environment
		// (an application user), not as a Graph permission.
		{Key: "microsoft", AuthMode: "first_party_client_credentials", RequiredScopes: []string{"AgentIdentity.Read.All", "Application.Read.All"}, HealthMode: "token_and_tenant_probe", DegradationMode: "provider_only", AuthorizationReady: true},
		{Key: "salesforce", AuthMode: "first_party_client_credentials", RequiredScopes: []string{"api"}, HealthMode: "token_and_organization_probe", DegradationMode: "provider_only", AuthorizationReady: true},
	}
}

func DefaultCredentialClasses() []CredentialClass {
	prohibited := []string{"browser_storage", "database_plaintext", "logs", "queues", "traces", "urls"}
	makeClass := func(key, creator, reader, resolver, rotator, revoker, storage, ttl, audit, deletion string) CredentialClass {
		return CredentialClass{Key: key, Creator: creator, MetadataReader: reader, Resolver: resolver, Rotator: rotator, Revoker: revoker, Storage: storage, TTL: ttl, Audit: audit, Deletion: deletion, ProhibitedSinks: append([]string(nil), prohibited...)}
	}
	return []CredentialClass{
		makeClass("oauth_attempt", "api", "api", "oauth_callback", "single_use", "api", "postgres_hash_and_kms_reference", "10m", "attempt_ids_only", "erase_verifier_on_consume"),
		makeClass("aws_external_id", "api", "api", "discovery_worker", "two_phase", "api", "secrets_manager_connector_kms", "versioned", "reference_only", "recovery_window"),
		makeClass("kubernetes_cluster_reference", "customer_edge_exchange", "api", "discovery_worker", "overlap", "api", "secrets_manager_connector_kms", "finite", "reference_only", "retention_policy"),
		makeClass("github_installation_reference", "oauth_callback", "api", "discovery_worker", "mint_per_attempt", "api", "postgres_reference", "provider", "installation_metadata", "retention_policy"),
		makeClass("okta_refresh_reference", "oauth_callback", "api", "api_and_discovery_worker", "provider_rotation", "api", "secrets_manager_connector_kms", "provider", "reference_only", "revoke_then_retain"),
		makeClass("nango_connection_reference", "nango", "api", "nango_proxy", "nango", "api", "nango_encrypted_postgres", "provider", "reference_only", "confirm_remote_delete"),
		// The customer's OAuth client secret. An operator stores it outside
		// the browser, like the AWS external id; the customer rotates it in
		// the provider and the operator replaces the stored value.
		makeClass("microsoft_client_secret", "operator", "api", "api_and_discovery_worker", "customer_rotation", "api", "secrets_manager_connector_kms", "versioned", "reference_only", "recovery_window"),
		makeClass("salesforce_client_secret", "operator", "api", "api_and_discovery_worker", "customer_rotation", "api", "secrets_manager_connector_kms", "versioned", "reference_only", "recovery_window"),
	}
}

func CanonicalEntityID(scope domain.Scope, kind, sourceNativeID string) (string, error) {
	if scope.Validate() != nil || !tokenPattern.MatchString(kind) || len(sourceNativeID) < 1 || len(sourceNativeID) > 1024 || strings.TrimSpace(sourceNativeID) != sourceNativeID {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), kind, sourceNativeID}, "\x1f")))
	hexValue := hex.EncodeToString(digest[:])
	return "pid_" + hexValue[:8] + "-" + hexValue[8:12] + "-4" + hexValue[13:16] + "-8" + hexValue[17:20] + "-" + hexValue[20:32], nil
}

func validManifest(value Manifest) bool {
	if !tokenPattern.MatchString(value.Key) || value.Nango || !value.AuthorizationReady || value.CollectionReady || len(value.RequiredScopes) < 1 || len(value.RequiredScopes) > 32 || value.HealthMode == "" || value.DegradationMode != "provider_only" || len(value.AuthMode) < 1 || len(value.AuthMode) > 64 {
		return false
	}
	return sort.StringsAreSorted(value.RequiredScopes) && uniqueStrings(value.RequiredScopes)
}

func validCredentialClass(value CredentialClass) bool {
	return tokenPattern.MatchString(value.Key) && value.Creator != "" && value.MetadataReader != "" && value.Resolver != "" && value.Rotator != "" && value.Revoker != "" && value.Storage != "" && value.TTL != "" && value.Audit != "" && value.Deletion != "" && len(value.ProhibitedSinks) >= 5 && uniqueStrings(value.ProhibitedSinks)
}

func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
