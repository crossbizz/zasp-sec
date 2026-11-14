package integration

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	ErrConfiguration = errors.New("integration configuration rejected")
	ErrInvalid       = errors.New("integration record rejected")
	ErrForbidden     = errors.New("integration authorization rejected")
	ErrNotFound      = errors.New("integration record not found")
	ErrConflict      = errors.New("integration conflict")
	ErrTransition    = errors.New("integration transition rejected")
)

type SetupField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type ConnectorManifest struct {
	Key            string
	Provider       string
	Category       string
	Description    string
	DataTypes      []string
	Actions        []string
	AuthMode       string
	SetupSchema    []SetupField
	AccessGuidance string
	TestSemantics  string
	adapterKey     string
	ossName        string
}

type PublicManifest struct {
	Key            string       `json:"key"`
	Provider       string       `json:"provider"`
	Category       string       `json:"category"`
	Description    string       `json:"description"`
	DataTypes      []string     `json:"data_types"`
	Actions        []string     `json:"actions"`
	AuthMode       string       `json:"auth_mode"`
	SetupSchema    []SetupField `json:"setup_schema"`
	AccessGuidance string       `json:"access_guidance"`
	TestSemantics  string       `json:"test_semantics"`
}

type CatalogFilter struct {
	Query, Category, DataType, Action, AuthMode string
}

type Catalog struct {
	values map[string]ConnectorManifest
}

func BuiltinManifests() []ConnectorManifest {
	return []ConnectorManifest{
		{
			Key: "aws", Provider: "Amazon Web Services", Category: "cloud",
			Description: "Inventory AWS accounts, identities, policies, and selected resources through a customer-owned read role.",
			DataTypes:   []string{"identity", "policy", "resource"}, Actions: []string{"inventory_read", "posture_read"}, AuthMode: "aws_assume_role",
			SetupSchema: []SetupField{
				{Key: "role_arn", Label: "Read role ARN", Type: "string", Required: true, Description: "Customer role trusted for the product's external-ID-bound session."},
				{Key: "external_id_reference", Label: "External ID", Type: "secret_reference", Required: true, Description: "Opaque product reference for the customer trust condition."},
				{Key: "region", Label: "Home region", Type: "string", Required: true, Description: "AWS region used for the identity check and regional inventory."},
			}, AccessGuidance: "Grant the documented read-only policy to one external-ID-bound role.", TestSemantics: "Assume the role, verify the returned account identity, and prove an unauthorized action is denied.", adapterKey: "aws_inventory_v1", ossName: "cartography-prowler",
		},
		{
			Key: "github", Provider: "GitHub", Category: "developer", Description: "Inventory organizations, repositories, applications, workflows, and permissions through a first-party GitHub App installation.", DataTypes: []string{"identity", "repository", "workflow"}, Actions: []string{"inventory_read"}, AuthMode: "github_app_oauth", SetupSchema: []SetupField{{Key: "authorization_mode", Label: "Authorization mode", Type: "string", Required: true, Description: "Fixed first-party GitHub App authorization mode."}}, AccessGuidance: "Authorize only the organizations and repositories intended for inventory.", TestSemantics: "Verify the GitHub App installation and its bounded permission set.", adapterKey: "github_first_party_v1", ossName: "github-app",
		},
		{
			Key: "kubernetes", Provider: "Kubernetes", Category: "runtime", Description: "Inventory one cluster through an explicitly bound cluster credential reference.", DataTypes: []string{"identity", "resource", "workload"}, Actions: []string{"inventory_read"}, AuthMode: "credential_reference", SetupSchema: []SetupField{{Key: "connection_reference", Label: "Cluster credential reference", Type: "connection_reference", Required: true, Description: "Opaque cluster-scoped reference created outside the browser."}}, AccessGuidance: "Grant get, list, and watch only for documented inventory resources.", TestSemantics: "Use the explicit endpoint and CA to verify server version and self-subject rules.", adapterKey: "kubernetes_first_party_v1", ossName: "kubernetes-client",
		},
		{
			Key: "okta", Provider: "Okta", Category: "identity", Description: "Inventory users, groups, applications, and service principals through first-party OAuth with PKCE.", DataTypes: []string{"application", "group", "identity"}, Actions: []string{"inventory_read"}, AuthMode: "okta_oauth_pkce", SetupSchema: []SetupField{{Key: "issuer", Label: "Okta issuer", Type: "uri", Required: true, Description: "Exact customer tenant issuer at https://tenant.okta.com."}}, AccessGuidance: "Grant the fixed read-only directory scopes and restrict the integration account.", TestSemantics: "Verify issuer, subject, scopes, and one bounded directory page.", adapterKey: "okta_first_party_v1", ossName: "okta-api",
		},
		{
			Key: "slack", Provider: "Slack", Category: "collaboration", Description: "Connect one approved Slack workspace through managed authorization and a bounded private proxy.", DataTypes: []string{"workspace"}, Actions: []string{"managed_authorization", "proxy_read"}, AuthMode: "managed_oauth",
			SetupSchema:    []SetupField{{Key: "workspace_label", Label: "Workspace label", Type: "string", Required: true, Description: "A non-secret label used to identify the approved workspace in the product."}},
			AccessGuidance: "Authorize only the intended workspace and keep the managed connection scopes read-only.", TestSemantics: "Verify the tenant-bound workspace reference and one allowlisted read-only proxy request.", adapterKey: "private_auth_proxy_v1", ossName: "private-auth-proxy",
		},
		{
			Key: "microsoft", Provider: "Microsoft Entra and Copilot Studio", Category: "saas",
			Description: "Inventory Entra agent identities, AI enterprise applications, and Copilot Studio agents of one tenant through a customer-owned app registration.",
			DataTypes:   []string{"agent", "application", "identity"}, Actions: []string{"inventory_read"}, AuthMode: "oauth_client_credentials",
			SetupSchema: []SetupField{
				{Key: "tenant_id", Label: "Directory (tenant) ID", Type: "string", Required: true, Description: "The Entra tenant GUID, in lower case."},
				{Key: "client_id", Label: "Application (client) ID", Type: "string", Required: true, Description: "The GUID of the app registration created for discovery, in lower case."},
				{Key: "client_secret_reference", Label: "Client secret", Type: "secret_reference", Required: true, Description: "Opaque product reference to the app registration's client secret, ref:microsoft/client-secret/<id>. The secret value is stored outside the browser."},
				{Key: "dataverse_url", Label: "Dataverse environment URL", Type: "uri", Required: false, Description: "Optional. The environment that holds the Copilot Studio agents, https://<name>.crm<n>.dynamics.com. Leave empty to skip Copilot Studio."},
			},
			AccessGuidance: "Register an Entra app with the application permissions Application.Read.All and, for Entra Agent ID, AgentIdentity.Read.All, and grant admin consent. For Copilot Studio add it as an application user in the Dataverse environment with read access to bot.",
			TestSemantics:  "Request an application token from the tenant's token endpoint for Microsoft Graph, and for the Dataverse environment when one is configured.",
			adapterKey:     "microsoft_first_party_v1", ossName: "microsoft-graph-dataverse",
		},
		{
			Key: "salesforce", Provider: "Salesforce Agentforce", Category: "saas",
			Description: "Inventory the Agentforce agents of one Salesforce org through a customer-owned connected app.",
			DataTypes:   []string{"agent"}, Actions: []string{"inventory_read"}, AuthMode: "oauth_client_credentials",
			SetupSchema: []SetupField{
				{Key: "instance_url", Label: "My Domain URL", Type: "uri", Required: true, Description: "The org's My Domain, https://<name>.my.salesforce.com."},
				{Key: "organization_id", Label: "Organization ID", Type: "string", Required: true, Description: "The 18-character organization ID that starts with 00D."},
				{Key: "client_id", Label: "Consumer key", Type: "string", Required: true, Description: "The consumer key of the connected app or external client app."},
				{Key: "client_secret_reference", Label: "Consumer secret", Type: "secret_reference", Required: true, Description: "Opaque product reference to the consumer secret, ref:salesforce/client-secret/<id>. The secret value is stored outside the browser."},
			},
			AccessGuidance: "Create a connected app or external client app with the client credentials flow enabled and the OAuth scope api, and set a run-as user that has API Enabled and View Setup and Configuration.",
			TestSemantics:  "Request a token from the My Domain token endpoint and require the response to name the configured instance and org.",
			adapterKey:     "salesforce_first_party_v1", ossName: "salesforce-rest",
		},
		{
			Key: "generic-webhook", Provider: "Generic Webhook", Category: "notification",
			Description: "Send signed response and approval notifications to one configured HTTPS destination.",
			DataTypes:   []string{"response", "approval"}, Actions: []string{"response_notification", "approval_response"},
			AuthMode: "signed_webhook",
			SetupSchema: []SetupField{
				{Key: "destination_url", Label: "HTTPS destination", Type: "uri", Required: true, Description: "One allowlisted HTTPS endpoint for all actions."},
				{Key: "signing_secret_reference", Label: "Signing secret", Type: "secret_reference", Required: true, Description: "Product secret reference used to sign each delivery."},
			},
			AccessGuidance: "Allow outbound HTTPS from the product worker and verify every signature before processing a notification.",
			TestSemantics:  "Send one signed synthetic notification and require a successful bounded response.",
			adapterKey:     "generic_webhook_v1", ossName: "internal-http-delivery",
		}}
}

func NewCatalog(values []ConnectorManifest) (*Catalog, error) {
	if len(values) == 0 || len(values) > 256 {
		return nil, ErrConfiguration
	}
	catalog := &Catalog{values: make(map[string]ConnectorManifest, len(values))}
	for _, value := range values {
		if !validManifest(value) {
			return nil, ErrConfiguration
		}
		if _, exists := catalog.values[value.Key]; exists {
			return nil, ErrConfiguration
		}
		catalog.values[value.Key] = cloneManifest(value)
	}
	return catalog, nil
}

func (catalog *Catalog) Search(filter CatalogFilter) ([]PublicManifest, error) {
	return catalog.SearchContext(context.Background(), filter)
}

func (catalog *Catalog) SearchContext(ctx context.Context, filter CatalogFilter) ([]PublicManifest, error) {
	if catalog == nil || catalog.values == nil || !validFilter(filter) {
		return nil, ErrInvalid
	}
	if !validContext(ctx) {
		return nil, ErrInvalid
	}
	result := make([]PublicManifest, 0, len(catalog.values))
	for _, value := range catalog.values {
		if filter.Category != "" && value.Category != filter.Category || filter.AuthMode != "" && value.AuthMode != filter.AuthMode ||
			filter.DataType != "" && !containsExact(value.DataTypes, filter.DataType) || filter.Action != "" && !containsExact(value.Actions, filter.Action) {
			continue
		}
		if filter.Query != "" && !containsFold(value.Key+" "+value.Provider+" "+value.Description, filter.Query) {
			continue
		}
		result = append(result, publicManifest(value))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func (catalog *Catalog) ValidateSetup(key string, configuration map[string]string) error {
	if catalog == nil || catalog.values == nil {
		return ErrConfiguration
	}
	manifest, exists := catalog.values[key]
	if !exists {
		return ErrInvalid
	}
	// Every required field is present, an optional field may be absent, and
	// nothing else is accepted. A present value is never empty.
	present := 0
	for _, field := range manifest.SetupSchema {
		value, exists := configuration[field.Key]
		if !exists && !field.Required {
			continue
		}
		if !exists || !validText(value, 2048) {
			return ErrInvalid
		}
		present++
	}
	if present != len(configuration) {
		return ErrInvalid
	}
	switch key {
	case "aws":
		return validateAWSSetup(configuration)
	case "github":
		if configuration["authorization_mode"] != "github_app" {
			return ErrInvalid
		}
		return nil
	case "kubernetes":
		if !validOpaqueReference(configuration["connection_reference"], 512) {
			return ErrInvalid
		}
		return nil
	case "okta":
		issuer, err := url.Parse(configuration["issuer"])
		if err != nil || issuer.Scheme != "https" || issuer.User != nil || issuer.Port() != "" || issuer.Path != "" || issuer.RawQuery != "" || issuer.Fragment != "" || !oktaIssuerHostPattern.MatchString(issuer.Hostname()) {
			return ErrInvalid
		}
		return nil
	case "microsoft":
		dataverseURL, hasDataverse := configuration["dataverse_url"]
		if !microsoftGUIDPattern.MatchString(configuration["tenant_id"]) || !microsoftGUIDPattern.MatchString(configuration["client_id"]) || !microsoftSecretReferencePattern.MatchString(configuration["client_secret_reference"]) || hasDataverse && !microsoftDataverseURLPattern.MatchString(dataverseURL) {
			return ErrInvalid
		}
		return nil
	case "salesforce":
		if !salesforceInstanceURLPattern.MatchString(configuration["instance_url"]) || !salesforceOrganizationPattern.MatchString(configuration["organization_id"]) || !salesforceClientIDPattern.MatchString(configuration["client_id"]) || !salesforceSecretReferencePattern.MatchString(configuration["client_secret_reference"]) {
			return ErrInvalid
		}
		return nil
	case "slack":
		if !validText(configuration["workspace_label"], 128) {
			return ErrInvalid
		}
		return nil
	case "generic-webhook":
	default:
		return ErrInvalid
	}
	parsed, err := url.Parse(configuration["destination_url"])
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" && strings.Contains(parsed.RawPath, "..") {
		return ErrInvalid
	}
	hostname := strings.ToLower(parsed.Hostname())
	if net.ParseIP(hostname) != nil || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") {
		return ErrInvalid
	}
	if !strings.HasPrefix(configuration["signing_secret_reference"], "secret_ref_") || len(configuration["signing_secret_reference"]) > 128 {
		return ErrInvalid
	}
	return nil
}

var awsRolePattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$`)
var oktaIssuerHostPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.okta\.com$`)

// The Microsoft and Salesforce setup grammars. The whole URL is matched, so a
// plain-HTTP URL, a port, a path, user information or another host is refused.
var (
	microsoftGUIDPattern             = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	microsoftSecretReferencePattern  = regexp.MustCompile(`^ref:microsoft/client-secret/[a-z0-9][a-z0-9._-]{7,127}$`)
	microsoftDataverseURLPattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$`)
	salesforceInstanceURLPattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62}){0,3}\.my\.salesforce\.com$`)
	salesforceOrganizationPattern    = regexp.MustCompile(`^00D[A-Za-z0-9]{15}$`)
	salesforceClientIDPattern        = regexp.MustCompile(`^[!-~]{16,256}$`)
	salesforceSecretReferencePattern = regexp.MustCompile(`^ref:salesforce/client-secret/[a-z0-9][a-z0-9._-]{7,127}$`)
)

func validateAWSSetup(configuration map[string]string) error {
	if !awsRolePattern.MatchString(configuration["role_arn"]) || !validOpaqueReference(configuration["external_id_reference"], 512) || !awsRegionPattern.MatchString(configuration["region"]) {
		return ErrInvalid
	}
	return nil
}

func validOpaqueReference(value string, maximum int) bool {
	if len(value) < 12 || len(value) > maximum || !strings.HasPrefix(value, "ref:") {
		return false
	}
	for _, character := range value[4:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("_./:-", character) {
			continue
		}
		return false
	}
	return true
}

func publicManifest(value ConnectorManifest) PublicManifest {
	return PublicManifest{Key: value.Key, Provider: value.Provider, Category: value.Category, Description: value.Description,
		DataTypes: append([]string(nil), value.DataTypes...), Actions: append([]string(nil), value.Actions...), AuthMode: value.AuthMode,
		SetupSchema: append([]SetupField(nil), value.SetupSchema...), AccessGuidance: value.AccessGuidance, TestSemantics: value.TestSemantics}
}

func cloneManifest(value ConnectorManifest) ConnectorManifest {
	value.DataTypes = append([]string(nil), value.DataTypes...)
	value.Actions = append([]string(nil), value.Actions...)
	value.SetupSchema = append([]SetupField(nil), value.SetupSchema...)
	return value
}

func validManifest(value ConnectorManifest) bool {
	if !validSlug(value.Key) || !validSlug(value.Category) || !validSlug(value.AuthMode) || !validSlug(value.adapterKey) ||
		!validText(value.Provider, 128) || !validText(value.Description, 512) || !validText(value.AccessGuidance, 512) || !validText(value.TestSemantics, 512) ||
		!validText(value.ossName, 128) || len(value.DataTypes) == 0 || len(value.Actions) == 0 || len(value.SetupSchema) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, values := range [][]string{value.DataTypes, value.Actions} {
		for _, item := range values {
			if !validSlug(item) {
				return false
			}
			if _, exists := seen[item]; exists {
				return false
			}
			seen[item] = struct{}{}
		}
	}
	seenFields, required := map[string]struct{}{}, false
	for _, field := range value.SetupSchema {
		if !validSlug(field.Key) || !validText(field.Label, 128) || !validSlug(field.Type) || !validText(field.Description, 512) {
			return false
		}
		if _, exists := seenFields[field.Key]; exists {
			return false
		}
		seenFields[field.Key] = struct{}{}
		required = required || field.Required
	}
	// At least one field is required: a connector with nothing to configure
	// has no setup.
	return required
}

func validFilter(value CatalogFilter) bool {
	for _, item := range []string{value.Query, value.Category, value.DataType, value.Action, value.AuthMode} {
		if len(item) > 128 || strings.TrimSpace(item) != item {
			return false
		}
	}
	return true
}

func validSlug(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsFold(value, wanted string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(wanted))
}
