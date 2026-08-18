package integration

import (
	"context"
	"errors"
	"net"
	"net/url"
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
	return []ConnectorManifest{{
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
	if !exists || key != "generic-webhook" || len(configuration) != len(manifest.SetupSchema) {
		return ErrInvalid
	}
	for _, field := range manifest.SetupSchema {
		value, exists := configuration[field.Key]
		if !exists || !validText(value, 2048) {
			return ErrInvalid
		}
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
	for _, field := range value.SetupSchema {
		if !validSlug(field.Key) || !validText(field.Label, 128) || !validSlug(field.Type) || !field.Required || !validText(field.Description, 512) {
			return false
		}
	}
	return true
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
