// Package saasdiscovery collects the AI agents, AI applications and MCP
// servers of a SaaS platform for the discovery collection contract. It is one
// collector for every platform: a platform is a Platform value (data and one
// mapping function per list endpoint), read through the Nango proxy. The
// collector never holds a provider token; its credential is the reference of
// a Nango connection.
//
// docs/operations/saas-connectors.md describes how to add a platform.
package saasdiscovery

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
)

var ErrInvalid = errors.New("SaaS connector input rejected")
var ErrProvider = errors.New("SaaS connector provider rejected")

// The three entity kinds a list endpoint may report. The tenant itself
// (saas_tenant) is reported by the collector from the tenant lookup.
const (
	// KindAgent: the platform's API names the object an agent.
	KindAgent = "saas_agent"
	// KindAIApplication: the product concludes the object is an AI
	// application from signals the platform's API states.
	KindAIApplication = "saas_ai_application"
	// KindMCPServer: an MCP server registered in the platform.
	KindMCPServer = "saas_mcp_server"
)

// PagingStyle is how a list endpoint continues.
type PagingStyle string

const (
	// PagingNone: the endpoint answers everything in one response.
	PagingNone PagingStyle = "none"
	// PagingCursor: the response carries a token for the next page
	// (next_page_token, next_cursor); the request sends it back.
	PagingCursor PagingStyle = "cursor"
	// PagingOffset: the request sends an offset and a limit; a page shorter
	// than the limit is the last.
	PagingOffset PagingStyle = "offset"
	// PagingLink: the response's Link header names the next page (RFC 8288,
	// rel="next").
	PagingLink PagingStyle = "link"
)

// Paging describes the continuation of a list endpoint.
type Paging struct {
	Style PagingStyle
	// CursorParam is the request query parameter that carries the token and
	// NextPath the place of the next token in the response document
	// (PagingCursor).
	CursorParam string
	NextPath    []string
	// OffsetParam and LimitParam are the request query parameters of
	// PagingOffset. LimitParam is optional for PagingCursor and PagingLink.
	OffsetParam string
	LimitParam  string
	// PageSize is the limit the collector asks for, 1 to 1000. It is
	// required when LimitParam is set.
	PageSize int
}

// Item is one decoded JSON object of a provider response. Numbers are
// json.Number. The helpers never panic on a missing or differently typed
// member.
type Item map[string]any

func (item Item) at(path []string) (any, bool) {
	var current any = map[string]any(item)
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = object[key]; !ok {
			return nil, false
		}
	}
	return current, true
}

// Text is the string or number at path, as text. "" when there is none.
func (item Item) Text(path ...string) string {
	value, _ := item.at(path)
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	}
	return ""
}

// Bool is the boolean at path; false when there is none.
func (item Item) Bool(path ...string) bool {
	value, _ := item.at(path)
	typed, _ := value.(bool)
	return typed
}

// Has reports whether path holds a value other than null.
func (item Item) Has(path ...string) bool {
	value, ok := item.at(path)
	return ok && value != nil
}

// Object is the object at path, or nil.
func (item Item) Object(path ...string) Item {
	value, _ := item.at(path)
	typed, _ := value.(map[string]any)
	return Item(typed)
}

// Objects are the objects of the array at path. Members that are not
// objects are skipped.
func (item Item) Objects(path ...string) []Item {
	value, _ := item.at(path)
	list, _ := value.([]any)
	result := make([]Item, 0, len(list))
	for _, member := range list {
		if object, ok := member.(map[string]any); ok {
			result = append(result, Item(object))
		}
	}
	return result
}

// Texts are the strings of the array at path.
func (item Item) Texts(path ...string) []string {
	value, _ := item.at(path)
	list, _ := value.([]any)
	result := make([]string, 0, len(list))
	for _, member := range list {
		if text, ok := member.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

// CleanText makes provider text fit an inventory text field: a tab or line
// break becomes a space, other control characters are dropped, surrounding
// space is trimmed and the result is cut
// to maximum bytes on a character boundary. It returns "" for text that has
// nothing printable.
func CleanText(value string, maximum int) string {
	var builder strings.Builder
	for _, character := range value {
		switch {
		case unicode.IsSpace(character):
			builder.WriteByte(' ')
		case character == utf8.RuneError || unicode.IsControl(character):
		default:
			builder.WriteRune(character)
		}
	}
	cleaned := strings.TrimSpace(builder.String())
	for len(cleaned) > maximum {
		_, size := utf8.DecodeLastRuneInString(cleaned)
		cleaned = strings.TrimSpace(cleaned[:len(cleaned)-size])
	}
	return cleaned
}

// Tenant is what the tenant lookup endpoint states about the tenant the
// connection reaches.
type Tenant struct {
	// ID is the tenant's id in the platform. The collector refuses the
	// collection unless it equals the tenant id of the integration.
	ID string
	// Name is the tenant's display name; ID is used when it is empty.
	Name string
}

// TenantLookup is the one request that says which tenant a connection
// reaches. It runs first in every collection and when the integration is
// authorized.
type TenantLookup struct {
	Path  string
	Query map[string]string
	// Map reads the tenant out of the response document. It returns false
	// when the document does not name a tenant.
	Map func(document Item) (Tenant, bool)
}

// Entity is what a mapping function says about one provider item. The
// collector adds the platform, the tenant, the ids and the relationship to
// the tenant.
type Entity struct {
	// Kind is KindAgent, KindAIApplication or KindMCPServer.
	Kind string
	// NativeID is the item's id in the platform, unique within ObjectType.
	NativeID string
	// DisplayName is shown in the inventory. Use CleanText on provider text.
	DisplayName string
	// ObjectType is the platform's name for the kind of object
	// (serving_endpoint, app), a lowercase token.
	ObjectType string
	// Status is the state the platform reports (READY, enabled). Required.
	Status string
	// AgentType and Model are optional facts of an agent or AI application;
	// EndpointHost is the optional host of an MCP server.
	AgentType    string
	Model        string
	EndpointHost string
	// Posture holds only the facts the platform's API states. A fact the
	// API does not state stays false and raises no finding. It is ignored
	// for an MCP server.
	Posture agentsignals.Posture
	// Signals are agentsignals catalog tokens (evidence.Signals()). An AI
	// application needs at least one: it is listed because of them.
	Signals []string
}

// TenantQueryValue, as the value of a list endpoint's fixed query parameter,
// is replaced by the tenant id of the collection (Slack's team_id).
const TenantQueryValue = "{tenant}"

// ListEndpoint is one list request of a platform and the mapping of its
// items.
type ListEndpoint struct {
	// Name is the endpoint's phase token in the collection cursor.
	Name string
	Path string
	// Query is sent with every request of the endpoint.
	Query map[string]string
	// ItemsPath is where the array of items is in the response document.
	// Empty means the response itself is the array.
	ItemsPath []string
	Paging    Paging
	// Map turns one item into an entity. It returns false for an item that
	// is not an AI agent, AI application or MCP server; the item is then
	// skipped. Map must not copy secrets, prompts or payloads into the
	// entity.
	Map func(item Item) (Entity, bool)
	// Absent lists HTTP statuses that mean the tenant does not have this
	// feature (404 where a product is not enabled). The endpoint then
	// contributes nothing and the collection continues.
	Absent []int
}

// Platform is the whole definition of one SaaS platform.
type Platform struct {
	// Token is the lowercase platform token: the first half of the subject
	// id, the platform stable field and the discovery platform.
	Token string
	// DisplayName and Description are shown in the connector catalog.
	DisplayName string
	Description string
	// Nango is the Nango integration the platform's connections belong to:
	// its key (the Provider-Config-Key), the provider host and the proxy
	// rules. The rules are an allow-list; a request no rule matches is
	// never sent.
	Nango nango.Entry
	// RequiredScopes are the provider scopes or permissions the connection
	// needs, for the catalog and the launch registry.
	RequiredScopes []string
	// TenantLabel and TenantHint describe the tenant id in the setup form.
	TenantLabel string
	TenantHint  string
	// TenantPattern is the grammar of the platform's tenant id. It is
	// matched against the whole id.
	TenantPattern *regexp.Regexp
	// AccessGuidance tells an operator what to grant.
	AccessGuidance string
	// Failure reads a provider error out of a 200 response (Slack answers
	// {"ok":false,"error":"…"}). It returns false when the document is not
	// an error. Optional.
	Failure func(document Item) (collection.FailureCode, bool)
	Tenant  TenantLookup
	Lists   []ListEndpoint
}

var (
	platformTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
	objectTypePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	endpointNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// With the platform token and the separator a subject id is at most
	// 128 bytes, the bound of a public scope label.
	tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,94}$`)
	queryKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\[\]-]{0,63}$`)
	scopePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)
	signalPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$`)
	nangoKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
	hostPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// ValidTenantID reports whether value can be the tenant half of a saas
// subject id.
func ValidTenantID(value string) bool {
	return tenantIDPattern.MatchString(value) && !strings.Contains(value, "..")
}

// ValidPlatformToken reports whether value has the form of a platform token.
func ValidPlatformToken(value string) bool { return platformTokenPattern.MatchString(value) }

func validPath(value string) bool {
	return len(value) >= 2 && len(value) <= 1024 && value[0] == '/' && !strings.Contains(value, "//") && !strings.Contains(value, "..") && !strings.ContainsAny(value, "?#\\\r\n ")
}

func validDisplayText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFixedQuery(query map[string]string) bool {
	if len(query) > 8 {
		return false
	}
	for key, value := range query {
		if !queryKeyPattern.MatchString(key) || !validDisplayText(value, 256) {
			return false
		}
	}
	return true
}

// queryKeys are the query parameters a request of the endpoint can carry.
func (endpoint ListEndpoint) queryKeys() []string {
	keys := make([]string, 0, len(endpoint.Query)+3)
	for key := range endpoint.Query {
		keys = append(keys, key)
	}
	for _, key := range []string{endpoint.Paging.CursorParam, endpoint.Paging.OffsetParam, endpoint.Paging.LimitParam} {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// ruleAllows reports whether one of the entry's proxy rules admits a GET of
// path with every one of keys. A Link-paged endpoint may meet further
// parameters at run time; those are refused by the adapter unless the rule
// lists them.
func ruleAllows(entry nango.Entry, path string, keys []string) bool {
	var selected *nango.Rule
	for index, rule := range entry.Rules {
		matches := path == rule.PathPrefix || strings.HasSuffix(rule.PathPrefix, "/") && strings.HasPrefix(path, rule.PathPrefix)
		if rule.Method == http.MethodGet && matches && (selected == nil || len(rule.PathPrefix) > len(selected.PathPrefix)) {
			selected = &entry.Rules[index]
		}
	}
	if selected == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range selected.QueryKeys {
		allowed[key] = true
	}
	for _, key := range keys {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func (paging Paging) valid() bool {
	if paging.PageSize < 0 || paging.PageSize > 1000 || (paging.LimitParam != "") != (paging.PageSize > 0) {
		return false
	}
	for _, key := range []string{paging.CursorParam, paging.OffsetParam, paging.LimitParam} {
		if key != "" && !queryKeyPattern.MatchString(key) {
			return false
		}
	}
	for _, key := range paging.NextPath {
		if key == "" || len(key) > 64 {
			return false
		}
	}
	switch paging.Style {
	case PagingNone:
		return paging.CursorParam == "" && len(paging.NextPath) == 0 && paging.OffsetParam == "" && paging.LimitParam == ""
	case PagingCursor:
		return paging.CursorParam != "" && len(paging.NextPath) >= 1 && len(paging.NextPath) <= 4 && paging.OffsetParam == "" && paging.CursorParam != paging.LimitParam
	case PagingOffset:
		return paging.OffsetParam != "" && paging.LimitParam != "" && paging.OffsetParam != paging.LimitParam && paging.CursorParam == "" && len(paging.NextPath) == 0
	case PagingLink:
		return paging.CursorParam == "" && len(paging.NextPath) == 0 && paging.OffsetParam == ""
	}
	return false
}

// Validate reports whether the definition is complete and consistent: a
// registry refuses a platform that is not.
func (platform Platform) Validate() error {
	if !platformTokenPattern.MatchString(platform.Token) || !validDisplayText(platform.DisplayName, 64) || !validDisplayText(platform.Description, 512) ||
		!validDisplayText(platform.TenantLabel, 64) || !validDisplayText(platform.TenantHint, 256) || !validDisplayText(platform.AccessGuidance, 512) || platform.TenantPattern == nil ||
		len(platform.RequiredScopes) < 1 || len(platform.RequiredScopes) > 32 || len(platform.Lists) < 1 || len(platform.Lists) > 16 ||
		platform.Tenant.Map == nil || !validPath(platform.Tenant.Path) || !validFixedQuery(platform.Tenant.Query) {
		return ErrInvalid
	}
	// The tenant lookup is what establishes the tenant; it cannot name it.
	for _, value := range platform.Tenant.Query {
		if value == TenantQueryValue {
			return ErrInvalid
		}
	}
	// The entry itself is checked by building a one-entry adapter
	// configuration the way the worker does.
	if !validNangoEntry(platform.Nango) {
		return ErrInvalid
	}
	seenScopes := map[string]bool{}
	for _, scope := range platform.RequiredScopes {
		if !scopePattern.MatchString(scope) || seenScopes[scope] {
			return ErrInvalid
		}
		seenScopes[scope] = true
	}
	tenantKeys := make([]string, 0, len(platform.Tenant.Query))
	for key := range platform.Tenant.Query {
		tenantKeys = append(tenantKeys, key)
	}
	if !ruleAllows(platform.Nango, platform.Tenant.Path, tenantKeys) {
		return ErrInvalid
	}
	// "tenant" and "complete" are the collector's own cursor phases.
	names := map[string]bool{"tenant": true, "complete": true}
	for _, endpoint := range platform.Lists {
		if !endpointNamePattern.MatchString(endpoint.Name) || names[endpoint.Name] || !validPath(endpoint.Path) || !validFixedQuery(endpoint.Query) || len(endpoint.ItemsPath) > 4 || endpoint.Map == nil || !endpoint.Paging.valid() || len(endpoint.Absent) > 4 {
			return ErrInvalid
		}
		names[endpoint.Name] = true
		for _, key := range endpoint.ItemsPath {
			if key == "" || len(key) > 64 {
				return ErrInvalid
			}
		}
		for _, key := range []string{endpoint.Paging.CursorParam, endpoint.Paging.OffsetParam, endpoint.Paging.LimitParam} {
			if _, fixed := endpoint.Query[key]; fixed && key != "" {
				return ErrInvalid
			}
		}
		for _, status := range endpoint.Absent {
			if status != http.StatusNotFound && status != http.StatusNotImplemented && status != http.StatusForbidden {
				return ErrInvalid
			}
		}
		if !ruleAllows(platform.Nango, endpoint.Path, endpoint.queryKeys()) {
			return ErrInvalid
		}
	}
	return nil
}

func validNangoEntry(entry nango.Entry) bool {
	if !nangoKeyPattern.MatchString(entry.Key) || entry.Key == "saas" || !hostPattern.MatchString(entry.ProviderHost) || len(entry.ProviderHost) < 4 || net.ParseIP(entry.ProviderHost) != nil ||
		strings.HasSuffix(entry.ProviderHost, ".local") || strings.HasSuffix(entry.ProviderHost, ".internal") || entry.AuthMode != "oauth" && entry.AuthMode != "api_key" || len(entry.Rules) < 1 || len(entry.Rules) > 32 {
		return false
	}
	for _, rule := range entry.Rules {
		// Discovery reads only.
		if rule.Method != http.MethodGet || !validPath(rule.PathPrefix) {
			return false
		}
	}
	return true
}
