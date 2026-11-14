package nango

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrInvalid = errors.New("Nango connector input rejected")
var ErrProxy = errors.New("Nango connector proxy rejected")

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
var environmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
var referencePattern = regexp.MustCompile(`^ref:nango/[a-z0-9][a-z0-9_./:-]{7,507}$`)
var queryKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\[\]-]{0,63}$`)

// A per-tenant host is a lowercase DNS name of at least two labels.
var tenantHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
var hostSuffixPattern = regexp.MustCompile(`^(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){2,6}$`)

// A customer's own host: DNS labels and an alphabetic top-level domain, so
// that no numeric form of an address and no single-label name is one.
var customerHostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$`)

// coreKeys are the first-party connectors. Nango serves long-tail providers
// only, so an entry for one of these is refused.
// "saas" is the generic discovery provider whose platforms are Nango entries;
// it is a provider name, never an entry key.
var coreKeys = map[string]struct{}{"aws": {}, "github": {}, "kubernetes": {}, "okta": {}, "microsoft": {}, "salesforce": {}, "saas": {}}

type Rule struct {
	Method, PathPrefix string
	QueryKeys          []string
	// HeaderKeys are the provider request headers a request of the rule may
	// carry beside the ones the proxy sets itself (OpenAI-Beta). A header
	// the rule does not list is refused.
	HeaderKeys []string
	// GraphQLDocuments, on a POST rule, are the exact GraphQL documents a
	// request of the rule may send. The body of a request must then be
	// {"query": <one of them>, "variables": {...}} and nothing else, so the
	// rule admits those queries and no other operation of the endpoint.
	GraphQLDocuments []string
}

// Request is one proxied provider request. Host is set for an entry with a
// per-tenant host and only for one.
type Request struct {
	ConnectorKey, ConnectionReference, Host string
	Method, Path                            string
	Query                                   url.Values
	// Headers are sent to the provider. Their names must be listed by the
	// matching rule.
	Headers map[string]string
	Body    []byte
}
type Entry struct {
	Key, ProviderHost, AuthMode string
	Rules                       []Rule
	// HostPattern and HostSuffixes are set together for a provider whose
	// host differs per tenant (acme.service-now.com). ProviderHost is then
	// empty and every request names its host (ProxyToHost). A host is
	// accepted only when the whole of it matches HostPattern and it ends
	// with one of HostSuffixes; the suffixes are the provider's own domains
	// (".service-now.com"), so a loose pattern cannot admit another domain.
	HostPattern  *regexp.Regexp
	HostSuffixes []string
	// CustomerHosted is set, explicitly, for a provider a customer runs on a
	// host of their own (a self-managed GitLab). The host is then not under
	// a domain of the provider, so the entry has a HostPattern and no
	// HostSuffixes, and a request names the host the integration was set up
	// with. Such a host is accepted only as a public DNS name: at least two
	// labels ending in an alphabetic top-level domain, never an address, a
	// cluster, local or internal name; and, as for every host, a request is
	// sent only when every address the name resolves to is public.
	CustomerHosted bool
}

// PerTenantHost reports whether the entry's requests name their own host.
func (entry Entry) PerTenantHost() bool { return entry.HostPattern != nil }

// AllowsHost reports whether host is a host the entry may be proxied to.
func (entry Entry) AllowsHost(host string) bool {
	if entry.HostPattern == nil || !validProviderHost(host) || !tenantHostPattern.MatchString(host) || strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".cluster.local") || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if match := entry.HostPattern.FindString(host); match != host {
		return false
	}
	if entry.CustomerHosted {
		return customerHostPattern.MatchString(host) && len(host) <= 200 && !strings.HasSuffix(host, ".svc") && !strings.Contains(host, ".svc.") && !strings.HasSuffix(host, ".lan") && !strings.HasSuffix(host, ".home") && !strings.HasSuffix(host, ".corp") && !strings.HasSuffix(host, ".test") && !strings.HasSuffix(host, ".example") && !strings.HasSuffix(host, ".invalid")
	}
	for _, suffix := range entry.HostSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

type Config struct {
	BaseURL, ServiceSecretReference, Environment string
	Entries                                      []Entry
}
type ProxyRequest struct {
	NangoBaseURL, ServiceSecretReference, Environment string
	ConnectorKey, ConnectionReference, ProviderHost   string
	Method, Path, RawQuery                            string
	// Headers are provider request headers. The proxy client sends each as
	// Nango-Proxy-<name>, which Nango forwards to the provider as <name>.
	Headers map[string]string
	// PinHost makes the proxy client tell Nango to send the request to
	// ProviderHost, whatever host the Nango connection was created with.
	PinHost     bool
	ResolvedIPs []net.IP
	Body        []byte
}
type ProxyResponse struct {
	StatusCode int
	Body       []byte
	Location   string
	// Link is the provider's Link response header (RFC 8288), which some
	// providers page with. It is empty when the provider sent none.
	Link string
}

// StatusError is a provider response outside 200 to 299 that the proxy
// relayed. It carries the status and the Retry-After header and nothing of
// the body, so a caller can tell a rate limit from a denial. It is an
// ErrProxy.
type StatusError struct {
	StatusCode int
	RetryAfter string
}

func (*StatusError) Error() string { return ErrProxy.Error() }
func (*StatusError) Unwrap() error { return ErrProxy }

// proxyStatusError keeps a relayed status only when it is a plausible HTTP
// error status with a bounded, printable Retry-After.
func proxyStatusError(status int, retryAfter string) error {
	if status < 300 || status > 599 {
		return ErrProxy
	}
	if len(retryAfter) > 64 {
		retryAfter = ""
	}
	for _, character := range retryAfter {
		if character < 0x20 || character > 0x7e {
			retryAfter = ""
			break
		}
	}
	return &StatusError{StatusCode: status, RetryAfter: retryAfter}
}

type DNSResolver interface {
	LookupIP(context.Context, string) ([]net.IP, error)
}
type ProxyClient interface {
	Proxy(context.Context, ProxyRequest) (ProxyResponse, error)
}
type Adapter struct {
	config   Config
	entries  map[string]Entry
	resolver DNSResolver
	client   ProxyClient
	timeout  time.Duration
}

func NewAdapter(config Config, resolver DNSResolver, client ProxyClient, timeout time.Duration) (*Adapter, error) {
	if resolver == nil || client == nil || timeout < 100*time.Millisecond || timeout > 10*time.Second || !validBaseURL(config.BaseURL) || !referencePattern.MatchString(config.ServiceSecretReference) || !environmentPattern.MatchString(config.Environment) || len(config.Entries) < 1 || len(config.Entries) > 64 {
		return nil, ErrInvalid
	}
	entries := make(map[string]Entry, len(config.Entries))
	for _, entry := range config.Entries {
		if !validEntry(entry) {
			return nil, ErrInvalid
		}
		if _, exists := entries[entry.Key]; exists {
			return nil, ErrInvalid
		}
		entry.Rules = cloneRules(entry.Rules)
		entry.HostSuffixes = append([]string(nil), entry.HostSuffixes...)
		entries[entry.Key] = entry
	}
	config.Entries = nil
	return &Adapter{config: config, entries: entries, resolver: resolver, client: client, timeout: timeout}, nil
}

func (adapter *Adapter) Proxy(ctx context.Context, connectorKey, connectionReference, method, path string, body []byte) (ProxyResponse, error) {
	return adapter.ProxyWithQuery(ctx, connectorKey, connectionReference, method, path, nil, body)
}

func (adapter *Adapter) ProxyWithQuery(ctx context.Context, connectorKey, connectionReference, method, path string, query url.Values, body []byte) (ProxyResponse, error) {
	return adapter.proxy(ctx, connectorKey, connectionReference, "", method, path, query, body)
}

// ProxyToHost proxies a request of a per-tenant entry to host. The host must
// be one the entry allows (its pattern and its suffixes) and must resolve to
// public addresses only. Nango is told to send the request to exactly that
// host, so the host a connection was created with cannot redirect it. An
// entry with a fixed host is refused here, and a per-tenant entry is refused
// by Proxy and ProxyWithQuery: a request never falls back to another host.
func (adapter *Adapter) ProxyToHost(ctx context.Context, connectorKey, connectionReference, host, method, path string, query url.Values, body []byte) (ProxyResponse, error) {
	if host == "" {
		return ProxyResponse{}, ErrInvalid
	}
	return adapter.proxy(ctx, connectorKey, connectionReference, host, method, path, query, body)
}

func (adapter *Adapter) proxy(ctx context.Context, connectorKey, connectionReference, tenantHost, method, path string, query url.Values, body []byte) (ProxyResponse, error) {
	return adapter.Do(ctx, Request{ConnectorKey: connectorKey, ConnectionReference: connectionReference, Host: tenantHost, Method: method, Path: path, Query: query, Body: body})
}

// Do proxies one request. It is refused unless a rule of the entry admits
// its method and path, every query parameter and header it carries, and, for
// a rule that lists GraphQL documents, its body.
func (adapter *Adapter) Do(ctx context.Context, request Request) (ProxyResponse, error) {
	connectorKey, connectionReference, tenantHost, method, path, query, body := request.ConnectorKey, request.ConnectionReference, request.Host, request.Method, request.Path, request.Query, request.Body
	if adapter == nil || adapter.client == nil || adapter.resolver == nil || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString(connectionReference) || len(body) > 64<<10 || containsSecret(body) {
		return ProxyResponse{}, ErrInvalid
	}
	entry, exists := adapter.entries[connectorKey]
	rule, allowed := matchingRule(entry.Rules, method, path)
	if !exists || !validProxyPath(path) || !allowed || !validProxyQuery(query, rule.QueryKeys) || !validProxyHeaders(request.Headers, rule.HeaderKeys) || !validRuleBody(rule, body) {
		return ProxyResponse{}, ErrInvalid
	}
	headers := make(map[string]string, len(request.Headers))
	for name, value := range request.Headers {
		headers[name] = value
	}
	host := entry.ProviderHost
	if entry.PerTenantHost() != (tenantHost != "") {
		return ProxyResponse{}, ErrInvalid
	}
	if tenantHost != "" {
		if !entry.AllowsHost(tenantHost) {
			return ProxyResponse{}, ErrInvalid
		}
		host = tenantHost
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	addresses, err := adapter.resolver.LookupIP(bounded, host)
	if err != nil || len(addresses) < 1 || len(addresses) > 8 {
		return ProxyResponse{}, ErrProxy
	}
	resolved := make([]net.IP, len(addresses))
	for index, address := range addresses {
		if !publicIP(address) {
			return ProxyResponse{}, ErrProxy
		}
		resolved[index] = append(net.IP(nil), address...)
	}
	response, err := adapter.client.Proxy(bounded, ProxyRequest{
		NangoBaseURL: adapter.config.BaseURL, ServiceSecretReference: adapter.config.ServiceSecretReference, Environment: adapter.config.Environment,
		ConnectorKey: connectorKey, ConnectionReference: connectionReference, ProviderHost: host, PinHost: tenantHost != "", Method: method, Path: path,
		RawQuery: query.Encode(), Headers: headers, ResolvedIPs: resolved, Body: append([]byte(nil), body...),
	})
	var status *StatusError
	if errors.As(err, &status) && bounded.Err() == nil {
		return ProxyResponse{}, proxyStatusError(status.StatusCode, status.RetryAfter)
	}
	if err != nil || bounded.Err() != nil || response.StatusCode < 200 || response.StatusCode > 299 || response.Location != "" || len(response.Body) > 1<<20 || len(response.Link) > 8192 || containsSecret(response.Body) || containsSecret([]byte(response.Link)) {
		return ProxyResponse{}, ErrProxy
	}
	response.Body = append([]byte(nil), response.Body...)
	return response, nil
}

func validBaseURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.HasSuffix(host, ".svc.cluster.local") && net.ParseIP(host) == nil
}

func validEntry(entry Entry) bool {
	if entry.PerTenantHost() && entry.CustomerHosted {
		// The host is the customer's: no suffix can describe it, and the
		// entry names none.
		if entry.ProviderHost != "" || len(entry.HostSuffixes) != 0 {
			return false
		}
		entry.ProviderHost = "tenant.customer-hosted.com"
	} else if entry.PerTenantHost() {
		// The host comes with each request; the entry names none.
		if entry.ProviderHost != "" || len(entry.HostSuffixes) < 1 || len(entry.HostSuffixes) > 8 {
			return false
		}
		for _, suffix := range entry.HostSuffixes {
			if !hostSuffixPattern.MatchString(suffix) || strings.HasSuffix(suffix, ".local") || strings.HasSuffix(suffix, ".internal") || strings.HasSuffix(suffix, ".localhost") {
				return false
			}
		}
		entry.ProviderHost = "tenant" + entry.HostSuffixes[0]
	} else if len(entry.HostSuffixes) != 0 || entry.CustomerHosted {
		return false
	}
	if !keyPattern.MatchString(entry.Key) || len(entry.ProviderHost) < 4 || len(entry.ProviderHost) > 253 || net.ParseIP(entry.ProviderHost) != nil || strings.ToLower(entry.ProviderHost) != entry.ProviderHost || strings.HasSuffix(entry.ProviderHost, ".local") || strings.HasSuffix(entry.ProviderHost, ".internal") || entry.AuthMode != "oauth" && entry.AuthMode != "api_key" || len(entry.Rules) < 1 || len(entry.Rules) > 32 {
		return false
	}
	if _, forbidden := coreKeys[entry.Key]; forbidden {
		return false
	}
	uniqueRules := make(map[string]struct{}, len(entry.Rules))
	for _, rule := range entry.Rules {
		if rule.Method != "GET" && rule.Method != "POST" || !validProxyPath(rule.PathPrefix) {
			return false
		}
		ruleIdentity := rule.Method + "\x00" + rule.PathPrefix
		if _, duplicate := uniqueRules[ruleIdentity]; duplicate {
			return false
		}
		uniqueRules[ruleIdentity] = struct{}{}
		seen := make(map[string]struct{}, len(rule.QueryKeys))
		for _, key := range rule.QueryKeys {
			if !queryKeyPattern.MatchString(key) {
				return false
			}
			if _, exists := seen[key]; exists {
				return false
			}
			seen[key] = struct{}{}
		}
		if len(rule.HeaderKeys) > 8 || len(rule.GraphQLDocuments) > 8 || len(rule.GraphQLDocuments) > 0 && rule.Method != "POST" {
			return false
		}
		seenHeaders := make(map[string]struct{}, len(rule.HeaderKeys))
		for _, key := range rule.HeaderKeys {
			if _, exists := seenHeaders[strings.ToLower(key)]; exists || !ValidForwardedHeaderName(key) {
				return false
			}
			seenHeaders[strings.ToLower(key)] = struct{}{}
		}
		for _, document := range rule.GraphQLDocuments {
			if !ReadOnlyGraphQLDocument(document) {
				return false
			}
		}
	}
	return true
}

func validProxyPath(value string) bool {
	return len(value) >= 2 && len(value) <= 2048 && value[0] == '/' && !strings.Contains(value, "//") && !strings.Contains(value, "..") && !strings.ContainsAny(value, "?#\\\r\n")
}

func matchingRule(rules []Rule, method, path string) (Rule, bool) {
	var selected Rule
	found := false
	for _, rule := range rules {
		pathMatches := path == rule.PathPrefix || strings.HasSuffix(rule.PathPrefix, "/") && strings.HasPrefix(path, rule.PathPrefix)
		if method == rule.Method && pathMatches && (!found || len(rule.PathPrefix) > len(selected.PathPrefix)) {
			selected, found = rule, true
		}
	}
	return selected, found
}

func validProxyQuery(query url.Values, allowedKeys []string) bool {
	if len(query) > 16 || len(query.Encode()) > 2048 {
		return false
	}
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	for key, values := range query {
		if _, exists := allowed[key]; !exists || len(values) != 1 || !validQueryValue(values[0]) {
			return false
		}
	}
	return true
}

func validQueryValue(value string) bool {
	if len(value) < 1 || len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func cloneRules(values []Rule) []Rule {
	result := make([]Rule, len(values))
	for index, value := range values {
		result[index] = value
		result[index].QueryKeys = append([]string(nil), value.QueryKeys...)
		sort.Strings(result[index].QueryKeys)
		result[index].HeaderKeys = append([]string(nil), value.HeaderKeys...)
		result[index].GraphQLDocuments = append([]string(nil), value.GraphQLDocuments...)
	}
	return result
}

var forwardedHeaderNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,62}$`)

// ValidForwardedHeaderName admits a provider header a rule may forward. The
// headers that carry credentials, choose the destination or belong to the
// proxy itself are never forwarded.
func ValidForwardedHeaderName(name string) bool {
	if !forwardedHeaderNamePattern.MatchString(name) {
		return false
	}
	switch lower := strings.ToLower(name); lower {
	case "authorization", "proxy-authorization", "cookie", "host", "connection", "connection-id", "provider-config-key", "base-url-override", "content-length", "transfer-encoding", "retries", "decompress":
		return false
	default:
		return !strings.HasPrefix(lower, "nango-") && !strings.HasPrefix(lower, "x-forwarded-")
	}
}

func validProxyHeaders(headers map[string]string, allowedKeys []string) bool {
	if len(headers) > 8 {
		return false
	}
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	for name, value := range headers {
		if _, exists := allowed[name]; !exists || !validQueryValue(value) || len(value) > 256 || containsSecret([]byte(value)) {
			return false
		}
	}
	return true
}

var graphQLWritePattern = regexp.MustCompile(`(?i)\b(mutation|subscription)\b`)

// ReadOnlyGraphQLDocument reports whether document is one GraphQL query
// operation: it starts with the keyword query and names neither a mutation
// nor a subscription anywhere, and it is printable text of at most 4 KiB
// without a comment (a comment could hide a second operation from a
// reader).
func ReadOnlyGraphQLDocument(document string) bool {
	if len(document) < 8 || len(document) > 4096 || !strings.HasPrefix(document, "query") || strings.Contains(document, "#") || graphQLWritePattern.MatchString(document) {
		return false
	}
	for _, character := range document {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	// One operation: the braces balance and close once, at the end.
	depth := 0
	for index, character := range document {
		switch character {
		case '{':
			depth++
		case '}':
			if depth--; depth < 0 || depth == 0 && index != len(document)-1 {
				return false
			}
		}
	}
	return depth == 0 && strings.HasSuffix(document, "}")
}

// validRuleBody admits the body of a request of rule. A rule that lists
// GraphQL documents admits only {"query": <listed document>, "variables":
// {...}}; variables hold strings, numbers, booleans and null.
func validRuleBody(rule Rule, body []byte) bool {
	if len(rule.GraphQLDocuments) == 0 {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var document struct {
		Query     *string        `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if decoder.Decode(&document) != nil || decoder.More() || document.Query == nil || len(document.Variables) > 8 {
		return false
	}
	for _, value := range document.Variables {
		switch value.(type) {
		case nil, string, float64, bool:
		default:
			return false
		}
	}
	for _, listed := range rule.GraphQLDocuments {
		if listed == *document.Query {
			return true
		}
	}
	return false
}

// nonPublicNetworks are the address ranges that Go's own tests do not call
// private, loopback, link-local or multicast and that still never belong to
// a provider on the public internet: shared address space (carrier NAT,
// where cloud and cluster services often live), protocol assignments,
// benchmarking, documentation, reserved space, and the IPv6 ranges that
// embed or translate an IPv4 address.
var nonPublicNetworks = func() []*net.IPNet {
	var networks []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "2002::/16", "2001::/32",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}()

func publicIP(value net.IP) bool {
	if value == nil || len(value) != net.IPv4len && len(value) != net.IPv6len || value.IsUnspecified() || value.IsLoopback() || value.IsPrivate() || value.IsLinkLocalUnicast() || value.IsLinkLocalMulticast() || value.IsMulticast() || value.IsInterfaceLocalMulticast() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(value) {
			return false
		}
	}
	return true
}

func containsSecret(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	lower := bytes.ToLower(value)
	for _, marker := range [][]byte{[]byte("access_token"), []byte("refresh_token"), []byte("client_secret"), []byte("private_key"), []byte("password")} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	return false
}
