package nango

import (
	"bytes"
	"context"
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

// coreKeys are the first-party connectors. Nango serves long-tail providers
// only, so an entry for one of these is refused.
// "saas" is the generic discovery provider whose platforms are Nango entries;
// it is a provider name, never an entry key.
var coreKeys = map[string]struct{}{"aws": {}, "github": {}, "kubernetes": {}, "okta": {}, "microsoft": {}, "salesforce": {}, "saas": {}}

type Rule struct {
	Method, PathPrefix string
	QueryKeys          []string
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
	if adapter == nil || adapter.client == nil || adapter.resolver == nil || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString(connectionReference) || len(body) > 64<<10 || containsSecret(body) {
		return ProxyResponse{}, ErrInvalid
	}
	entry, exists := adapter.entries[connectorKey]
	rule, allowed := matchingRule(entry.Rules, method, path)
	if !exists || !validProxyPath(path) || !allowed || !validProxyQuery(query, rule.QueryKeys) {
		return ProxyResponse{}, ErrInvalid
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
		RawQuery: query.Encode(), ResolvedIPs: resolved, Body: append([]byte(nil), body...),
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
	if entry.PerTenantHost() {
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
	} else if len(entry.HostSuffixes) != 0 {
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
	}
	return result
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
