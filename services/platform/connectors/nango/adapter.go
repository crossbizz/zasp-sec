package nango

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("Nango connector input rejected")
var ErrProxy = errors.New("Nango connector proxy rejected")

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
var environmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
var referencePattern = regexp.MustCompile(`^ref:nango/[a-z0-9][a-z0-9_./:-]{7,507}$`)

var coreKeys = map[string]struct{}{"aws": {}, "github": {}, "kubernetes": {}, "okta": {}}

type Rule struct{ Method, PathPrefix string }
type Entry struct {
	Key, ProviderHost, AuthMode string
	Rules                       []Rule
}
type Config struct {
	BaseURL, ServiceSecretReference, Environment string
	Entries                                      []Entry
}
type ProxyRequest struct {
	NangoBaseURL, ServiceSecretReference, Environment string
	ConnectorKey, ConnectionReference, ProviderHost   string
	Method, Path                                      string
	ResolvedIPs                                       []net.IP
	Body                                              []byte
}
type ProxyResponse struct {
	StatusCode int
	Body       []byte
	Location   string
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
		entry.Rules = append([]Rule(nil), entry.Rules...)
		entries[entry.Key] = entry
	}
	config.Entries = nil
	return &Adapter{config: config, entries: entries, resolver: resolver, client: client, timeout: timeout}, nil
}

func (adapter *Adapter) Proxy(ctx context.Context, connectorKey, connectionReference, method, path string, body []byte) (ProxyResponse, error) {
	if adapter == nil || adapter.client == nil || adapter.resolver == nil || ctx == nil || ctx.Err() != nil || !referencePattern.MatchString(connectionReference) || len(body) > 64<<10 || containsSecret(body) {
		return ProxyResponse{}, ErrInvalid
	}
	entry, exists := adapter.entries[connectorKey]
	if !exists || !validProxyPath(path) || !allowed(entry.Rules, method, path) {
		return ProxyResponse{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	addresses, err := adapter.resolver.LookupIP(bounded, entry.ProviderHost)
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
		ConnectorKey: connectorKey, ConnectionReference: connectionReference, ProviderHost: entry.ProviderHost, Method: method, Path: path,
		ResolvedIPs: resolved, Body: append([]byte(nil), body...),
	})
	if err != nil || bounded.Err() != nil || response.StatusCode < 200 || response.StatusCode > 299 || response.Location != "" || len(response.Body) > 1<<20 || containsSecret(response.Body) {
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
	if !keyPattern.MatchString(entry.Key) || len(entry.ProviderHost) < 4 || len(entry.ProviderHost) > 253 || net.ParseIP(entry.ProviderHost) != nil || strings.ToLower(entry.ProviderHost) != entry.ProviderHost || strings.HasSuffix(entry.ProviderHost, ".local") || strings.HasSuffix(entry.ProviderHost, ".internal") || entry.AuthMode != "oauth" && entry.AuthMode != "api_key" || len(entry.Rules) < 1 || len(entry.Rules) > 32 {
		return false
	}
	if _, forbidden := coreKeys[entry.Key]; forbidden {
		return false
	}
	for _, rule := range entry.Rules {
		if rule.Method != "GET" && rule.Method != "POST" || !validProxyPath(rule.PathPrefix) {
			return false
		}
	}
	return true
}

func validProxyPath(value string) bool {
	return len(value) >= 2 && len(value) <= 2048 && value[0] == '/' && !strings.Contains(value, "//") && !strings.Contains(value, "..") && !strings.ContainsAny(value, "?#\\\r\n")
}

func allowed(rules []Rule, method, path string) bool {
	for _, rule := range rules {
		if method == rule.Method && strings.HasPrefix(path, rule.PathPrefix) {
			return true
		}
	}
	return false
}

func publicIP(value net.IP) bool {
	return value != nil && !value.IsUnspecified() && !value.IsLoopback() && !value.IsPrivate() && !value.IsLinkLocalUnicast() && !value.IsLinkLocalMulticast() && !value.IsMulticast()
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
