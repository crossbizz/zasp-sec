package nango

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]net.IP, error)

func (function resolverFunc) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return function(ctx, host)
}

func TestNangoProxyAllowsOnlyDeclaredCanonicalQueryParameters(t *testing.T) {
	config := Config{
		BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{{
			Key: "onepassword-events", ProviderHost: "events.1password.com", AuthMode: "api_key",
			Rules: []Rule{{Method: "GET", PathPrefix: "/api/v2/events", QueryKeys: []string{"cursor", "limit"}}},
		}},
	}
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("13.107.42.14")}, nil })
	calls := 0
	client := proxyFunc(func(_ context.Context, request ProxyRequest) (ProxyResponse, error) {
		calls++
		if request.RawQuery != "cursor=next_1&limit=1" {
			t.Fatalf("raw query %q", request.RawQuery)
		}
		return ProxyResponse{StatusCode: 200, Body: []byte(`{"items":[]}`)}, nil
	})
	adapter, err := NewAdapter(config, resolver, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ProxyWithQuery(context.Background(), "onepassword-events", "ref:nango/connection-0001", "GET", "/api/v2/events", url.Values{"limit": {"1"}, "cursor": {"next_1"}}, nil); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]url.Values{
		"unknown":   {"target": {"http://169.254.169.254"}},
		"duplicate": {"limit": {"1", "2"}},
		"control":   {"cursor": {"next\nvalue"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := adapter.ProxyWithQuery(context.Background(), "onepassword-events", "ref:nango/connection-0001", "GET", "/api/v2/events", query, nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if calls != 1 {
		t.Fatalf("proxy calls=%d", calls)
	}
}

type proxyFunc func(context.Context, ProxyRequest) (ProxyResponse, error)

func (function proxyFunc) Proxy(ctx context.Context, request ProxyRequest) (ProxyResponse, error) {
	return function(ctx, request)
}

func TestPrivateNangoRegistryRejectsCoreKeysAndAllowsOnlyCataloguedProxyTemplates(t *testing.T) {
	config := Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", Entries: []Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/api/team.info"}}}}}
	resolver := resolverFunc(func(_ context.Context, host string) ([]net.IP, error) {
		if host != "slack.com" {
			t.Fatalf("resolved host %q", host)
		}
		return []net.IP{net.ParseIP("13.107.42.14")}, nil
	})
	client := proxyFunc(func(_ context.Context, request ProxyRequest) (ProxyResponse, error) {
		if request.NangoBaseURL != config.BaseURL || request.ProviderHost != "slack.com" || request.Method != "GET" || request.Path != "/api/team.info" || len(request.ResolvedIPs) != 1 {
			t.Fatalf("proxy request %#v", request)
		}
		return ProxyResponse{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil
	})
	adapter, err := NewAdapter(config, resolver, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Proxy(context.Background(), "slack", "ref:nango/connection-0001", "GET", "/api/team.info", nil); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"aws", "kubernetes", "github", "okta"} {
		config.Entries[0].Key = key
		if _, err := NewAdapter(config, resolver, client, time.Second); !errors.Is(err, ErrInvalid) {
			t.Fatalf("core key %q error=%v", key, err)
		}
	}
}

func TestPrivateNangoRegistryRejectsDuplicateProxyRules(t *testing.T) {
	config := Config{
		BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{
			{Method: "GET", PathPrefix: "/api/team.info", QueryKeys: []string{"cursor"}},
			{Method: "GET", PathPrefix: "/api/team.info", QueryKeys: []string{"limit"}},
		}}},
	}
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("13.107.42.14")}, nil })
	client := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) { return ProxyResponse{StatusCode: 200}, nil })
	if _, err := NewAdapter(config, resolver, client, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate proxy rule accepted: %v", err)
	}
}

func TestNangoProxyRejectsPrivateDNSRedirectsUnexpectedPathsAndSecretBodies(t *testing.T) {
	config := Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", Entries: []Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/api/team.info"}}}}}
	privateResolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("169.254.169.254")}, nil })
	client := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) {
		t.Fatal("unsafe request reached client")
		return ProxyResponse{}, nil
	})
	adapter, _ := NewAdapter(config, privateResolver, client, time.Second)
	if _, err := adapter.Proxy(context.Background(), "slack", "ref:nango/connection-0001", "GET", "/api/team.info", nil); !errors.Is(err, ErrProxy) {
		t.Fatalf("private DNS error=%v", err)
	}
	publicResolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("13.107.42.14")}, nil })
	redirectClient := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) {
		return ProxyResponse{StatusCode: 302, Location: "http://169.254.169.254/latest"}, nil
	})
	adapter, _ = NewAdapter(config, publicResolver, redirectClient, time.Second)
	if _, err := adapter.Proxy(context.Background(), "slack", "ref:nango/connection-0001", "GET", "/api/team.info", nil); !errors.Is(err, ErrProxy) {
		t.Fatalf("redirect error=%v", err)
	}
	if _, err := adapter.Proxy(context.Background(), "slack", "ref:nango/connection-0001", "POST", "/api/admin", []byte(`{"access_token":"plaintext"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hostile request error=%v", err)
	}
}

func TestNangoProxyTreatsNonSlashRulesAsExactPaths(t *testing.T) {
	config := Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", Entries: []Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/api/team.info"}}}}}
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("13.107.42.14")}, nil })
	calls := 0
	client := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) {
		calls++
		return ProxyResponse{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil
	})
	adapter, err := NewAdapter(config, resolver, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Proxy(context.Background(), "slack", "ref:nango/connection-0001", "GET", "/api/team.info", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Proxy(context.Background(), "slack", "ref:nango/connection-0001", "GET", "/api/team.info/foreign", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("suffix path error=%v", err)
	}
	if calls != 1 {
		t.Fatalf("proxy calls=%d", calls)
	}
}
