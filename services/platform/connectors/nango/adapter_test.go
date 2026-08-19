package nango

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]net.IP, error)

func (function resolverFunc) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return function(ctx, host)
}

type proxyFunc func(context.Context, ProxyRequest) (ProxyResponse, error)

func (function proxyFunc) Proxy(ctx context.Context, request ProxyRequest) (ProxyResponse, error) {
	return function(ctx, request)
}

func TestPrivateNangoRegistryRejectsCoreKeysAndAllowsOnlyCataloguedProxyTemplates(t *testing.T) {
	config := Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", Entries: []Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/api/team."}}}}}
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

func TestNangoProxyRejectsPrivateDNSRedirectsUnexpectedPathsAndSecretBodies(t *testing.T) {
	config := Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", Entries: []Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/api/team."}}}}}
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
