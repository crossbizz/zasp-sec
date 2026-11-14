package nango

import (
	"context"
	"errors"
	"net"
	"regexp"
	"testing"
	"time"
)

func customerHostConfig() Config {
	return Config{
		BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{
			{Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, HostPattern: regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,198}[a-z0-9])?$`),
				Rules: []Rule{{Method: "GET", PathPrefix: "/api/v4/groups/"}}},
			{Key: "fixed-host", ProviderHost: "api.example.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/v1/items"}}},
		},
	}
}

// A customer-hosted entry sends to the host a request names when that host
// is a public DNS name whose every address is public, pins Nango to it, and
// sends nowhere else.
func TestCustomerHostedEntrySendsOnlyToAPublicCustomerHost(t *testing.T) {
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	addresses := map[string][]net.IP{"gitlab.acme-corp.com": {net.ParseIP("203.0.114.10")}}
	var resolved []string
	resolver := resolverFunc(func(_ context.Context, host string) ([]net.IP, error) {
		resolved = append(resolved, host)
		if found, ok := addresses[host]; ok {
			return found, nil
		}
		return nil, errors.New("no such host")
	})
	var sent []ProxyRequest
	client := proxyFunc(func(_ context.Context, request ProxyRequest) (ProxyResponse, error) {
		sent = append(sent, request)
		return ProxyResponse{StatusCode: 200, Body: []byte(`{"id":4242}`)}, nil
	})
	adapter, err := NewAdapter(customerHostConfig(), resolver, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	get := func(host string) error {
		_, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab-pat", ConnectionReference: reference, Host: host, Method: "GET", Path: "/api/v4/groups/4242"})
		return err
	}
	if err := get("gitlab.acme-corp.com"); err != nil || len(sent) != 1 || sent[0].ProviderHost != "gitlab.acme-corp.com" || !sent[0].PinHost || len(sent[0].ResolvedIPs) != 1 {
		t.Fatalf("customer host: %v, %+v", err, sent)
	}
	// Names that are not a public DNS name are refused before any lookup.
	resolved = nil
	for _, host := range []string{
		"", "10.0.0.5", "169.254.169.254", "2130706433", "0x7f.0.0.1", "[::1]", "localhost", "gitlab", "gitlab.local", "gitlab.internal", "metadata.google.internal",
		"gitlab.gitlab.svc", "nango.connector.svc.cluster.local", "gitlab.acme.123", "gitlab.lan", "gitlab.home", "gitlab.corp", "gitlab.test", "gitlab.acme-corp.com:8443",
		"gitlab.acme-corp.com/x", "user@gitlab.acme-corp.com", "GitLab.acme-corp.com", "gitlab.acme-corp.com.", "gitlab..acme-corp.com", "-gitlab.acme-corp.com", "gitlab.acme_corp.com",
	} {
		if err := get(host); !errors.Is(err, ErrInvalid) {
			t.Errorf("host %q: %v", host, err)
		}
	}
	if len(resolved) != 0 || len(sent) != 1 {
		t.Fatalf("a refused host was resolved (%v) or sent (%d)", resolved, len(sent))
	}
	// A public name that does not resolve, and a fixed-host entry given a
	// host, are refused too; a customer-hosted entry needs a host.
	if err := get("gitlab.other-corp.com"); !errors.Is(err, ErrProxy) {
		t.Errorf("unresolvable host: %v", err)
	}
	if _, err := adapter.Do(context.Background(), Request{ConnectorKey: "fixed-host", ConnectionReference: reference, Host: "gitlab.acme-corp.com", Method: "GET", Path: "/v1/items"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("fixed entry with a host: %v", err)
	}
	if _, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab-pat", ConnectionReference: reference, Method: "GET", Path: "/api/v4/groups/4242"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("customer-hosted entry without a host: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("requests sent = %d", len(sent))
	}
}

// The customer's name decides nothing about where the request goes: every
// address it resolves to must be public, or nothing is sent.
func TestCustomerHostedEntryRefusesAHostThatResolvesToANonPublicAddress(t *testing.T) {
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	for name, addresses := range map[string][]string{
		"loopback": {"127.0.0.1"}, "private": {"10.1.2.3"}, "private 172": {"172.16.0.9"}, "private 192": {"192.168.1.1"}, "metadata link-local": {"169.254.169.254"},
		"shared address": {"100.64.0.10"}, "ipv6 loopback": {"::1"}, "ipv6 unique local": {"fd00::1"}, "mapped private": {"::ffff:10.0.0.1"},
		"one private of two": {"203.0.114.10", "10.0.0.1"}, "none": {},
	} {
		resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) {
			var result []net.IP
			for _, address := range addresses {
				result = append(result, net.ParseIP(address))
			}
			return result, nil
		})
		client := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) {
			t.Errorf("%s: Nango was called for a non-public destination", name)
			return ProxyResponse{}, nil
		})
		adapter, err := NewAdapter(customerHostConfig(), resolver, client, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab-pat", ConnectionReference: reference, Host: "gitlab.acme-corp.com", Method: "GET", Path: "/api/v4/groups/4242"}); !errors.Is(err, ErrProxy) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Customer hosting is declared explicitly and cannot be combined with a
// fixed host or with provider suffixes; without the declaration a per-tenant
// entry still needs its provider's suffixes.
func TestCustomerHostedEntriesAreDeclaredExplicitly(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z0-9.-]+$`)
	rules := []Rule{{Method: "GET", PathPrefix: "/api/v4/groups/"}}
	if !validEntry(Entry{Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, HostPattern: pattern, Rules: rules}) {
		t.Fatal("a customer-hosted entry is refused")
	}
	for name, entry := range map[string]Entry{
		"any host without the declaration": {Key: "gitlab-pat", AuthMode: "api_key", HostPattern: pattern, Rules: rules},
		"declared with a fixed host":       {Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, ProviderHost: "gitlab.com", Rules: rules},
		"declared with a pattern and host": {Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, HostPattern: pattern, ProviderHost: "gitlab.com", Rules: rules},
		"declared with suffixes":           {Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, HostPattern: pattern, HostSuffixes: []string{".gitlab-dedicated.com"}, Rules: rules},
		"declared without a pattern":       {Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, Rules: rules},
	} {
		if validEntry(entry) {
			t.Errorf("%s: entry accepted", name)
		}
	}
	// A provider-suffix entry is unchanged: it does not admit a customer's host.
	servicenow := tenantHostConfig().Entries[0]
	if servicenow.AllowsHost("gitlab.acme-corp.com") || !servicenow.AllowsHost("acme.service-now.com") {
		t.Fatal("a provider-suffix entry admits another domain")
	}
}
