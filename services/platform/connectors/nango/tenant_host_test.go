package nango

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func tenantHostConfig() Config {
	return Config{
		BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{
			{Key: "servicenow", AuthMode: "oauth", HostPattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}\.service-now\.com$`), HostSuffixes: []string{".service-now.com"},
				Rules: []Rule{{Method: "GET", PathPrefix: "/api/now/table/", QueryKeys: []string{"sysparm_limit"}}}},
			{Key: "fixed-host", ProviderHost: "api.example.com", AuthMode: "oauth", Rules: []Rule{{Method: "GET", PathPrefix: "/v1/items"}}},
		},
	}
}

func TestProxyToHostSendsOnlyToAnAllowedPublicTenantHost(t *testing.T) {
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	addresses := map[string][]net.IP{"acme.service-now.com": {net.ParseIP("149.96.6.119")}}
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
		return ProxyResponse{StatusCode: 200, Body: []byte(`{"result":[]}`)}, nil
	})
	adapter, err := NewAdapter(tenantHostConfig(), resolver, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ProxyToHost(context.Background(), "servicenow", reference, "acme.service-now.com", "GET", "/api/now/table/sys_properties", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].ProviderHost != "acme.service-now.com" || !sent[0].PinHost || len(sent[0].ResolvedIPs) != 1 || resolved[0] != "acme.service-now.com" {
		t.Fatalf("sent = %+v resolved = %v", sent, resolved)
	}

	// A host outside the entry's pattern or suffix is refused before any
	// name is resolved and before Nango is called.
	resolved, sent = nil, nil
	for name, host := range map[string]string{
		"another domain":       "acme.example.com",
		"suffix inside a name": "acme.service-now.com.attacker.net",
		"prefix trick":         "attacker.net.service-now.com",
		"bare suffix":          "service-now.com",
		"address":              "169.254.169.254",
		"cluster name":         "nango.connector.svc.cluster.local",
		"upper case":           "ACME.service-now.com",
		"port":                 "acme.service-now.com:8443",
		"credentials":          "user@acme.service-now.com",
		"path":                 "acme.service-now.com/x",
		"empty":                "",
	} {
		if _, err := adapter.ProxyToHost(context.Background(), "servicenow", reference, host, "GET", "/api/now/table/sys_properties", nil, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: host %q error = %v", name, host, err)
		}
	}
	if len(resolved) != 0 || len(sent) != 0 {
		t.Fatalf("a refused host was resolved %v or sent %v", resolved, sent)
	}

	// A fixed-host entry takes no host and a per-tenant entry needs one: a
	// request cannot fall back to the other kind of destination.
	addresses["api.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	if _, err := adapter.ProxyToHost(context.Background(), "fixed-host", reference, "acme.service-now.com", "GET", "/v1/items", nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("fixed entry with a host: %v", err)
	}
	if _, err := adapter.ProxyWithQuery(context.Background(), "servicenow", reference, "GET", "/api/now/table/sys_properties", nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("per-tenant entry without a host: %v", err)
	}
	if _, err := adapter.ProxyWithQuery(context.Background(), "fixed-host", reference, "GET", "/v1/items", nil, nil); err != nil || sent[len(sent)-1].PinHost {
		t.Fatalf("fixed entry: %v pinned=%v", err, sent)
	}
}

func TestProxyToHostRefusesATenantHostThatResolvesToANonPublicAddress(t *testing.T) {
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	for name, addresses := range map[string][]string{
		"loopback":            {"127.0.0.1"},
		"private":             {"10.1.2.3"},
		"metadata link-local": {"169.254.169.254"},
		"shared address":      {"100.64.0.10"},
		"benchmark":           {"198.18.0.1"},
		"reserved":            {"240.0.0.1"},
		"this network":        {"0.1.2.3"},
		"ipv6 loopback":       {"::1"},
		"ipv6 unique local":   {"fd00::1"},
		"ipv6 link-local":     {"fe80::1"},
		"nat64 of loopback":   {"64:ff9b::7f00:1"},
		"6to4":                {"2002:a00:1::1"},
		"mapped private":      {"::ffff:10.0.0.1"},
		"one private of two":  {"149.96.6.119", "192.168.1.1"},
		"none":                {},
	} {
		t.Run(name, func(t *testing.T) {
			resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) {
				var result []net.IP
				for _, address := range addresses {
					result = append(result, net.ParseIP(address))
				}
				return result, nil
			})
			client := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) {
				t.Error("Nango was called for a non-public destination")
				return ProxyResponse{}, nil
			})
			adapter, err := NewAdapter(tenantHostConfig(), resolver, client, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.ProxyToHost(context.Background(), "servicenow", reference, "acme.service-now.com", "GET", "/api/now/table/sys_properties", nil, nil); !errors.Is(err, ErrProxy) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPerTenantEntryNeedsAPatternAndProviderOwnedSuffixes(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("149.96.6.119")}, nil })
	client := proxyFunc(func(context.Context, ProxyRequest) (ProxyResponse, error) { return ProxyResponse{StatusCode: 200}, nil })
	pattern := regexp.MustCompile(`^.+$`)
	for name, entry := range map[string]Entry{
		"suffix without a pattern":    {Key: "tenant-a", ProviderHost: "api.example.com", AuthMode: "oauth", HostSuffixes: []string{".example.com"}},
		"pattern without a suffix":    {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern},
		"pattern and a fixed host":    {Key: "tenant-a", ProviderHost: "api.example.com", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".example.com"}},
		"suffix that is a whole tld":  {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".com"}},
		"suffix without a dot":        {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{"example.com"}},
		"cluster suffix":              {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".svc.cluster.local"}},
		"internal suffix":             {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".corp.internal"}},
		"neither host nor a pattern":  {Key: "tenant-a", AuthMode: "oauth"},
		"upper case suffix":           {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".Example.com"}},
		"suffix with a path":          {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".example.com/x"}},
		"too many suffixes":           {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".a.com", ".b.com", ".c.com", ".d.com", ".e.com", ".f.com", ".g.com", ".h.com", ".i.com"}},
		"suffix of the local domain":  {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".example.local"}},
		"suffix of localhost":         {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".app.localhost"}},
		"suffix with an empty label":  {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{"..example.com"}},
		"suffix that ends with a dot": {Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".example.com."}},
	} {
		entry.Rules = []Rule{{Method: "GET", PathPrefix: "/v1/items"}}
		config := tenantHostConfig()
		config.Entries = []Entry{entry}
		if _, err := NewAdapter(config, resolver, client, time.Second); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	// Even a pattern that matches anything admits only names under the
	// entry's suffixes.
	loose := Entry{Key: "tenant-a", AuthMode: "oauth", HostPattern: pattern, HostSuffixes: []string{".example.com"}}
	if !loose.AllowsHost("acme.example.com") || loose.AllowsHost("acme.example.org") || loose.AllowsHost("example.com") || loose.AllowsHost("metadata.google.internal") {
		t.Fatal("the suffix does not bound a loose pattern")
	}
	// A pattern that matches only part of the name does not admit it.
	partial := Entry{Key: "tenant-a", AuthMode: "oauth", HostPattern: regexp.MustCompile(`[a-z]+\.example\.com`), HostSuffixes: []string{".example.com"}}
	if !partial.AllowsHost("acme.example.com") || partial.AllowsHost("10-0-0-1.acme.example.com") {
		t.Fatal("the pattern is not matched against the whole host")
	}
}

func TestProductionProxyClientPinsTheTenantHostOnlyWhenAsked(t *testing.T) {
	var overrides []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		overrides = append(overrides, strings.Join(request.Header.Values("Base-Url-Override"), ","))
		_, _ = io.WriteString(writer, `{}`)
	}))
	defer server.Close()
	address := server.Listener.Addr().String()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client, err := NewProxyClientWithHTTP(testSecretResolver{}, &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	if err != nil {
		t.Fatal(err)
	}
	request := ProxyRequest{NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "servicenow", ConnectionReference: "ref:nango/connection/11111111-1111-4111-8111-111111111111", ProviderHost: "acme.service-now.com", Method: "GET", Path: "/api/now/table/sys_properties"}
	if _, err := client.Proxy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.PinHost = true
	if _, err := client.Proxy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 2 || overrides[0] != "" || overrides[1] != "https://acme.service-now.com" {
		t.Fatalf("Base-Url-Override headers = %q", overrides)
	}
}

type testSecretResolver struct{}

func (testSecretResolver) Resolve(context.Context, string) ([]byte, error) {
	return []byte("stand-in-nango-service-key-0001"), nil
}
