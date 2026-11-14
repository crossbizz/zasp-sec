package nango

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixedPublicResolver struct{}

func (fixedPublicResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

func saasTestAdapter(t *testing.T, respond func(*http.Request) *http.Response) *Adapter {
	t.Helper()
	resolver := serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("00000000-0000-4000-8000-000000000001"), nil
	})
	client, err := NewProxyClientWithHTTP(resolver, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) { return respond(request), nil }), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{{Key: "databricks", ProviderHost: "accounts.cloud.databricks.com", AuthMode: "oauth", Rules: []Rule{{Method: http.MethodGet, PathPrefix: "/api/2.0/serving-endpoints", QueryKeys: []string{"page_token"}}}}}}, fixedPublicResolver{}, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func saasTestResponse(status int, body string, headers map[string]string) *http.Response {
	response := &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	for key, value := range headers {
		response.Header.Set(key, value)
	}
	return response
}

const saasTestConnection = "ref:nango/connection/11111111-1111-4111-8111-111111111111"

// A provider refusal reaches the caller as its status and Retry-After, never
// as its body, and is still an ErrProxy for callers that only test for that.
func TestProxyRelaysARefusalAsStatusAndRetryAfterOnly(t *testing.T) {
	adapter := saasTestAdapter(t, func(*http.Request) *http.Response {
		return saasTestResponse(http.StatusTooManyRequests, `{"error":"slow down","detail":"request 4711"}`, map[string]string{"Retry-After": "30"})
	})
	_, err := adapter.Proxy(context.Background(), "databricks", saasTestConnection, http.MethodGet, "/api/2.0/serving-endpoints", nil)
	var status *StatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusTooManyRequests || status.RetryAfter != "30" || !errors.Is(err, ErrProxy) || strings.Contains(err.Error(), "4711") {
		t.Fatalf("refusal = %#v (%v)", status, err)
	}
	for name, response := range map[string]*http.Response{
		"an oversized Retry-After":  saasTestResponse(http.StatusServiceUnavailable, `{}`, map[string]string{"Retry-After": strings.Repeat("9", 65)}),
		"a Retry-After with a line": saasTestResponse(http.StatusServiceUnavailable, `{}`, map[string]string{"Retry-After": "1 "}),
	} {
		adapter := saasTestAdapter(t, func(*http.Request) *http.Response { return response })
		_, err := adapter.Proxy(context.Background(), "databricks", saasTestConnection, http.MethodGet, "/api/2.0/serving-endpoints", nil)
		if !errors.As(err, &status) || status.StatusCode != http.StatusServiceUnavailable || status.RetryAfter != "" {
			t.Fatalf("%s: %#v (%v)", name, status, err)
		}
	}
	// A status that is not an HTTP error status is a plain proxy failure.
	adapter = saasTestAdapter(t, func(*http.Request) *http.Response { return saasTestResponse(199, `{}`, nil) })
	if _, err := adapter.Proxy(context.Background(), "databricks", saasTestConnection, http.MethodGet, "/api/2.0/serving-endpoints", nil); errors.As(err, &status) || !errors.Is(err, ErrProxy) {
		t.Fatalf("status 199: %v", err)
	}
}

func TestProxyRelaysTheLinkHeaderAndRefusesOneThatCarriesASecret(t *testing.T) {
	link := `<https://api.example/api/2.0/serving-endpoints?page_token=abc>; rel="next"`
	adapter := saasTestAdapter(t, func(*http.Request) *http.Response {
		return saasTestResponse(http.StatusOK, `{"endpoints":[]}`, map[string]string{"Link": link})
	})
	response, err := adapter.Proxy(context.Background(), "databricks", saasTestConnection, http.MethodGet, "/api/2.0/serving-endpoints", nil)
	if err != nil || response.Link != link || string(response.Body) != `{"endpoints":[]}` {
		t.Fatalf("response = %#v, %v", response, err)
	}
	for name, header := range map[string]string{
		"a token in the link": `<https://api.example/api/2.0/serving-endpoints?access_token=abc>; rel="next"`,
		"an oversized link":   "<https://api.example/" + strings.Repeat("a", 9000) + `>; rel="next"`,
	} {
		adapter := saasTestAdapter(t, func(*http.Request) *http.Response {
			return saasTestResponse(http.StatusOK, `{}`, map[string]string{"Link": header})
		})
		if _, err := adapter.Proxy(context.Background(), "databricks", saasTestConnection, http.MethodGet, "/api/2.0/serving-endpoints", nil); !errors.Is(err, ErrProxy) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// "saas" is the discovery provider's name, never a Nango entry.
func TestAdapterRefusesAnEntryNamedAfterTheSaaSProvider(t *testing.T) {
	resolver := serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) { return nil, nil })
	client, err := NewProductionProxyClient(resolver, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewAdapter(Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{{Key: "saas", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []Rule{{Method: http.MethodGet, PathPrefix: "/api/team.info"}}}}}, fixedPublicResolver{}, client, time.Second)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("entry named saas: %v", err)
	}
}

func TestFileServiceSecretResolverReadsOnlyAProtectedKeyFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "service-key")
	if err := os.WriteFile(path, []byte("00000000-0000-4000-8000-000000000001"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewFileServiceSecretResolver(path, "ref:nango/service-key-0001")
	if err != nil {
		t.Fatal(err)
	}
	value, err := resolver.Resolve(context.Background(), "ref:nango/service-key-0001")
	if err != nil || string(value) != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("key = %q, %v", value, err)
	}
	if _, err := resolver.Resolve(context.Background(), "ref:nango/service-key-0002"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another reference: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "ref:nango/service-key-0001"); !errors.Is(err, ErrProxy) {
		t.Fatalf("world-readable key: %v", err)
	}
	for _, hostile := range []string{"relative/service-key", filepath.Join(directory, "other-name"), directory + "/../service-key"} {
		if _, err := NewFileServiceSecretResolver(hostile, "ref:nango/service-key-0001"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("path %q accepted", hostile)
		}
	}
	if _, err := NewFileServiceSecretResolver(path, "service-key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a reference that is not one: %v", err)
	}
}
