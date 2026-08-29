package nango

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type serviceSecretResolverFunc func(context.Context, string) ([]byte, error)

func (function serviceSecretResolverFunc) Resolve(ctx context.Context, reference string) ([]byte, error) {
	return function(ctx, reference)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProductionProxyClientUsesOnlyPrivateNangoAuthorityAndOpaqueConnection(t *testing.T) {
	secret := []byte("00000000-0000-4000-8000-000000000001")
	resolverCalls := 0
	resolver := serviceSecretResolverFunc(func(_ context.Context, reference string) ([]byte, error) {
		resolverCalls++
		if reference != "ref:nango/service-key-0001" {
			t.Fatalf("secret reference %q", reference)
		}
		return append([]byte(nil), secret...), nil
	})
	transportCalls := 0
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			transportCalls++
			if request.Method != http.MethodGet || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/proxy/api/team.info?limit=1" {
				t.Fatalf("request %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("Authorization") != "Bearer "+string(secret) || request.Header.Get("Connection-Id") != "11111111-1111-4111-8111-111111111111" || request.Header.Get("Provider-Config-Key") != "slack" {
				t.Fatalf("headers %#v", request.Header)
			}
			if request.Header.Get("Nango-Is-Sync") != "false" || request.Header.Get("Accept") != "application/json" {
				t.Fatalf("fixed headers %#v", request.Header)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		}),
		Timeout:       time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	client, err := newProductionProxyClientWithHTTP(resolver, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Proxy(context.Background(), ProxyRequest{
		NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "slack", ConnectionReference: "ref:nango/connection/11111111-1111-4111-8111-111111111111", ProviderHost: "slack.com", Method: http.MethodGet, Path: "/api/team.info", RawQuery: "limit=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolverCalls != 1 || transportCalls != 1 || response.StatusCode != http.StatusOK || string(response.Body) != `{"ok":true}` || response.Location != "" {
		t.Fatalf("calls=(%d,%d) response=%#v", resolverCalls, transportCalls, response)
	}
}

func TestProductionProxyClientRejectsRedirectsSecretsAndMalformedAuthority(t *testing.T) {
	resolver := serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("00000000-0000-4000-8000-000000000001"), nil
	})
	request := ProxyRequest{
		NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "slack", ConnectionReference: "ref:nango/connection/11111111-1111-4111-8111-111111111111", ProviderHost: "slack.com", Method: http.MethodGet, Path: "/api/team.info",
	}
	for name, response := range map[string]*http.Response{
		"redirect": {StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://169.254.169.254/latest"}}, Body: io.NopCloser(strings.NewReader(""))},
		"secret":   {StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"provider-secret"}`))},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := newProductionProxyClientWithHTTP(resolver, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return response, nil }), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Proxy(context.Background(), request); !errors.Is(err, ErrProxy) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	client, err := newProductionProxyClientWithHTTP(resolver, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("malformed request reached transport")
		return nil, nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	if err != nil {
		t.Fatal(err)
	}
	request.ConnectionReference = "ref:nango/connection/not-a-uuid"
	if _, err := client.Proxy(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error=%v", err)
	}
}
