package nango

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maximumProxyResponseBytes = 1 << 20

var connectionReferencePattern = regexp.MustCompile(`^ref:nango/connection/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$`)

type ServiceSecretResolver interface {
	Resolve(context.Context, string) ([]byte, error)
}

type ProductionProxyClient struct {
	resolver ServiceSecretResolver
	client   *http.Client
}

func NewProductionProxyClient(resolver ServiceSecretResolver, timeout time.Duration) (*ProductionProxyClient, error) {
	if resolver == nil || timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, ErrInvalid
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 1 << 20,
	}
	return newProductionProxyClientWithHTTP(resolver, &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
}

func newProductionProxyClientWithHTTP(resolver ServiceSecretResolver, client *http.Client) (*ProductionProxyClient, error) {
	if resolver == nil || client == nil || client.Transport == nil || client.Timeout < 100*time.Millisecond || client.Timeout > 10*time.Second || client.CheckRedirect == nil {
		return nil, ErrInvalid
	}
	return &ProductionProxyClient{resolver: resolver, client: client}, nil
}

func (client *ProductionProxyClient) Proxy(ctx context.Context, request ProxyRequest) (ProxyResponse, error) {
	connection := connectionReferencePattern.FindStringSubmatch(request.ConnectionReference)
	if client == nil || client.resolver == nil || client.client == nil || ctx == nil || ctx.Err() != nil ||
		!validBaseURL(request.NangoBaseURL) || !referencePattern.MatchString(request.ServiceSecretReference) ||
		!environmentPattern.MatchString(request.Environment) || !keyPattern.MatchString(request.ConnectorKey) ||
		len(connection) != 2 || !validProviderHost(request.ProviderHost) || !validProxyPath(request.Path) ||
		!validCanonicalRawQuery(request.RawQuery) || request.Method != http.MethodGet && request.Method != http.MethodPost || len(request.Body) > 64<<10 || containsSecret(request.Body) {
		return ProxyResponse{}, ErrInvalid
	}
	base, err := url.Parse(request.NangoBaseURL)
	if err != nil {
		return ProxyResponse{}, ErrInvalid
	}
	base.Path = "/proxy" + request.Path
	base.RawQuery = request.RawQuery
	secret, err := client.resolver.Resolve(ctx, request.ServiceSecretReference)
	if err != nil || !validServiceSecret(secret) {
		clear(secret)
		return ProxyResponse{}, ErrProxy
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, base.String(), bytes.NewReader(request.Body))
	if err != nil {
		clear(secret)
		return ProxyResponse{}, ErrProxy
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(secret))
	httpRequest.Header.Set("Connection-Id", connection[1])
	httpRequest.Header.Set("Provider-Config-Key", request.ConnectorKey)
	httpRequest.Header.Set("Nango-Is-Sync", "false")
	httpRequest.Header.Set("Accept", "application/json")
	if len(request.Body) > 0 {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	clear(secret)
	response, err := client.client.Do(httpRequest)
	if err != nil || response == nil {
		return ProxyResponse{}, ErrProxy
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maximumProxyResponseBytes+1))
	if readErr != nil || len(payload) > maximumProxyResponseBytes || response.StatusCode < 200 || response.StatusCode > 299 || response.Header.Get("Location") != "" || containsSecret(payload) {
		clear(payload)
		return ProxyResponse{}, ErrProxy
	}
	return ProxyResponse{StatusCode: response.StatusCode, Body: payload}, nil
}

func validCanonicalRawQuery(value string) bool {
	if len(value) > 2048 {
		return false
	}
	query, err := url.ParseQuery(value)
	return err == nil && query.Encode() == value
}

func (client *ProductionProxyClient) Close() error {
	if client != nil && client.client != nil {
		client.client.CloseIdleConnections()
	}
	return nil
}

func validProviderHost(value string) bool {
	return len(value) >= 4 && len(value) <= 253 && strings.ToLower(value) == value && net.ParseIP(value) == nil && !strings.ContainsAny(value, "/:@?#\\\x00\r\n\t ") && !strings.HasSuffix(value, ".local") && !strings.HasSuffix(value, ".internal")
}

func validServiceSecret(value []byte) bool {
	if len(value) < 16 || len(value) > 4096 || !bytes.Equal(value, bytes.TrimSpace(value)) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
