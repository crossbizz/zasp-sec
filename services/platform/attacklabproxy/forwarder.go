package attacklabproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

var targetCredentialReferenceRE = regexp.MustCompile(`^ref:red-team/[a-z][a-z0-9_-]{7,127}$`)

type proxyResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type proxyTransportFactory func(string, string, time.Duration) http.RoundTripper

type HTTPSForwarder struct {
	client       *http.Client
	maximumBytes int64
	authorizer   TargetAuthorizer
}

type TargetAuthorization struct {
	PayloadDigest string
	Signature     string
}

type TargetAuthorizer interface {
	Authorize(context.Context, string, []byte) (TargetAuthorization, error)
}

type credentialTargetAuthorizer struct {
	resolver redteamadapter.CredentialResolver
}

func NewTargetAuthorizer(resolver redteamadapter.CredentialResolver) (TargetAuthorizer, error) {
	if resolver == nil {
		return nil, ErrUnavailable
	}
	return &credentialTargetAuthorizer{resolver: resolver}, nil
}

func (authorizer *credentialTargetAuthorizer) Authorize(ctx context.Context, reference string, payload []byte) (TargetAuthorization, error) {
	if authorizer == nil || authorizer.resolver == nil {
		return TargetAuthorization{}, ErrUnavailable
	}
	result, err := redteamadapter.AuthorizeTargetPayload(ctx, authorizer.resolver, reference, payload)
	if err != nil {
		return TargetAuthorization{}, ErrUnavailable
	}
	return TargetAuthorization{PayloadDigest: result.PayloadDigest, Signature: result.Signature}, nil
}

type pinnedProxyRoundTripper struct {
	networks []*net.IPNet
	timeout  time.Duration
	resolver proxyResolver
	factory  proxyTransportFactory
}

func NewHTTPSForwarder(allowedCIDRs []string, timeout time.Duration, maximumBytes int64, authorizer TargetAuthorizer) (*HTTPSForwarder, error) {
	return newHTTPSForwarder(allowedCIDRs, timeout, maximumBytes, authorizer, net.DefaultResolver, productionProxyPinnedTransport)
}

func newHTTPSForwarder(allowedCIDRs []string, timeout time.Duration, maximumBytes int64, authorizer TargetAuthorizer, resolver proxyResolver, factory proxyTransportFactory) (*HTTPSForwarder, error) {
	networks, ok := parseProxyCIDRs(allowedCIDRs)
	if !ok || timeout < time.Second || timeout > 30*time.Second || maximumBytes != 32<<10 || authorizer == nil || resolver == nil || factory == nil {
		return nil, ErrUnavailable
	}
	roundTripper := &pinnedProxyRoundTripper{networks: networks, timeout: timeout, resolver: resolver, factory: factory}
	client := &http.Client{Transport: roundTripper, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}
	return &HTTPSForwarder{client: client, maximumBytes: maximumBytes, authorizer: authorizer}, nil
}

func (forwarder *HTTPSForwarder) Forward(ctx context.Context, input ForwardRequest) (ForwardResult, error) {
	if forwarder == nil || forwarder.client == nil || forwarder.authorizer == nil || ctx == nil || ctx.Err() != nil || !validForwardRequest(input) || int64(len(input.Body)) > forwarder.maximumBytes {
		return ForwardResult{}, ErrUnavailable
	}
	authorization, err := forwarder.authorizer.Authorize(ctx, input.CredentialReference, input.Body)
	if err != nil || !validTargetAuthorization(authorization) {
		return ForwardResult{}, ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, input.Method, "https://"+input.Destination+input.Path, bytes.NewReader(input.Body))
	if err != nil {
		return ForwardResult{}, ErrUnavailable
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", input.ContentType)
	request.Header.Set("User-Agent", "zasp-attack-lab-proxy/1")
	request.Header.Set("X-Zasp-Run-ID", input.RunID)
	request.Header.Set("X-Zasp-Payload-Digest", authorization.PayloadDigest)
	request.Header.Set("X-Zasp-Signature", authorization.Signature)
	response, err := forwarder.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ForwardResult{}, ErrUnavailable
	}
	defer response.Body.Close()
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	body, readErr := io.ReadAll(io.LimitReader(response.Body, forwarder.maximumBytes+1))
	if mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 || readErr != nil || len(body) < 2 || int64(len(body)) > forwarder.maximumBytes || !jsonBody(body) {
		clear(body)
		return ForwardResult{}, ErrUnavailable
	}
	return ForwardResult{StatusCode: response.StatusCode, ContentType: "application/json", Body: body}, nil
}

func (roundTripper *pinnedProxyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper == nil || request == nil || request.URL == nil || request.Context() == nil || request.Context().Err() != nil || request.Method != http.MethodPost || request.URL.Scheme != "https" || request.URL.Port() != "" || request.URL.User != nil || request.URL.Path != "/v1/attack-lab/canary" || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return nil, ErrUnavailable
	}
	host := strings.ToLower(request.URL.Hostname())
	if !validProxyHostname(host) {
		return nil, ErrUnavailable
	}
	addresses, err := roundTripper.resolver.LookupIPAddr(request.Context(), host)
	if err != nil || len(addresses) < 1 || len(addresses) > 32 {
		return nil, ErrUnavailable
	}
	values := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if !validProxyPublicIP(address.IP) || !proxyIPAllowed(address.IP, roundTripper.networks) {
			return nil, ErrUnavailable
		}
		value := address.IP.String()
		if _, duplicate := seen[value]; !duplicate {
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return nil, ErrUnavailable
	}
	sort.Strings(values)
	transport := roundTripper.factory(host, values[0], roundTripper.timeout)
	if transport == nil {
		return nil, ErrUnavailable
	}
	return transport.RoundTrip(request)
}

func productionProxyPinnedTransport(host, pinnedIP string, timeout time.Duration) http.RoundTripper {
	if !validProxyHostname(host) || !validProxyPublicIP(net.ParseIP(pinnedIP)) || timeout < time.Second || timeout > 30*time.Second {
		return nil
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedHost, port, err := net.SplitHostPort(address)
		if err != nil || strings.ToLower(requestedHost) != host || port != "443" {
			return nil, ErrUnavailable
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(pinnedIP, "443"))
	}
	return transport
}

func parseProxyCIDRs(values []string) ([]*net.IPNet, bool) {
	if len(values) < 1 || len(values) > 64 {
		return nil, false
	}
	result := make([]*net.IPNet, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		ones, bits := 0, 0
		if err == nil {
			ones, bits = network.Mask.Size()
		}
		if err != nil || network.String() != value || !ip.Equal(network.IP) || !validProxyPublicIP(ip) || bits == 32 && ones < 16 || bits == 128 && ones < 32 || bits != 32 && bits != 128 {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		for _, existing := range result {
			if existing.Contains(network.IP) || network.Contains(existing.IP) {
				return nil, false
			}
		}
		seen[value] = struct{}{}
		result = append(result, network)
	}
	return result, true
}

func ValidTargetCIDRs(values []string) bool {
	_, ok := parseProxyCIDRs(values)
	return ok
}

func validForwardRequest(input ForwardRequest) bool {
	_, runErr := domain.ParseProductID(input.RunID)
	return validProxyHostname(input.Destination) && targetCredentialReferenceRE.MatchString(input.CredentialReference) && runErr == nil && input.Method == http.MethodPost && input.Path == "/v1/attack-lab/canary" && input.ContentType == "application/json" && len(input.Body) >= 2 && jsonBody(input.Body)
}

func validTargetAuthorization(value TargetAuthorization) bool {
	return regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(value.PayloadDigest) && regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(value.Signature)
}

func validProxyHostname(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func validProxyPublicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func proxyIPAllowed(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func jsonBody(value []byte) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) >= 2 && json.Valid(trimmed) && (trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' || trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']')
}

var _ Forwarder = (*HTTPSForwarder)(nil)
