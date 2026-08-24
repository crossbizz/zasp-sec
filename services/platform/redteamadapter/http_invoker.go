package redteamadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type Credential struct {
	mu        sync.Mutex
	secret    []byte
	destroyed bool
	onDestroy func()
}

func newCredential(secret []byte, onDestroy func()) (*Credential, error) {
	if len(secret) < 32 || len(secret) > 4096 || onDestroy == nil {
		return nil, ErrAdapter
	}
	return &Credential{secret: secret, onDestroy: onDestroy}, nil
}

func (credential *Credential) bytes() ([]byte, bool) {
	if credential == nil {
		return nil, false
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.destroyed || len(credential.secret) < 32 || len(credential.secret) > 4096 {
		return nil, false
	}
	return append([]byte(nil), credential.secret...), true
}

func (credential *Credential) Destroy() {
	if credential == nil {
		return
	}
	credential.mu.Lock()
	if credential.destroyed {
		credential.mu.Unlock()
		return
	}
	clear(credential.secret)
	credential.secret = nil
	credential.destroyed = true
	onDestroy := credential.onDestroy
	credential.onDestroy = nil
	credential.mu.Unlock()
	onDestroy()
}

type CredentialResolver interface {
	ResolveTargetCredential(context.Context, string) (*Credential, error)
}

type TargetAuthorization struct {
	PayloadDigest string
	Signature     string
}

func AuthorizeTargetPayload(ctx context.Context, resolver CredentialResolver, reference string, payload []byte) (TargetAuthorization, error) {
	if ctx == nil || ctx.Err() != nil || resolver == nil || !credentialReferenceRE.MatchString(reference) || len(payload) < 2 || len(payload) > 64*1024 || !json.Valid(payload) {
		return TargetAuthorization{}, ErrAdapter
	}
	credential, err := resolver.ResolveTargetCredential(ctx, reference)
	if err != nil || credential == nil {
		if credential != nil {
			credential.Destroy()
		}
		return TargetAuthorization{}, ErrAdapter
	}
	defer credential.Destroy()
	secret, ok := credential.bytes()
	if !ok {
		return TargetAuthorization{}, ErrAdapter
	}
	defer clear(secret)
	digest := sha256.Sum256(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return TargetAuthorization{PayloadDigest: "sha256:" + hex.EncodeToString(digest[:]), Signature: "sha256:" + hex.EncodeToString(mac.Sum(nil))}, nil
}

type HTTPSInvoker struct {
	client      *http.Client
	credentials CredentialResolver
	timeout     time.Duration
}

type targetWireRequest struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	TargetID      string `json:"target_id"`
	TargetKind    string `json:"target_kind"`
	Category      string `json:"category"`
	Input         string `json:"input"`
}

func NewProductionHTTPSInvoker(allowedCIDRs []string, timeout time.Duration, credentials CredentialResolver) (*HTTPSInvoker, error) {
	return newProductionHTTPSInvoker(allowedCIDRs, timeout, credentials, net.DefaultResolver, productionPinnedTransport)
}

func newProductionHTTPSInvoker(allowedCIDRs []string, timeout time.Duration, credentials CredentialResolver, lookup interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}, factory pinnedTransportFactory) (*HTTPSInvoker, error) {
	roundTripper, err := newPinnedRoundTripper(allowedCIDRs, timeout, lookup, factory)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: roundTripper, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAdapter }}
	return newHTTPSInvoker(client, credentials, timeout)
}

func newHTTPSInvoker(client *http.Client, credentials CredentialResolver, timeout time.Duration) (*HTTPSInvoker, error) {
	if client == nil || client.Transport == nil || credentials == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrAdapter
	}
	bounded := *client
	bounded.Timeout = timeout
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrAdapter }
	return &HTTPSInvoker{client: &bounded, credentials: credentials, timeout: timeout}, nil
}

func (invoker *HTTPSInvoker) Invoke(ctx context.Context, invocation Invocation) (string, error) {
	if invoker == nil || invoker.client == nil || invoker.credentials == nil || ctx == nil || ctx.Err() != nil || invocation.Scope.Validate() != nil || !validBinding(invocation.Binding) || invocation.RunID == invocation.Binding.TargetID || !validRequestBody(requestBody{TargetID: invocation.Binding.TargetID, TargetKind: invocation.Binding.TargetKind, Category: invocation.Category, Input: invocation.Input}) {
		return "", ErrAdapter
	}
	payload, err := json.Marshal(targetWireRequest{SchemaVersion: "red-team-target-v1", RunID: invocation.RunID, TargetID: invocation.Binding.TargetID, TargetKind: invocation.Binding.TargetKind, Category: invocation.Category, Input: invocation.Input})
	if err != nil || len(payload) < 1 || len(payload) > 64*1024 {
		return "", ErrAdapter
	}
	authorization, err := AuthorizeTargetPayload(ctx, invoker.credentials, invocation.Binding.CredentialReference, payload)
	if err != nil {
		return "", ErrAdapter
	}
	bounded, cancel := context.WithTimeout(ctx, invoker.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, invocation.Binding.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", ErrAdapter
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "zasp-red-team-target-adapter/1")
	request.Header.Set("X-Zasp-Run-ID", invocation.RunID)
	request.Header.Set("X-Zasp-Payload-Digest", authorization.PayloadDigest)
	request.Header.Set("X-Zasp-Signature", authorization.Signature)
	response, err := invoker.client.Do(request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeResponse(response)
		return "", ErrAdapter
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if readErr != nil || len(body) < 1 || len(body) > 64*1024 || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return "", ErrAdapter
	}
	var result Response
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil {
		return "", ErrAdapter
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || !validText(result.Output, 64*1024) {
		return "", ErrAdapter
	}
	return result.Output, nil
}

func closeResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

type lookupResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type pinnedTransportFactory func(string, string, time.Duration) http.RoundTripper

type pinnedRoundTripper struct {
	networks []*net.IPNet
	timeout  time.Duration
	lookup   lookupResolver
	factory  pinnedTransportFactory
}

func newPinnedRoundTripper(allowedCIDRs []string, timeout time.Duration, lookup lookupResolver, factory pinnedTransportFactory) (*pinnedRoundTripper, error) {
	networks, ok := parseCIDRs(allowedCIDRs)
	if !ok || timeout < 100*time.Millisecond || timeout > 30*time.Second || lookup == nil || factory == nil {
		return nil, ErrAdapter
	}
	return &pinnedRoundTripper{networks: networks, timeout: timeout, lookup: lookup, factory: factory}, nil
}

func (roundTripper *pinnedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper == nil || request == nil || request.URL == nil || request.Context() == nil || request.Context().Err() != nil || request.Method != http.MethodPost || request.URL.Scheme != "https" || request.URL.Port() != "" || request.URL.User != nil || request.URL.Path != "/v1/evaluate" || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return nil, ErrAdapter
	}
	host := strings.ToLower(request.URL.Hostname())
	if !hostnameRE.MatchString(host) || !netPublicHostname(host) {
		return nil, ErrAdapter
	}
	addresses, err := roundTripper.lookup.LookupIPAddr(request.Context(), host)
	if err != nil || len(addresses) < 1 || len(addresses) > 32 {
		return nil, ErrAdapter
	}
	values := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		ip := address.IP
		if !validPublicIP(ip) || !ipAllowed(ip, roundTripper.networks) {
			return nil, ErrAdapter
		}
		value := ip.String()
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, ErrAdapter
	}
	sort.Strings(values)
	transport := roundTripper.factory(host, values[0], roundTripper.timeout)
	if transport == nil {
		return nil, ErrAdapter
	}
	return transport.RoundTrip(request)
}

func parseCIDRs(values []string) ([]*net.IPNet, bool) {
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
		if err != nil || network.String() != value || !ip.Equal(network.IP) || !validPublicIP(ip) || bits == 32 && ones < 16 || bits == 128 && ones < 32 || bits != 32 && bits != 128 {
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
	_, ok := parseCIDRs(values)
	return ok
}

func validPublicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func ipAllowed(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func productionPinnedTransport(host, pinnedIP string, timeout time.Duration) http.RoundTripper {
	if !hostnameRE.MatchString(host) || !netPublicHostname(host) || !validPublicIP(net.ParseIP(pinnedIP)) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedHost, port, err := net.SplitHostPort(address)
		if err != nil || strings.ToLower(requestedHost) != host || port != "443" {
			return nil, ErrAdapter
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(pinnedIP, "443"))
	}
	return transport
}

var _ TargetInvoker = (*HTTPSInvoker)(nil)
