package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type gatewayProxyResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type gatewayProxyTransportFactory func(string, string, time.Duration) http.RoundTripper

type productionGatewayProxyRoundTripper struct {
	upstream *url.URL
	networks []*net.IPNet
	timeout  time.Duration
	resolver gatewayProxyResolver
	factory  gatewayProxyTransportFactory
}

func newProductionGatewayProxy(runtime *gatewayRuntime, config productionGatewayConfig, resolver gatewayProxyResolver, factory gatewayProxyTransportFactory) (*gatewayProxyHandler, error) {
	if runtime == nil || !validGatewayProxyAuthority(config.ProxyUpstreamURL, config.ProxyAllowedCIDRs) || config.MaximumRequestBytes < 1024 || config.MaximumRequestBytes > 64*1024 || config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second || resolver == nil || factory == nil {
		return nil, errRuntimeUnavailable
	}
	upstream, err := url.Parse(config.ProxyUpstreamURL)
	networks, networksOK := parseGatewayProxyCIDRs(config.ProxyAllowedCIDRs)
	if err != nil || !networksOK {
		return nil, errRuntimeUnavailable
	}
	token, err := loadGatewayProxyToken(config.ProxyClientTokenFile)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer clear(token)
	roundTripper := &productionGatewayProxyRoundTripper{upstream: upstream, networks: networks, timeout: config.OperationTimeout, resolver: resolver, factory: factory}
	client := &http.Client{Transport: roundTripper, Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errRuntimeUnavailable }}
	handler, err := newGatewayProxyHandler(gatewayProxyConfig{Runtime: runtime, Client: client, Upstream: upstream, ClientToken: token, MaximumBytes: config.MaximumRequestBytes, Ready: roundTripper.Ready})
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return handler, nil
}

func (roundTripper *productionGatewayProxyRoundTripper) Ready(ctx context.Context) error {
	if roundTripper == nil || ctx == nil || ctx.Err() != nil || roundTripper.upstream == nil {
		return errRuntimeUnavailable
	}
	_, _, err := roundTripper.pinned(ctx)
	return err
}

func (roundTripper *productionGatewayProxyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if roundTripper == nil || request == nil || request.URL == nil || request.Context() == nil || request.Context().Err() != nil || !validGatewayProxyMethod(request.Method) || roundTripper.upstream == nil || !validGatewayProxyTarget(roundTripper.upstream, request.URL) {
		return nil, errRuntimeUnavailable
	}
	host, pinnedIP, err := roundTripper.pinned(request.Context())
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	transport := roundTripper.factory(host, pinnedIP, roundTripper.timeout)
	if transport == nil {
		return nil, errRuntimeUnavailable
	}
	return transport.RoundTrip(request)
}

func (roundTripper *productionGatewayProxyRoundTripper) pinned(ctx context.Context) (string, string, error) {
	if roundTripper == nil || ctx == nil || ctx.Err() != nil || roundTripper.upstream == nil || !validGatewayProxyHostname(roundTripper.upstream.Hostname()) || len(roundTripper.networks) < 1 || roundTripper.resolver == nil || roundTripper.factory == nil {
		return "", "", errRuntimeUnavailable
	}
	host := roundTripper.upstream.Hostname()
	addresses, err := roundTripper.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) < 1 || len(addresses) > 32 {
		return "", "", errRuntimeUnavailable
	}
	values := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if !validGatewayProxyIP(address.IP) || !gatewayProxyIPAllowed(address.IP, roundTripper.networks) {
			return "", "", errRuntimeUnavailable
		}
		value := address.IP.String()
		if _, duplicate := seen[value]; !duplicate {
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return "", "", errRuntimeUnavailable
	}
	sort.Strings(values)
	return host, values[0], nil
}

func productionGatewayProxyTransport(host, pinnedIP string, timeout time.Duration) http.RoundTripper {
	if !validGatewayProxyHostname(host) || !validGatewayProxyIP(net.ParseIP(pinnedIP)) || timeout < time.Second || timeout > 30*time.Second {
		return nil
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedHost, port, err := net.SplitHostPort(address)
		if err != nil || strings.ToLower(requestedHost) != host || port != "443" {
			return nil, errRuntimeUnavailable
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(pinnedIP, "443"))
	}
	return transport
}

func loadGatewayProxyToken(path string) ([]byte, error) {
	if !validGatewayPath(path, false) {
		return nil, errRuntimeUnavailable
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() < 32 || before.Size() > 4096 {
		return nil, errRuntimeUnavailable
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	value, readErr := io.ReadAll(io.LimitReader(file, 4097))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	after, afterErr := root.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || after.Mode().Perm() != 0o600 || len(value) < 32 || len(value) > 4096 || !validGatewayProxyToken(value) {
		clear(value)
		return nil, errRuntimeUnavailable
	}
	return value, nil
}

func validGatewayProxyToken(value []byte) bool {
	if len(value) < 32 || len(value) > 4096 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validGatewayProxyAuthority(rawURL string, cidrs []string) bool {
	upstream, err := url.Parse(rawURL)
	if err != nil || upstream.String() != rawURL || upstream.Scheme != "https" || !validGatewayProxyHostname(upstream.Hostname()) || upstream.Port() != "" || upstream.User != nil || upstream.Path == "" || upstream.EscapedPath() != upstream.Path || upstream.RawQuery != "" || upstream.Fragment != "" {
		return false
	}
	_, ok := parseGatewayProxyCIDRs(cidrs)
	return ok
}

func parseGatewayProxyCIDRs(values []string) ([]*net.IPNet, bool) {
	if len(values) < 1 || len(values) > 64 {
		return nil, false
	}
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || network.String() != value || !ip.Equal(network.IP) || !validGatewayProxyIP(ip) {
			return nil, false
		}
		ones, bits := network.Mask.Size()
		if bits == 32 && ones < 16 || bits == 128 && ones < 32 || bits != 32 && bits != 128 {
			return nil, false
		}
		for _, existing := range networks {
			if existing.Contains(network.IP) || network.Contains(existing.IP) {
				return nil, false
			}
		}
		networks = append(networks, network)
	}
	return networks, true
}

func validGatewayProxyHostname(host string) bool {
	if len(host) < 1 || len(host) > 253 || host != strings.ToLower(host) || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
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

func validGatewayProxyIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func gatewayProxyIPAllowed(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
