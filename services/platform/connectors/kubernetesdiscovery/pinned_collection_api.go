package kubernetesdiscovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"sort"
	"time"
)

// PinnedCollectionAPIConfig is the production customer-edge authority. Every
// DNS answer must remain inside an operator-supplied CIDR before a connection
// is made; TLS continues to authenticate the original endpoint hostname.
type PinnedCollectionAPIConfig struct {
	Endpoint     string
	CABundlePEM  []byte
	AllowedCIDRs []string
	Timeout      time.Duration
}

type pinnedCollectionResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type pinnedCollectionDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func NewPinnedKubernetesCollectionAPI(config PinnedCollectionAPIConfig) (*KubernetesCollectionAPI, error) {
	dialer := &net.Dialer{Timeout: config.Timeout, KeepAlive: -1}
	return newPinnedKubernetesCollectionAPI(config, net.DefaultResolver, dialer)
}

func newPinnedKubernetesCollectionAPI(config PinnedCollectionAPIConfig, resolver pinnedCollectionResolver, dialer pinnedCollectionDialer) (*KubernetesCollectionAPI, error) {
	parsed, ok := parseKubernetesCollectionEndpoint(config.Endpoint)
	networks, networksOK := parsePinnedCollectionCIDRs(config.AllowedCIDRs)
	pool, caOK := pinnedCollectionCertPool(config.CABundlePEM)
	if !ok || !networksOK || !caOK || resolver == nil || dialer == nil || config.Timeout < 100*time.Millisecond || config.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	host := parsed.Hostname()
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host},
		TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 * 1024,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		requestedHost, port, splitErr := net.SplitHostPort(address)
		if ctx == nil || ctx.Err() != nil || splitErr != nil || network != "tcp" || requestedHost != host || port != "443" {
			return nil, ErrDenied
		}
		addresses, lookupErr := resolver.LookupIPAddr(ctx, host)
		if lookupErr != nil || len(addresses) < 1 || len(addresses) > 16 {
			return nil, ErrDenied
		}
		values := make([]string, 0, len(addresses))
		seen := make(map[string]struct{}, len(addresses))
		for _, answer := range addresses {
			ip := answer.IP
			if ip == nil || answer.Zone != "" || !pinnedCollectionIPAllowed(ip, networks) {
				return nil, ErrDenied
			}
			text := ip.String()
			if _, duplicate := seen[text]; duplicate {
				return nil, ErrDenied
			}
			seen[text] = struct{}{}
			values = append(values, text)
		}
		sort.Slice(values, func(left, right int) bool {
			leftV4 := net.ParseIP(values[left]).To4() != nil
			rightV4 := net.ParseIP(values[right]).To4() != nil
			if leftV4 != rightV4 {
				return leftV4
			}
			return values[left] < values[right]
		})
		connection, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(values[0], "443"))
		if dialErr != nil || ctx.Err() != nil {
			if connection != nil {
				_ = connection.Close()
			}
			return nil, ErrDenied
		}
		return connection, nil
	}
	return newKubernetesCollectionAPI(config.Endpoint, transport, config.Timeout)
}

func parsePinnedCollectionCIDRs(values []string) ([]*net.IPNet, bool) {
	if len(values) < 1 || len(values) > 32 {
		return nil, false
	}
	result := make([]*net.IPNet, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip == nil || network.String() != value {
			return nil, false
		}
		ones, bits := network.Mask.Size()
		if ones < 1 || bits != 32 && bits != 128 || bits == 32 && ones < 8 || bits == 128 && ones < 32 {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		seen[value] = struct{}{}
		result = append(result, network)
	}
	return result, true
}

func pinnedCollectionIPAllowed(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func pinnedCollectionCertPool(value []byte) (*x509.CertPool, bool) {
	if len(value) < 64 || len(value) > 32<<10 {
		return nil, false
	}
	pool := x509.NewCertPool()
	rest := bytes.Clone(value)
	certificates := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			clear(rest)
			return nil, false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		clear(block.Bytes)
		if err != nil {
			clear(rest)
			return nil, false
		}
		pool.AddCert(certificate)
		certificates++
		rest = remaining
	}
	return pool, certificates >= 1 && certificates <= 32
}
