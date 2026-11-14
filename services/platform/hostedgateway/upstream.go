package hostedgateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/publicaddress"
)

// ErrUpstreamAddress is returned when an upstream resolves to an address the
// gateway does not connect to.
var ErrUpstreamAddress = errors.New("upstream address is not public")

// UpstreamConfig bounds the gateway's outbound connections.
type UpstreamConfig struct {
	// AllowAddress decides whether the gateway connects to an address. It is
	// asked for the address of every connection, after name resolution, so a
	// name that resolves to a private address, or that changes its answer
	// between a check and the connection, cannot be reached. Nil means
	// public addresses only.
	AllowAddress func(net.IP) bool
	// RootCAs are the certificate authorities an upstream's certificate
	// must chain to. Nil means the system's.
	RootCAs *x509.CertPool
	// ResponseHeaderTimeout bounds the wait for an upstream's first byte.
	ResponseHeaderTimeout time.Duration
}

// NewUpstreamClient returns the HTTP client of the gateway's outbound
// requests: TLS 1.2 or later, no proxy, no redirects (a redirect could name
// another host), and no connection to an address AllowAddress refuses.
func NewUpstreamClient(config UpstreamConfig) *http.Client {
	allow := config.AllowAddress
	if allow == nil {
		allow = publicaddress.IsPublic
	}
	timeout := config.ResponseHeaderTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrUpstreamAddress
		}
		if ip := net.ParseIP(host); ip == nil || !allow(ip) {
			return ErrUpstreamAddress
		}
		return nil
	}}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.RootCAs},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConns: 256, MaxIdleConnsPerHost: 32, IdleConnTimeout: 90 * time.Second,
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ValidUpstreamURL reports whether value may be registered as the address of
// an upstream MCP server: an https URL on the default port, with a host, no
// credentials, no query and no fragment. A query is refused because keys are
// often put there and the address is stored and shown; the upstream's
// credential travels in a request header instead and is never stored. The
// host is returned in lower case.
func ValidUpstreamURL(value string) (string, bool) {
	if len(value) < 12 || len(value) > 2048 || strings.ContainsAny(value, " \t\r\n\\") {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Host == "" {
		return "", false
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		if !publicaddress.IsPublic(ip) {
			return "", false
		}
		return host, true
	}
	if !strings.Contains(host, ".") {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return "", false
			}
		}
	}
	return host, true
}

// RateLimiter admits a number of requests a minute for each key (an API
// token). It is a token bucket in the memory of one process: with several
// replicas each admits the rate, so the Environment's effective limit is the
// rate times the replicas that serve the token.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
	now     func() time.Time
}

type rateBucket struct {
	tokens float64
	seen   time.Time
}

// NewRateLimiter returns an empty limiter.
func NewRateLimiter(now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{buckets: map[string]*rateBucket{}, now: now}
}

// Allow takes one request of key's bucket. perMinute is the bucket's size
// and what it refills in a minute; zero or less means no limit.
func (limiter *RateLimiter) Allow(key string, perMinute int) bool {
	if limiter == nil || perMinute <= 0 {
		return true
	}
	now := limiter.now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.buckets) >= 10000 {
		for name, bucket := range limiter.buckets {
			if now.Sub(bucket.seen) > 2*time.Minute {
				delete(limiter.buckets, name)
			}
		}
		if len(limiter.buckets) >= 10000 {
			// More live keys than the limiter holds: refuse the new one
			// rather than admit it unlimited.
			if _, known := limiter.buckets[key]; !known {
				return false
			}
		}
	}
	bucket, known := limiter.buckets[key]
	if !known {
		bucket = &rateBucket{tokens: float64(perMinute), seen: now}
		limiter.buckets[key] = bucket
	}
	bucket.tokens += now.Sub(bucket.seen).Seconds() * float64(perMinute) / 60
	if bucket.tokens > float64(perMinute) {
		bucket.tokens = float64(perMinute)
	}
	bucket.seen = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func boundedContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return context.WithTimeout(parent, timeout)
}
