package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errInvalidOperationalConfig = errors.New("invalid operational configuration")

type edgeSecurityConfig struct {
	PublicOrigin      string
	TrustedProxyCIDRs []string
}

func newEdgeSecurityMiddleware(config edgeSecurityConfig, next http.Handler) (http.Handler, error) {
	if next == nil || len(config.TrustedProxyCIDRs) == 0 {
		return nil, errInvalidOperationalConfig
	}
	origin, err := url.Parse(config.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errInvalidOperationalConfig
	}
	networks := make([]*net.IPNet, 0, len(config.TrustedProxyCIDRs))
	for _, value := range config.TrustedProxyCIDRs {
		_, network, parseErr := net.ParseCIDR(value)
		if parseErr != nil || network.String() != value {
			return nil, errInvalidOperationalConfig
		}
		networks = append(networks, network)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !validEdgeRequest(request, origin, networks) {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, "{\"code\":\"request_rejected\",\"message\":\"Request rejected\",\"retryable\":false}\n")
			return
		}
		next.ServeHTTP(writer, request)
	}), nil
}

func validEdgeRequest(request *http.Request, origin *url.URL, networks []*net.IPNet) bool {
	if request == nil || request.URL == nil || request.Host != origin.Host || request.Header.Get("Forwarded") != "" {
		return false
	}
	if value := request.Header.Get("Origin"); value != "" && value != origin.String() {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(request.RemoteAddr)
	remoteIP := net.ParseIP(remoteHost)
	if err != nil || remoteIP == nil || !containsIP(networks, remoteIP) {
		return false
	}
	allowed := map[string]struct{}{"X-Forwarded-For": {}, "X-Forwarded-Host": {}, "X-Forwarded-Port": {}, "X-Forwarded-Proto": {}}
	for name := range request.Header {
		canonical := http.CanonicalHeaderKey(name)
		if strings.HasPrefix(canonical, "X-Forwarded-") {
			if _, ok := allowed[canonical]; !ok || len(request.Header.Values(name)) != 1 {
				return false
			}
		}
	}
	if request.Header.Get("X-Forwarded-Proto") != "https" || request.Header.Get("X-Forwarded-Host") != origin.Host || request.Header.Get("X-Forwarded-Port") != defaultHTTPSPort(origin) {
		return false
	}
	forwardedFor := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
	if len(forwardedFor) == 0 || len(forwardedFor) > 8 {
		return false
	}
	for _, entry := range forwardedFor {
		if entry != strings.TrimSpace(entry) || net.ParseIP(entry) == nil {
			return false
		}
	}
	if traceparent := request.Header.Get("Traceparent"); traceparent != "" && !validTraceparent(traceparent) {
		return false
	}
	return true
}

func defaultHTTPSPort(origin *url.URL) string {
	if origin.Port() != "" {
		return origin.Port()
	}
	return "443"
}

func containsIP(networks []*net.IPNet, address net.IP) bool {
	for _, network := range networks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

type requestLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	maximum int
	now     func() time.Time
	clients map[string]clientBucket
}

type clientBucket struct {
	tokens  float64
	updated time.Time
}

func newRequestLimiter(rate int, burst int, maximum int, now func() time.Time) *requestLimiter {
	if rate < 1 || rate > 10000 || burst < 1 || burst > 10000 || maximum < 1 || maximum > 100000 || now == nil {
		return nil
	}
	return &requestLimiter{rate: float64(rate), burst: float64(burst), maximum: maximum, now: now, clients: make(map[string]clientBucket)}
}

func (limiter *requestLimiter) allow(request *http.Request) bool {
	if limiter == nil || request == nil {
		return false
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil {
		return false
	}
	now := limiter.now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	bucket, exists := limiter.clients[host]
	if !exists {
		if len(limiter.clients) >= limiter.maximum {
			limiter.evictOldest()
		}
		bucket = clientBucket{tokens: limiter.burst, updated: now}
	}
	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens = min(limiter.burst, bucket.tokens+elapsed*limiter.rate)
	}
	bucket.updated = now
	if bucket.tokens < 1 {
		limiter.clients[host] = bucket
		return false
	}
	bucket.tokens--
	limiter.clients[host] = bucket
	return true
}

func (limiter *requestLimiter) evictOldest() {
	var key string
	var oldest time.Time
	for candidate, bucket := range limiter.clients {
		if key == "" || bucket.updated.Before(oldest) {
			key, oldest = candidate, bucket.updated
		}
	}
	delete(limiter.clients, key)
}

type operationalMetrics struct {
	mu               sync.Mutex
	requests         map[string]uint64
	duration         map[string]float64
	rateLimited      atomic.Uint64
	authRejected     atomic.Uint64
	dependencyErrors atomic.Uint64
}

func newOperationalMetrics() *operationalMetrics {
	return &operationalMetrics{requests: make(map[string]uint64), duration: make(map[string]float64)}
}

func (metrics *operationalMetrics) observe(method, route string, status int, duration time.Duration) {
	if metrics == nil {
		return
	}
	key := method + "\x00" + route + "\x00" + strconv.Itoa(status/100) + "xx"
	metrics.mu.Lock()
	metrics.requests[key]++
	metrics.duration[key] += duration.Seconds()
	metrics.mu.Unlock()
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		metrics.authRejected.Add(1)
	}
	if status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
		metrics.dependencyErrors.Add(1)
	}
}

func (metrics *operationalMetrics) Prometheus() string {
	if metrics == nil {
		return ""
	}
	metrics.mu.Lock()
	keys := make([]string, 0, len(metrics.requests))
	for key := range metrics.requests {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var output strings.Builder
	output.WriteString("# HELP zasp_http_requests_total Product API requests.\n# TYPE zasp_http_requests_total counter\n")
	for _, key := range keys {
		parts := strings.Split(key, "\x00")
		fmt.Fprintf(&output, "zasp_http_requests_total{method=%q,route=%q,status_class=%q} %d\n", parts[0], parts[1], parts[2], metrics.requests[key])
	}
	output.WriteString("# HELP zasp_http_request_duration_seconds Product API request duration.\n# TYPE zasp_http_request_duration_seconds counter\n")
	for _, key := range keys {
		parts := strings.Split(key, "\x00")
		fmt.Fprintf(&output, "zasp_http_request_duration_seconds{method=%q,route=%q,status_class=%q} %.6f\n", parts[0], parts[1], parts[2], metrics.duration[key])
	}
	metrics.mu.Unlock()
	fmt.Fprintf(&output, "# HELP zasp_http_rate_limited_total Rejected requests.\n# TYPE zasp_http_rate_limited_total counter\nzasp_http_rate_limited_total %d\n", metrics.rateLimited.Load())
	fmt.Fprintf(&output, "# HELP zasp_auth_rejections_total Authentication and authorization rejections.\n# TYPE zasp_auth_rejections_total counter\nzasp_auth_rejections_total %d\n", metrics.authRejected.Load())
	fmt.Fprintf(&output, "# HELP zasp_dependency_errors_total Bounded dependency failures.\n# TYPE zasp_dependency_errors_total counter\nzasp_dependency_errors_total %d\n", metrics.dependencyErrors.Load())
	return output.String()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) Unwrap() http.ResponseWriter { return recorder.ResponseWriter }

func (recorder *statusRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
	recorder.ResponseWriter.WriteHeader(status)
}
func (recorder *statusRecorder) Write(value []byte) (int, error) {
	if recorder.status == 0 {
		recorder.WriteHeader(http.StatusOK)
	}
	return recorder.ResponseWriter.Write(value)
}

func newOperationalMiddleware(output io.Writer, metrics *operationalMetrics, limiter *requestLimiter, next http.Handler) (http.Handler, error) {
	if output == nil || metrics == nil || limiter == nil || next == nil {
		return nil, errInvalidOperationalConfig
	}
	logger := &operationalLogger{output: output}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		traceID, spanID := requestTrace(request)
		writer.Header().Set("Traceparent", "00-"+traceID+"-"+spanID+"-01")
		writer.Header().Set("X-Correlation-ID", generateCorrelationID())
		if !limiter.allow(request) {
			metrics.rateLimited.Add(1)
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusTooManyRequests)
			logger.write(request, http.StatusTooManyRequests, started, writer.Header().Get("X-Correlation-ID"), traceID, spanID)
			return
		}
		recorder := &statusRecorder{ResponseWriter: writer}
		next.ServeHTTP(recorder, request)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		route := operationalRoute(request.URL.Path)
		metrics.observe(request.Method, route, recorder.status, time.Since(started))
		logger.write(request, recorder.status, started, recorder.Header().Get("X-Correlation-ID"), traceID, spanID)
	}), nil
}

type operationalLogger struct {
	mu     sync.Mutex
	output io.Writer
}

func (logger *operationalLogger) write(request *http.Request, status int, started time.Time, correlationID, traceID, spanID string) {
	entry := map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "severity": "INFO", "event": "http_request", "method": request.Method, "route": operationalRoute(request.URL.Path), "status": status, "duration_ms": time.Since(started).Milliseconds(), "correlation_id": correlationID, "trace_id": traceID, "span_id": spanID}
	logger.mu.Lock()
	_ = json.NewEncoder(logger.output).Encode(entry)
	logger.mu.Unlock()
}

func operationalRoute(value string) string {
	segments := strings.Split(strings.Trim(value, "/"), "/")
	if len(segments) < 3 || segments[0] != "api" || segments[1] != "v1" {
		return "/unmatched"
	}
	route := "/api/v1/" + safeMetricLabel(segments[2])
	if len(segments) > 3 {
		route += "/:resource"
	}
	return route
}

func safeMetricLabel(value string) string {
	if value == "" || len(value) > 64 {
		return "unknown"
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && character != '-' {
			return "unknown"
		}
	}
	return value
}

func requestTrace(request *http.Request) (string, string) {
	if request != nil {
		value := request.Header.Get("Traceparent")
		if validTraceparent(value) {
			return value[3:35], value[36:52]
		}
	}
	return randomHex(16), randomHex(8)
}

func validTraceparent(value string) bool {
	if len(value) != 55 || value[0:3] != "00-" || value[35] != '-' || value[52] != '-' || value[53:] != "00" && value[53:] != "01" {
		return false
	}
	for _, portion := range []string{value[3:35], value[36:52]} {
		if strings.Trim(portion, "0") == "" {
			return false
		}
		if _, err := hex.DecodeString(portion); err != nil {
			return false
		}
	}
	return true
}

func randomHex(size int) string {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return strings.Repeat("f", size*2)
	}
	return hex.EncodeToString(value)
}
