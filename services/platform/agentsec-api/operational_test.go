package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEdgeSecurityAcceptsOnlyExactTrustedTLSForwarding(t *testing.T) {
	config := edgeSecurityConfig{PublicOrigin: "https://app.zasp.example", TrustedProxyCIDRs: []string{"10.20.0.0/16"}}
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	handler, err := newEdgeSecurityMiddleware(config, next)
	if err != nil {
		t.Fatal(err)
	}

	accepted := edgeRequest("10.20.4.8:4312")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, accepted)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}

	for name, mutate := range map[string]func(*http.Request){
		"host":           func(request *http.Request) { request.Host = "evil.example" },
		"origin":         func(request *http.Request) { request.Header.Set("Origin", "https://evil.example") },
		"proxy":          func(request *http.Request) { request.RemoteAddr = "10.21.0.2:1234" },
		"proto":          func(request *http.Request) { request.Header.Set("X-Forwarded-Proto", "http") },
		"forwarded host": func(request *http.Request) { request.Header.Set("X-Forwarded-Host", "evil.example") },
		"forwarded port": func(request *http.Request) { request.Header.Set("X-Forwarded-Port", "80") },
		"forwarded for":  func(request *http.Request) { request.Header.Set("X-Forwarded-For", "victim.example") },
		"raw forwarded": func(request *http.Request) {
			request.Header.Set("Forwarded", "for=192.0.2.1;proto=https;host=evil.example")
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := edgeRequest("10.20.4.8:4312")
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

func TestOperationalMiddlewareRedactsAndBoundsTraffic(t *testing.T) {
	var logs bytes.Buffer
	metrics := newOperationalMetrics()
	limiter := newRequestLimiter(1, 1, 1024, func() time.Time { return time.Unix(100, 0) })
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Correlation-ID", "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
		writer.WriteHeader(http.StatusNoContent)
	})
	handler, err := newOperationalMiddleware(&logs, metrics, limiter, next)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "https://app.zasp.example/api/v1/findings/pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa?token=secret-token", nil)
	request.RemoteAddr = "192.0.2.8:4312"
	request.Header.Set("Authorization", "Bearer secret-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, request.Clone(request.Context()))
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked status = %d", blocked.Code)
	}
	if strings.Contains(logs.String(), "secret-token") || strings.Contains(logs.String(), "pid_aaaaaaaa") {
		t.Fatalf("sensitive log: %s", logs.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))[0], &entry); err != nil {
		t.Fatal(err)
	}
	if entry["route"] != "/api/v1/findings/:resource" || entry["correlation_id"] == "" || entry["trace_id"] == "" {
		t.Fatalf("entry = %#v", entry)
	}
	payload := metrics.Prometheus()
	for _, metric := range []string{"zasp_http_requests_total", "zasp_http_request_duration_seconds", "zasp_http_rate_limited_total", "zasp_auth_rejections_total", "zasp_dependency_errors_total"} {
		if !strings.Contains(payload, metric) {
			t.Fatalf("metrics missing %s: %s", metric, payload)
		}
	}
}

func edgeRequest(remote string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.example/api/v1/home/summary", nil)
	request.Host = "app.zasp.example"
	request.RemoteAddr = remote
	request.Header.Set("Origin", "https://app.zasp.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "app.zasp.example")
	request.Header.Set("X-Forwarded-Port", "443")
	request.Header.Set("X-Forwarded-For", "192.0.2.20")
	return request
}
