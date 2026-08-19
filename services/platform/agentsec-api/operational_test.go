package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
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
	exporter := &captureSpanExporter{}
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Correlation-ID", "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
		writer.WriteHeader(http.StatusNoContent)
	})
	handler, err := newOperationalMiddleware(&logs, metrics, limiter, 2*time.Second, exporter, next)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "https://app.zasp.example/api/v1/findings/pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa?token=secret-token", nil)
	request.RemoteAddr = "192.0.2.8:4312"
	request = request.WithContext(context.WithValue(request.Context(), verifiedClientContextKey{}, "192.0.2.8"))
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
	if !strings.Contains(logs.String(), `"event":"audit_outcome"`) {
		t.Fatalf("structured audit outcome missing: %s", logs.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))[0], &entry); err != nil {
		t.Fatal(err)
	}
	if entry["route"] != "/api/v1/findings/:resource" || entry["correlation_id"] == "" || entry["trace_id"] == "" {
		t.Fatalf("entry = %#v", entry)
	}
	payload := metrics.Prometheus()
	for _, metric := range []string{"zasp_http_requests_total", "zasp_http_request_duration_seconds_bucket", "zasp_http_request_duration_seconds_sum", "zasp_http_request_duration_seconds_count", "zasp_http_rate_limited_total", "zasp_auth_rejections_total", "zasp_dependency_operations_total", "zasp_job_operations_total", "zasp_postgres_pool_connections"} {
		if !strings.Contains(payload, metric) {
			t.Fatalf("metrics missing %s: %s", metric, payload)
		}
	}
	if !strings.Contains(payload, `le="+Inf"`) || len(exporter.spans) != 2 || exporter.spans[0].Name != "http.request" || exporter.spans[0].Kind != "server" || exporter.spans[1].Attributes["http.response.status_code"] != "429" {
		t.Fatalf("histogram/spans = %s / %#v", payload, exporter.spans)
	}
}

func TestRepositoryAndProviderBoundariesExportChildSpansAndMetrics(t *testing.T) {
	exporter := &captureSpanExporter{}
	metrics := newOperationalMetrics()
	trace := operationalTraceContext{TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef"}
	ctx := context.WithValue(context.Background(), operationalTraceContextKey{}, trace)
	database := &tracedJSONDatabase{next: boundaryDatabase{}, metrics: metrics, exporter: exporter}
	provider := &tracedCallbackProvider{next: apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
		return apiserver.SessionGrant{}, nil
	}), metrics: metrics, exporter: exporter}

	if _, err := database.SchemaVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.QueryJSON(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if err := database.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Complete(ctx, "code", "state"); err != nil {
		t.Fatal(err)
	}
	if err := provider.Ready(ctx); err != nil {
		t.Fatal(err)
	}

	if len(exporter.spans) != 5 {
		t.Fatalf("spans = %#v", exporter.spans)
	}
	for _, span := range exporter.spans {
		if span.TraceID != trace.TraceID || span.ParentSpanID != trace.SpanID || span.Kind != "client" {
			t.Fatalf("span = %#v", span)
		}
	}
	payload := metrics.Prometheus()
	for _, line := range []string{
		`zasp_dependency_operations_total{kind="repository",outcome="succeeded"} 3`,
		`zasp_dependency_operations_total{kind="provider",outcome="succeeded"} 2`,
	} {
		if !strings.Contains(payload, line) {
			t.Fatalf("metrics missing %q: %s", line, payload)
		}
	}
}

type boundaryDatabase struct{}

func (boundaryDatabase) SchemaVersion(context.Context) (string, error) {
	return apiserver.CoreSchemaVersion, nil
}
func (boundaryDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}
func (boundaryDatabase) Exec(context.Context, string, ...any) error { return nil }

func TestTrustedForwardedClientDrivesSpoofProofRateLimit(t *testing.T) {
	metrics := newOperationalMetrics()
	operational, err := newOperationalMiddleware(&bytes.Buffer{}, metrics, newRequestLimiter(1, 1, 32, func() time.Time { return time.Unix(100, 0) }), time.Second, &captureSpanExporter{}, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newEdgeSecurityMiddleware(edgeSecurityConfig{PublicOrigin: "https://app.zasp.example", TrustedProxyCIDRs: []string{"10.20.0.0/16"}}, operational)
	if err != nil {
		t.Fatal(err)
	}
	for index, forwarded := range []string{"198.51.100.10", "198.51.100.11", "203.0.113.99,198.51.100.11"} {
		request := edgeRequest("10.20.4.8:4312")
		request.Header.Set("X-Forwarded-For", forwarded)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := []int{http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests}[index]
		if response.Code != want {
			t.Fatalf("request %d status = %d, want %d", index, response.Code, want)
		}
	}
}

func TestOperationalMiddlewarePropagatesBoundedRequestDeadline(t *testing.T) {
	observed := make(chan time.Time, 1)
	next := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			observed <- time.Time{}
			return
		}
		observed <- deadline
		<-request.Context().Done()
	})
	handler, err := newOperationalMiddleware(&bytes.Buffer{}, newOperationalMetrics(), newRequestLimiter(1, 1, 1, time.Now), 10*time.Millisecond, &captureSpanExporter{}, next)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.example/api/v1/home/summary", nil)
	request.RemoteAddr = "192.0.2.8:4312"
	request = request.WithContext(context.WithValue(request.Context(), verifiedClientContextKey{}, "192.0.2.8"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if deadline := <-observed; deadline.IsZero() || response.Code != http.StatusGatewayTimeout {
		t.Fatalf("deadline/status = %v/%d", deadline, response.Code)
	}
}

type captureSpanExporter struct{ spans []operationalSpan }

func (exporter *captureSpanExporter) Export(_ context.Context, span operationalSpan) error {
	exporter.spans = append(exporter.spans, span)
	return nil
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
