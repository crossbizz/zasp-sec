package health

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	testService = "agentsec-api"
	testVersion = "1.2.3-rc_1+build"
)

type responseExpectation struct {
	status                int
	body                  string
	contentType           string
	allow                 string
	contentLengthOverride int
}

func TestHandlerDistinguishesLivenessReadinessVersionAndMetrics(t *testing.T) {
	handler := newTestHandler(t)

	assertResponse(t, handler, http.MethodGet, LivenessPath, responseExpectation{
		status:      http.StatusOK,
		body:        "{\"status\":\"live\"}\n",
		contentType: "application/json; charset=utf-8",
	})
	assertResponse(t, handler, http.MethodGet, ReadinessPath, responseExpectation{
		status:      http.StatusServiceUnavailable,
		body:        "{\"status\":\"not_ready\"}\n",
		contentType: "application/json; charset=utf-8",
	})
	assertResponse(t, handler, http.MethodGet, VersionPath, responseExpectation{
		status:      http.StatusOK,
		body:        "{\"service\":\"agentsec-api\",\"version\":\"1.2.3-rc_1+build\"}\n",
		contentType: "application/json; charset=utf-8",
	})
	assertResponse(t, handler, http.MethodGet, MetricsPath, responseExpectation{
		status:      http.StatusOK,
		body:        metricsBody("0"),
		contentType: "text/plain; version=0.0.4; charset=utf-8",
	})

	handler.SetReady(true)
	assertResponse(t, handler, http.MethodGet, LivenessPath, responseExpectation{
		status:      http.StatusOK,
		body:        "{\"status\":\"live\"}\n",
		contentType: "application/json; charset=utf-8",
	})
	assertResponse(t, handler, http.MethodGet, ReadinessPath, responseExpectation{
		status:      http.StatusOK,
		body:        "{\"status\":\"ready\"}\n",
		contentType: "application/json; charset=utf-8",
	})
	assertResponse(t, handler, http.MethodGet, MetricsPath, responseExpectation{
		status:      http.StatusOK,
		body:        metricsBody("1"),
		contentType: "text/plain; version=0.0.4; charset=utf-8",
	})

	handler.SetReady(false)
	assertResponse(t, handler, http.MethodGet, ReadinessPath, responseExpectation{
		status:      http.StatusServiceUnavailable,
		body:        "{\"status\":\"not_ready\"}\n",
		contentType: "application/json; charset=utf-8",
	})
}

func TestHandlerExactMethodsPathsHeadersAndHead(t *testing.T) {
	handler := newTestHandler(t)
	handler.SetReady(true)

	for _, test := range []struct {
		name     string
		path     string
		body     string
		typeName string
	}{
		{name: "liveness", path: LivenessPath, body: "{\"status\":\"live\"}\n", typeName: "application/json; charset=utf-8"},
		{name: "readiness", path: ReadinessPath, body: "{\"status\":\"ready\"}\n", typeName: "application/json; charset=utf-8"},
		{name: "version", path: VersionPath, body: "{\"service\":\"agentsec-api\",\"version\":\"1.2.3-rc_1+build\"}\n", typeName: "application/json; charset=utf-8"},
		{name: "metrics", path: MetricsPath, body: metricsBody("1"), typeName: "text/plain; version=0.0.4; charset=utf-8"},
	} {
		t.Run(test.name+" head", func(t *testing.T) {
			assertResponse(t, handler, http.MethodHead, test.path, responseExpectation{
				status:                http.StatusOK,
				body:                  "",
				contentType:           test.typeName,
				contentLengthOverride: len(test.body),
			})
		})
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, "TRACE"} {
		t.Run("method "+method, func(t *testing.T) {
			assertResponse(t, handler, method, LivenessPath, responseExpectation{
				status: http.StatusMethodNotAllowed,
				allow:  "GET, HEAD",
			})
		})
	}

	for _, test := range []struct {
		name    string
		target  string
		rawPath string
	}{
		{name: "root", target: "/"},
		{name: "unknown", target: "/unknown"},
		{name: "trailing slash", target: "/healthz/"},
		{name: "query", target: "/healthz?probe=1"},
		{name: "escaped path", target: "/health%7A", rawPath: "/health%7A"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.URL.RawPath = test.rawPath
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertRecorder(t, response, responseExpectation{status: http.StatusNotFound})
		})
	}

	assertResponse(t, handler, http.MethodPost, "/unknown", responseExpectation{status: http.StatusNotFound})
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	testServices := []string{"a", "0", "agentsec", "agentsec-api", "a1-b2", strings.Repeat("a", 64)}
	testVersions := []string{"0", "dev", "V1", "1.2.3", "1.2.3-rc_1+build", "a-", strings.Repeat("a", 64)}

	for _, service := range testServices {
		t.Run("valid service "+service, func(t *testing.T) {
			handler, err := New(Config{Service: service, Version: testVersion})
			if err != nil || handler == nil {
				t.Fatalf("New() = (%v, %v), want non-nil handler and nil error", handler, err)
			}
		})
	}
	for _, version := range testVersions {
		t.Run("valid version "+version, func(t *testing.T) {
			handler, err := New(Config{Service: testService, Version: version})
			if err != nil || handler == nil {
				t.Fatalf("New() = (%v, %v), want non-nil handler and nil error", handler, err)
			}
		})
	}

	intestServices := map[string]string{
		"empty":               "",
		"too long":            strings.Repeat("a", 65),
		"uppercase":           "Agentsec",
		"space":               "agent sec",
		"slash":               "agent/sec",
		"underscore":          "agent_sec",
		"leading hyphen":      "-agentsec",
		"trailing hyphen":     "agentsec-",
		"double hyphen":       "agent--sec",
		"control":             "agent\nsec",
		"non ascii":           "agéntsec",
		"prometheus escaping": `agent\"sec`,
	}
	intestVersions := map[string]string{
		"empty":              "",
		"too long":           strings.Repeat("a", 65),
		"leading dot":        ".1",
		"leading underscore": "_1",
		"leading plus":       "+1",
		"leading hyphen":     "-1",
		"space":              "1 2",
		"slash":              "1/2",
		"quote":              `1\"2`,
		"control":            "1\n2",
		"non ascii":          "vérsion",
	}

	for name, service := range intestServices {
		t.Run("invalid service "+name, func(t *testing.T) {
			assertInvalidConfig(t, Config{Service: service, Version: testVersion})
		})
	}
	for name, version := range intestVersions {
		t.Run("invalid version "+name, func(t *testing.T) {
			assertInvalidConfig(t, Config{Service: testService, Version: version})
		})
	}
}

func TestHandlerConcurrentReadiness(t *testing.T) {
	handler := newTestHandler(t)
	const workers = 16
	const iterations = 250

	errorsChannel := make(chan error, workers*iterations)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				if worker%2 == 0 {
					handler.SetReady(iteration%2 == 0)
					continue
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, ReadinessPath, nil))
				projection := fmt.Sprintf("%d:%s", response.Code, response.Body.String())
				if projection != "200:{\"status\":\"ready\"}\n" && projection != "503:{\"status\":\"not_ready\"}\n" {
					errorsChannel <- fmt.Errorf("unexpected readiness projection %q", projection)
				}
			}
		}(worker)
	}
	close(start)
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	handler, err := New(Config{Service: testService, Version: testVersion})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if handler == nil {
		t.Fatal("New() returned a nil handler")
	}
	return handler
}

func assertInvalidConfig(t *testing.T, config Config) {
	t.Helper()
	handler, err := New(config)
	if handler != nil {
		t.Fatalf("New(%+v) handler = %v, want nil", config, handler)
	}
	if !errors.Is(err, ErrInvalidConfig) || err != ErrInvalidConfig {
		t.Fatalf("New(%+v) error = %v, want exact ErrInvalidConfig", config, err)
	}
}

func assertResponse(t *testing.T, handler http.Handler, method, target string, expectation responseExpectation) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, target, nil))
	assertRecorder(t, response, expectation)
}

func assertRecorder(t *testing.T, response *httptest.ResponseRecorder, expectation responseExpectation) {
	t.Helper()
	if response.Code != expectation.status {
		t.Errorf("status = %d, want %d", response.Code, expectation.status)
	}
	if got := response.Body.String(); got != expectation.body {
		t.Errorf("body = %q, want %q", got, expectation.body)
	}
	if got := response.Header().Get("Content-Type"); got != expectation.contentType {
		t.Errorf("Content-Type = %q, want %q", got, expectation.contentType)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	wantLength := len(expectation.body)
	if expectation.contentLengthOverride > 0 {
		wantLength = expectation.contentLengthOverride
	}
	if got := response.Header().Get("Content-Length"); got != strconv.Itoa(wantLength) {
		t.Errorf("Content-Length = %q, want %d", got, wantLength)
	}
	if got := response.Header().Get("Allow"); got != expectation.allow {
		t.Errorf("Allow = %q, want %q", got, expectation.allow)
	}
	if got := response.Header().Values("Content-Type"); len(got) > 1 {
		t.Errorf("Content-Type values = %v, want at most one", got)
	}
}

func metricsBody(ready string) string {
	return "# HELP agentsec_up Process liveness.\n" +
		"# TYPE agentsec_up gauge\n" +
		"agentsec_up{service=\"agentsec-api\"} 1\n" +
		"# HELP agentsec_ready Service readiness.\n" +
		"# TYPE agentsec_ready gauge\n" +
		"agentsec_ready{service=\"agentsec-api\"} " + ready + "\n" +
		"# HELP agentsec_build_info Build information.\n" +
		"# TYPE agentsec_build_info gauge\n" +
		"agentsec_build_info{service=\"agentsec-api\",version=\"1.2.3-rc_1+build\"} 1\n"
}
