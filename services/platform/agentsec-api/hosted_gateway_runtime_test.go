package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The hosted gateway is off unless the deployment turns it on, and its
// timeout is only read when it is on.
func TestRuntimeConfigHostsTheGatewayOnlyOnRequest(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	load := func(change map[string]string) (RuntimeConfig, error) {
		selected := mapsClone(values)
		for key, value := range change {
			selected[key] = value
		}
		return loadRuntimeConfig(func(key string) string { return selected[key] })
	}
	config, err := load(nil)
	if err != nil || config.HostedGatewayEnabled || config.HostedGatewayTimeout != 0 || hostedGatewayBodyLimit(config) != 0 {
		t.Fatalf("default config hosts the gateway: %v %v %v", config.HostedGatewayEnabled, config.HostedGatewayTimeout, err)
	}
	config, err = load(map[string]string{"ZASP_HOSTED_GATEWAY_ENABLED": "false"})
	if err != nil || config.HostedGatewayEnabled {
		t.Fatalf("an explicit false: %v %v", config.HostedGatewayEnabled, err)
	}
	config, err = load(map[string]string{"ZASP_HOSTED_GATEWAY_ENABLED": "true"})
	if err != nil || !config.HostedGatewayEnabled || config.HostedGatewayTimeout != 5*time.Minute || hostedGatewayBodyLimit(config) != 4<<20 {
		t.Fatalf("enabled with defaults: %+v %v", config.HostedGatewayTimeout, err)
	}
	config, err = load(map[string]string{"ZASP_HOSTED_GATEWAY_ENABLED": "true", "ZASP_HOSTED_GATEWAY_TIMEOUT": "90s"})
	if err != nil || config.HostedGatewayTimeout != 90*time.Second {
		t.Fatalf("enabled with a timeout: %v %v", config.HostedGatewayTimeout, err)
	}
	for name, change := range map[string]map[string]string{
		"a value that is not a boolean":      {"ZASP_HOSTED_GATEWAY_ENABLED": "yes please"},
		"a timeout that is not a duration":   {"ZASP_HOSTED_GATEWAY_ENABLED": "true", "ZASP_HOSTED_GATEWAY_TIMEOUT": "soon"},
		"a timeout under ten seconds":        {"ZASP_HOSTED_GATEWAY_ENABLED": "true", "ZASP_HOSTED_GATEWAY_TIMEOUT": "2s"},
		"a timeout over thirty minutes":      {"ZASP_HOSTED_GATEWAY_ENABLED": "true", "ZASP_HOSTED_GATEWAY_TIMEOUT": "2h"},
		"a timeout for a gateway that's off": {"ZASP_HOSTED_GATEWAY_TIMEOUT": "90s"},
	} {
		if _, err := load(change); !errors.Is(err, errInvalidRuntimeConfig) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

// A request of the gateway's traffic routes is bounded by the gateway's
// timeout; every other request keeps the product API's.
func TestOperationalMiddlewareGivesGatewayTrafficItsOwnDeadline(t *testing.T) {
	remaining := map[string]time.Duration{}
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		deadline, ok := request.Context().Deadline()
		if ok {
			remaining[request.URL.Path] = time.Until(deadline)
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	build := func(gatewayTimeout time.Duration) http.Handler {
		handler, err := newGatewayOperationalMiddleware(&bytes.Buffer{}, newOperationalMetrics(), newRequestLimiter(100, 100, 100, time.Now), 10*time.Second, gatewayTimeout, &captureSpanExporter{}, next)
		if err != nil {
			t.Fatal(err)
		}
		return handler
	}
	send := func(handler http.Handler, path string) {
		request := httptest.NewRequest(http.MethodPost, "https://app.zasp.example"+path, nil)
		request.RemoteAddr = "192.0.2.8:4312"
		request = request.WithContext(context.WithValue(request.Context(), verifiedClientContextKey{}, "192.0.2.8"))
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	paths := []string{"/api/v1/gateway/llm/v1/chat/completions", "/api/v1/gateway/mcp/pid_61000001-0000-4000-8000-000000000001", "/api/v1/gateway/policy", "/api/v1/gateway/mcp-servers/pid_61000001-0000-4000-8000-000000000001", "/api/v1/findings"}
	hosted := build(5 * time.Minute)
	for _, path := range paths {
		send(hosted, path)
	}
	for index, path := range paths {
		traffic := index < 2
		if got := remaining[path]; traffic != (got > 5*time.Minute && got <= 5*time.Minute+30*time.Second) || !traffic && (got <= 0 || got > 10*time.Second) {
			t.Errorf("%s: deadline in %v", path, got)
		}
	}
	// Where the gateway is not hosted its paths are ordinary requests.
	remaining = map[string]time.Duration{}
	plain := build(0)
	for _, path := range paths {
		send(plain, path)
		if got := remaining[path]; got <= 0 || got > 10*time.Second {
			t.Errorf("%s without the gateway: deadline in %v", path, got)
		}
	}
	if _, err := newGatewayOperationalMiddleware(&bytes.Buffer{}, newOperationalMetrics(), newRequestLimiter(1, 1, 1, time.Now), 10*time.Second, time.Hour, &captureSpanExporter{}, next); !errors.Is(err, errInvalidOperationalConfig) {
		t.Fatalf("a gateway timeout over thirty minutes: %v", err)
	}
	// The gateway's requests are measured under their own route.
	if operationalRoute("/api/v1/gateway/llm/v1/messages") != "/api/v1/gateway/:resource" {
		t.Fatalf("route=%s", operationalRoute("/api/v1/gateway/llm/v1/messages"))
	}
}
