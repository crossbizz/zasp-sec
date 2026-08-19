package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLoadRuntimeConfigIsStrict(t *testing.T) {
	values := map[string]string{
		"ZASP_ENVIRONMENT": "production", "ZASP_PRODUCT_LISTEN_ADDRESS": ":8080", "ZASP_INTERNAL_LISTEN_ADDRESS": ":8081",
		"ZASP_PUBLIC_ORIGIN": "https://app.zasp.example", "ZASP_COOKIE_SECURE": "true",
		"ZASP_PROVIDER_TIMEOUT": "5s", "ZASP_SHUTDOWN_TIMEOUT": "5s",
	}
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if config.ProductListenAddress != ":8080" || config.InternalListenAddress != ":8081" || config.PublicOrigin != "https://app.zasp.example" || !config.CookieSecure {
		t.Fatalf("config = %#v", config)
	}

	for _, key := range []string{"ZASP_ENVIRONMENT", "ZASP_PRODUCT_LISTEN_ADDRESS", "ZASP_INTERNAL_LISTEN_ADDRESS", "ZASP_PUBLIC_ORIGIN", "ZASP_COOKIE_SECURE", "ZASP_PROVIDER_TIMEOUT", "ZASP_SHUTDOWN_TIMEOUT"} {
		t.Run("missing "+key, func(t *testing.T) {
			copy := mapsClone(values)
			delete(copy, key)
			if _, err := loadRuntimeConfig(func(key string) string { return copy[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
				t.Fatalf("error = %v, want errInvalidRuntimeConfig", err)
			}
		})
	}
}

func TestRuntimeRejectsMemoryDependenciesInProduction(t *testing.T) {
	config := fixtureRuntimeConfig()
	dependencies := RuntimeDependencies{ProductHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), MigrationReady: true, IdentityReady: true, CompositionReady: true,
		Stores: []StoreDependency{{Name: "core", Durable: false}}}
	if err := validateRuntime(config, dependencies); !errors.Is(err, errInvalidRuntimeDependencies) {
		t.Fatalf("validateRuntime() error = %v, want errInvalidRuntimeDependencies", err)
	}
	dependencies.Stores[0].Durable = true
	if err := validateRuntime(config, dependencies); err != nil {
		t.Fatalf("durable validateRuntime() error = %v", err)
	}
}

func TestServeRuntimeSplitsProductAndInternalListeners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan commandListenResult, 2)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		opened <- commandListenResult{listener: listener, network: network, address: address, err: err}
		return listener, err
	}
	dependencies := fixtureRuntimeDependencies()
	result := make(chan error, 1)
	go func() {
		result <- serveRuntime(ctx, &bytes.Buffer{}, "1.2.3", fixtureRuntimeConfig(), dependencies, listen)
	}()

	listeners := map[string]net.Listener{}
	for len(listeners) < 2 {
		select {
		case value := <-opened:
			if value.err != nil {
				t.Fatal(value.err)
			}
			listeners[value.address] = value.listener
		case <-time.After(2 * time.Second):
			t.Fatal("listeners not opened")
		}
	}
	productURL := "http://" + listeners[":8080"].Addr().String()
	internalURL := "http://" + listeners[":8081"].Addr().String()
	waitForStatus(t, productURL+"/api/v1/home/summary", http.StatusNoContent)
	waitForReady(t, internalURL)
	assertEndpoint(t, internalURL+"/healthz", http.StatusOK, "{\"status\":\"live\"}\n")
	assertEndpoint(t, productURL+"/healthz", http.StatusNotFound, "404 page not found\n")

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serveRuntime() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveRuntime() did not drain")
	}
}

func TestServeRuntimeClosesProductListenerAfterPartialStartup(t *testing.T) {
	first := &commandListener{}
	calls := 0
	listen := func(string, string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, errors.New("internal listen failed")
	}
	err := serveRuntime(context.Background(), &bytes.Buffer{}, "dev", fixtureRuntimeConfig(), fixtureRuntimeDependencies(), listen)
	if err == nil || first.closes != 1 {
		t.Fatalf("error/closes = (%v, %d), want error and one close", err, first.closes)
	}
}

func fixtureRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{Environment: "production", ProductListenAddress: ":8080", InternalListenAddress: ":8081", PublicOrigin: "https://app.zasp.example", CookieSecure: true, ProviderTimeout: 5 * time.Second, ShutdownTimeout: 5 * time.Second}
}

func fixtureRuntimeDependencies() RuntimeDependencies {
	return RuntimeDependencies{ProductHandler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/home/summary" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}), MigrationReady: true, IdentityReady: true, CompositionReady: true, Stores: []StoreDependency{{Name: "core", Durable: true}}}
}

func waitForStatus(t *testing.T, target string, status int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := testHTTPClient.Get(target)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == status {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not return %d", target, status)
}

func mapsClone(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
