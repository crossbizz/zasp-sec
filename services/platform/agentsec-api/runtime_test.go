package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestLoadRuntimeConfigIsStrict(t *testing.T) {
	values := map[string]string{
		"ZASP_ENVIRONMENT": "production", "ZASP_PRODUCT_LISTEN_ADDRESS": ":8080", "ZASP_INTERNAL_LISTEN_ADDRESS": ":8081",
		"ZASP_PUBLIC_ORIGIN": "https://app.zasp.example", "ZASP_COOKIE_SECURE": "true",
		"ZASP_TRUSTED_PROXY_CIDRS": "10.20.0.0/16,2001:db8::/32", "ZASP_REQUEST_RATE_PER_SECOND": "100", "ZASP_REQUEST_BURST": "200",
		"ZASP_PROVIDER_TIMEOUT": "5s", "ZASP_REQUEST_TIMEOUT": "10s", "ZASP_SHUTDOWN_TIMEOUT": "5s",
		"ZASP_READINESS_INTERVAL": "5s", "ZASP_READINESS_MAX_INTERVAL": "1m",
		"ZASP_DEPLOYMENT_MODE": "saas", "ZASP_ORGANIZATION_ID": "",
		"ZASP_POSTGRES_DSN":    "postgres://zasp@db.internal:5432/zasp?sslmode=require",
		"ZASP_STYTCH_BASE_URL": "https://api.stytch.com", "ZASP_STYTCH_AUTHORIZE_URL": "https://api.stytch.com/v1/b2b/public/oauth/google/start", "ZASP_STYTCH_PROJECT_ID": "project-live-local", "ZASP_STYTCH_SECRET": "secret-live-local", "ZASP_STYTCH_PUBLIC_TOKEN": "public-token-live-local", "ZASP_STYTCH_ORGANIZATION_ID": "organization-live-local", "ZASP_WORKFLOW_SIGNING_KEY": "0123456789abcdef0123456789abcdef", "ZASP_TOKEN_REVEAL_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
		"ZASP_CONNECTOR_AWS_REGION": "us-east-1", "ZASP_CONNECTOR_ROLE_ARN": "arn:aws:iam::000000000000:role/zasp-api-connectors", "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "ZASP_CONNECTOR_KMS_KEY_ARN": "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-4111-8111-111111111111", "ZASP_CONNECTOR_SECRET_PREFIX": "zasp/oauth",
		"ZASP_AWS_CUSTOMER_ROLE_PREFIXES": `["arn:aws:iam::111111111111:role/zasp,team/","arn:aws:iam::123456789012:role/zasp/"]`, "ZASP_KUBERNETES_EGRESS_CIDRS": "203.0.113.0/24",
		"ZASP_AWS_CUSTOMER_ROLE_ARNS": `["arn:aws:iam::111111111111:role/zasp,team/customer","arn:aws:iam::123456789012:role/zasp/customer"]`,
		"ZASP_GITHUB_CLIENT_ID":       "Iv1.1234567890abcdef", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE": "ref:github/app-secret-0001", "ZASP_GITHUB_APP_ID": "123456", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE": "ref:github/app-private-key-0001", "ZASP_OKTA_CLIENT_ID": "0oa1234567890abcdef", "ZASP_OKTA_CLIENT_SECRET_REFERENCE": "ref:okta/client-secret-0001",
	}
	config, err := loadRuntimeConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if config.ProductListenAddress != ":8080" || config.InternalListenAddress != ":8081" || config.PublicOrigin != "https://app.zasp.example" || !config.CookieSecure || len(config.AWSCustomerRolePrefixes) != 2 || config.AWSCustomerRolePrefixes[0] != "arn:aws:iam::111111111111:role/zasp,team/" || config.AWSCustomerRolePrefixes[1] != "arn:aws:iam::123456789012:role/zasp/" || len(config.AWSCustomerRoleARNs) != 2 {
		t.Fatalf("config = %#v", config)
	}
	invalidCIDRs := mapsClone(values)
	invalidCIDRs["ZASP_KUBERNETES_EGRESS_CIDRS"] = "not-a-cidr"
	if _, err := loadRuntimeConfig(func(key string) string { return invalidCIDRs[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
		t.Fatalf("invalid Kubernetes egress CIDRs error = %v", err)
	}

	for _, key := range []string{"ZASP_ENVIRONMENT", "ZASP_PRODUCT_LISTEN_ADDRESS", "ZASP_INTERNAL_LISTEN_ADDRESS", "ZASP_PUBLIC_ORIGIN", "ZASP_COOKIE_SECURE", "ZASP_TRUSTED_PROXY_CIDRS", "ZASP_REQUEST_RATE_PER_SECOND", "ZASP_REQUEST_BURST", "ZASP_PROVIDER_TIMEOUT", "ZASP_REQUEST_TIMEOUT", "ZASP_SHUTDOWN_TIMEOUT", "ZASP_READINESS_INTERVAL", "ZASP_READINESS_MAX_INTERVAL", "ZASP_DEPLOYMENT_MODE", "ZASP_POSTGRES_DSN", "ZASP_STYTCH_BASE_URL", "ZASP_STYTCH_AUTHORIZE_URL", "ZASP_STYTCH_PROJECT_ID", "ZASP_STYTCH_SECRET", "ZASP_STYTCH_PUBLIC_TOKEN", "ZASP_STYTCH_ORGANIZATION_ID", "ZASP_WORKFLOW_SIGNING_KEY", "ZASP_TOKEN_REVEAL_KEY", "ZASP_CONNECTOR_AWS_REGION", "ZASP_CONNECTOR_ROLE_ARN", "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE", "ZASP_CONNECTOR_KMS_KEY_ARN", "ZASP_CONNECTOR_SECRET_PREFIX", "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_GITHUB_CLIENT_ID", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE", "ZASP_GITHUB_APP_ID", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE", "ZASP_OKTA_CLIENT_ID", "ZASP_OKTA_CLIENT_SECRET_REFERENCE"} {
		t.Run("missing "+key, func(t *testing.T) {
			copy := mapsClone(values)
			delete(copy, key)
			if _, err := loadRuntimeConfig(func(key string) string { return copy[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
				t.Fatalf("error = %v, want errInvalidRuntimeConfig", err)
			}
		})
	}
	values["ZASP_DEPLOYMENT_MODE"] = "single_tenant"
	values["ZASP_ORGANIZATION_ID"] = "pid_11111111-1111-4111-8111-111111111111"
	if config, err := loadRuntimeConfig(func(key string) string { return values[key] }); err != nil || config.OrganizationID == "" {
		t.Fatalf("single-tenant config = %#v, %v", config, err)
	}
	values["ZASP_ORGANIZATION_ID"] = ""
	if _, err := loadRuntimeConfig(func(key string) string { return values[key] }); !errors.Is(err, errInvalidRuntimeConfig) {
		t.Fatalf("single tenant without organization error = %v", err)
	}
}

func TestConnectorWorkerOwnerIsPerProcessAndBounded(t *testing.T) {
	first, err := newConnectorWorkerOwner("agentsec-api-7c8f9d6b4f-a1b2c", bytes.NewReader(make([]byte, 8)))
	if err != nil || first != "agentsec-api:agentsec-api-7c8f9d6b4f-a1b2c:0000000000000000" || len(first) > 128 {
		t.Fatalf("worker owner=%q err=%v", first, err)
	}
	second, err := newConnectorWorkerOwner("agentsec-api-7c8f9d6b4f-a1b2c", bytes.NewReader(bytes.Repeat([]byte{1}, 8)))
	if err != nil || second == first {
		t.Fatalf("worker owner did not distinguish process restart: %q/%q err=%v", first, second, err)
	}
	for _, hostname := range []string{"", " hostile", strings.Repeat("a", 97)} {
		if _, err := newConnectorWorkerOwner(hostname, bytes.NewReader(make([]byte, 8))); err == nil {
			t.Fatalf("hostile hostname accepted: %q", hostname)
		}
	}
}

func TestRuntimeNangoConfigurationIsOptionalAllOrNothingAndPrivate(t *testing.T) {
	config := fixtureRuntimeConfig()
	if !validRuntimeConfig(config) {
		t.Fatal("core runtime without Nango must remain valid")
	}
	config.NangoBaseURL = "http://nango.connector.svc.cluster.local:3003"
	if validRuntimeConfig(config) {
		t.Fatal("partial Nango configuration accepted")
	}
	config.NangoServiceSecretReference = "ref:nango/service-key-0001"
	config.NangoEnvironment = "production"
	if !validRuntimeConfig(config) {
		t.Fatal("private complete Nango configuration rejected")
	}
	config.NangoBaseURL = "https://nango.example.com"
	if validRuntimeConfig(config) {
		t.Fatal("public Nango endpoint accepted")
	}
}

func TestRuntimeRejectsMemoryDependenciesInProduction(t *testing.T) {
	config := fixtureRuntimeConfig()
	dependencies := RuntimeDependencies{ProductHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ReadinessCheck: func(context.Context) error { return nil },
		Stores: []StoreDependency{{Name: "core", Durable: false}}}
	if err := validateRuntime(config, dependencies); !errors.Is(err, errInvalidRuntimeDependencies) {
		t.Fatalf("validateRuntime() error = %v, want errInvalidRuntimeDependencies", err)
	}
	dependencies.Stores[0].Durable = true
	if err := validateRuntime(config, dependencies); err != nil {
		t.Fatalf("durable validateRuntime() error = %v", err)
	}
}

func TestComposeRuntimeDependenciesRejectsSchemaDrift(t *testing.T) {
	_, err := composeRuntimeDependencies(fixtureRuntimeConfig(), schemaDriftDatabase{}, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
		return apiserver.SessionGrant{}, nil
	}))
	if err == nil {
		t.Fatal("composeRuntimeDependencies() accepted schema drift")
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
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() {
		result <- serveRuntime(ctx, &output, "1.2.3", fixtureRuntimeConfig(), dependencies, listen)
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
	for _, event := range []string{`"event":"runtime_started"`, `"event":"runtime_stopped"`} {
		if !bytes.Contains(output.Bytes(), []byte(event)) {
			t.Fatalf("lifecycle log missing %s: %s", event, output.String())
		}
	}
}

func TestServeRuntimeRunsAndCancelsConnectorLifecycleWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opened := make(chan commandListenResult, 2)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		opened <- commandListenResult{listener: listener, network: network, address: address, err: err}
		return listener, err
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	dependencies := fixtureRuntimeDependencies()
	dependencies.LifecycleWorker = func(workerContext context.Context) error {
		close(started)
		<-workerContext.Done()
		close(stopped)
		return workerContext.Err()
	}
	result := make(chan error, 1)
	go func() {
		result <- serveRuntime(ctx, &bytes.Buffer{}, "1.2.3", fixtureRuntimeConfig(), dependencies, listen)
	}()
	for range 2 {
		<-opened
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("connector lifecycle worker did not start")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("connector lifecycle worker did not stop")
	}
}

func TestServeRuntimeBoundsHostileLifecycleWorkerShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opened := make(chan commandListenResult, 2)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		opened <- commandListenResult{listener: listener, network: network, address: address, err: err}
		return listener, err
	}
	release := make(chan struct{})
	dependencies := fixtureRuntimeDependencies()
	dependencies.LifecycleWorker = func(context.Context) error {
		<-release
		return nil
	}
	config := fixtureRuntimeConfig()
	config.ShutdownTimeout = 100 * time.Millisecond
	result := make(chan error, 1)
	go func() { result <- serveRuntime(ctx, &bytes.Buffer{}, "1.2.3", config, dependencies, listen) }()
	for range 2 {
		<-opened
	}
	started := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, errRuntimeUnavailable) || time.Since(started) > time.Second {
			t.Fatalf("bounded hostile worker shutdown err=%v elapsed=%s", err, time.Since(started))
		}
	case <-time.After(time.Second):
		t.Fatal("hostile lifecycle worker blocked process shutdown")
	}
	close(release)
}

func TestServeRuntimeReadinessTracksRequiredProviderChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := make(chan commandListenResult, 2)
	listen := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		opened <- commandListenResult{listener: listener, network: network, address: address, err: err}
		return listener, err
	}
	var providersReady atomic.Bool
	dependencies := fixtureRuntimeDependencies()
	dependencies.ReadinessCheck = func(context.Context) error {
		if !providersReady.Load() {
			return errors.New("required provider unavailable")
		}
		return nil
	}
	result := make(chan error, 1)
	go func() {
		result <- serveRuntime(ctx, &bytes.Buffer{}, "1.2.3", fixtureRuntimeConfig(), dependencies, listen)
	}()
	listeners := map[string]net.Listener{}
	for len(listeners) < 2 {
		value := <-opened
		listeners[value.address] = value.listener
	}
	readyURL := "http://" + listeners[":8081"].Addr().String() + "/readyz"
	waitForStatus(t, readyURL, http.StatusServiceUnavailable)
	providersReady.Store(true)
	waitForStatus(t, readyURL, http.StatusOK)
	providersReady.Store(false)
	waitForStatus(t, readyURL, http.StatusServiceUnavailable)
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
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
	return RuntimeConfig{Environment: "production", DeploymentMode: "saas", ProductListenAddress: ":8080", InternalListenAddress: ":8081", PublicOrigin: "https://app.zasp.example", TrustedProxyCIDRs: []string{"10.20.0.0/16"}, RequestRatePerSecond: 100, RequestBurst: 200, CookieSecure: true, ProviderTimeout: 5 * time.Second, RequestTimeout: 10 * time.Second, ShutdownTimeout: 5 * time.Second,
		ReadinessInterval: 100 * time.Millisecond, ReadinessMaxInterval: 500 * time.Millisecond, PostgresDSN: "postgres://zasp@db.internal:5432/zasp?sslmode=require", StytchBaseURL: "https://api.stytch.com", StytchAuthorizeURL: "https://api.stytch.com/v1/b2b/public/oauth/google/start", StytchProjectID: "project-live-local", StytchSecret: "secret-live-local", StytchPublicToken: "public-token-live-local", StytchOrganizationID: "organization-live-local", WorkflowSigningKey: "0123456789abcdef0123456789abcdef", TokenRevealKey: []byte("0123456789abcdef0123456789abcdef"),
		ConnectorAWSRegion: "us-east-1", ConnectorRoleARN: "arn:aws:iam::000000000000:role/zasp-api-connectors", ConnectorTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", ConnectorKMSKeyARN: "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-4111-8111-111111111111", ConnectorSecretPrefix: "zasp/oauth", AWSCustomerRolePrefixes: []string{"arn:aws:iam::111111111111:role/zasp/", "arn:aws:iam::123456789012:role/zasp/"}, AWSCustomerRoleARNs: []string{"arn:aws:iam::111111111111:role/zasp/customer", "arn:aws:iam::123456789012:role/zasp/customer"}, KubernetesEgressCIDRs: []string{"203.0.113.0/24"}, GitHubClientID: "Iv1.1234567890abcdef", GitHubSecretReference: "ref:github/app-secret-0001", GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaSecretReference: "ref:okta/client-secret-0001"}
}

func fixtureRuntimeDependencies() RuntimeDependencies {
	return RuntimeDependencies{ProductHandler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/home/summary" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}), ReadinessCheck: func(context.Context) error { return nil }, Stores: []StoreDependency{{Name: "core", Durable: true}}}
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

type schemaDriftDatabase struct{}

func (schemaDriftDatabase) SchemaVersion(context.Context) (string, error) { return "old-schema", nil }
func (schemaDriftDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("unused")
}
func (schemaDriftDatabase) Exec(context.Context, string, ...any) error { return errors.New("unused") }
