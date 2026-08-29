package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestProductionCombinedE2ERuntimeGatewayProxy(t *testing.T) {
	dsn := os.Getenv("ZASP_COMBINED_E2E_GATEWAY_DSN")
	phase := os.Getenv("ZASP_COMBINED_E2E_GATEWAY_PHASE")
	if dsn == "" {
		t.Skip("combined E2E helper")
	}
	if phase != "apply" && phase != "cleanup" {
		t.Fatal("combined E2E gateway phase is invalid")
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(os.Getenv("ZASP_COMBINED_E2E_GATEWAY_POLICY_PRIVATE_KEY"))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		t.Fatal("combined E2E gateway signing authority is invalid")
	}
	defer clear(privateKey)
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repository, err := gatewaycontrol.NewPostgresRepository(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := &combinedGatewayRepositoryClient{repository: repository}

	upstream := &combinedGatewayTLSUpstream{}
	server := httptest.NewTLSServer(http.HandlerFunc(upstream.serve))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverURL.Hostname()}, DisableKeepAlives: true}
	defer tlsTransport.CloseIdleConnections()
	pinnedTransport := &combinedGatewayTLSRoundTripper{target: serverURL, next: tlsTransport}

	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, credentialPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(directory, "gateway-credential.json")
	credential := `{"credential_id":"pid_79000003-0000-4000-8000-000000000003","key_id":"gateway-device-key-01","private_key":"` + base64.RawURLEncoding.EncodeToString(credentialPrivate) + `"}`
	if err := os.WriteFile(credentialPath, []byte(credential), 0o600); err != nil {
		t.Fatal(err)
	}
	policyKeysPath := filepath.Join(directory, "gateway-policy-keys.json")
	if err := os.WriteFile(policyKeysPath, []byte(`{"keys":[{"key_id":"gateway-key-01","public_key":"`+base64.RawURLEncoding.EncodeToString(publicKey)+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdef0123456789abcdef"
	tokenPath := filepath.Join(directory, "proxy-token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	config := productionGatewayConfig{
		ControlPlaneURL: "https://gateway-control.zasp.example",
		OrganizationID:  "pid_10000001-0000-4000-8000-000000000001", WorkspaceID: "pid_10000002-0000-4000-8000-000000000002", EnvironmentID: "pid_10000003-0000-4000-8000-000000000003",
		DeviceID: "pid_79000001-0000-4000-8000-000000000001", CredentialID: "pid_79000003-0000-4000-8000-000000000003",
		PrivateKeyFile: credentialPath, PolicyKeysFile: policyKeysPath, PolicyCacheFile: filepath.Join(directory, "policy-cache.json"), EvidenceStoreDirectory: filepath.Join(directory, "evidence"), EvidenceMaximumBytes: 8 << 30,
		ProxyUpstreamURL: "https://tools.customer.example/v1/actions", ProxyAllowedCIDRs: []string{"203.0.113.0/24"}, ProxyClientTokenFile: tokenPath,
		BootstrapFailureMode: "closed", MaximumRequestBytes: 16 * 1024, MaximumPendingEvents: 32, OperationTimeout: time.Second, SyncInterval: time.Second, ShutdownTimeout: time.Second,
	}
	dependencies, err := buildProductionGatewayDependenciesWithFactories(ctx, config, func(gatewaycontrol.HTTPClientConfig) (gatewayHTTPClient, error) {
		return client, nil
	}, combinedGatewayResolver{}, func(host, pinnedIP string, timeout time.Duration) http.RoundTripper {
		if host != "tools.customer.example" || pinnedIP != "203.0.113.10" || timeout != time.Second {
			t.Fatalf("host=%q pinned_ip=%q timeout=%s", host, pinnedIP, timeout)
		}
		return pinnedTransport
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.Close()
	if err := dependencies.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	runCtx, stopRun := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- dependencies.Run(runCtx) }()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("composed runtime gateway stopped before its first scheduled refresh")
	case <-time.After(3 * config.SyncInterval):
	}
	stopRun()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	beforeAuthority, err := repository.Authority(ctx, config.CredentialID)
	if err != nil {
		t.Fatal(err)
	}

	eventID := "pid_79000030-0000-4000-8000-000000000030"
	expectedStatus, expectedCalls := http.StatusForbidden, 0
	if phase == "cleanup" {
		eventID = "pid_79000031-0000-4000-8000-000000000031"
		expectedStatus, expectedCalls = http.StatusAccepted, 1
	}
	request := httptest.NewRequest(http.MethodPut, gatewayHTTPProxyPath+"/repositories/a%2Fb?dry_run=true", bytes.NewReader([]byte(`{"operation":"read"}`)))
	combinedGatewayHeaders(request, token, eventID, phase == "apply")
	response := httptest.NewRecorder()
	dependencies.Handler.ServeHTTP(response, request)
	if response.Code != expectedStatus || upstream.calls() != expectedCalls {
		t.Fatalf("phase=%s status=%d upstream_calls=%d transport_error=%v body=%s", phase, response.Code, upstream.calls(), pinnedTransport.lastError(), response.Body.String())
	}
	if phase == "cleanup" {
		method, target, body := upstream.last()
		if method != http.MethodPut || target != "/v1/actions/repositories/a%2Fb?dry_run=true" || body != `{"operation":"read"}` {
			t.Fatalf("method=%q target=%q body=%q", method, target, body)
		}
	}
	if err := dependencies.Drain(ctx); err != nil {
		event, recordErr := client.recordFailure()
		t.Fatalf("drain=%v record=%v diagnostic=%v event=%#v", err, recordErr, diagnoseCombinedGatewayRecord(ctx, pool, event), event)
	}
	afterAuthority, err := repository.Authority(ctx, config.CredentialID)
	if err != nil || afterAuthority.ReplayFloor != beforeAuthority.ReplayFloor+1 {
		t.Fatalf("event=%s before_floor=%d after_floor=%d err=%v", eventID, beforeAuthority.ReplayFloor, afterAuthority.ReplayFloor, err)
	}

	client.setOffline()
	cachedEventID := map[string]string{"apply": "pid_79000032-0000-4000-8000-000000000032", "cleanup": "pid_79000033-0000-4000-8000-000000000033"}[phase]
	request = httptest.NewRequest(http.MethodPut, gatewayHTTPProxyPath+"/repositories/a%2Fb?dry_run=true", bytes.NewReader([]byte(`{"operation":"read"}`)))
	combinedGatewayHeaders(request, token, cachedEventID, false)
	response = httptest.NewRecorder()
	dependencies.Handler.ServeHTTP(response, request)
	if response.Code != expectedStatus || upstream.calls() != expectedCalls+map[string]int{"apply": 0, "cleanup": 1}[phase] {
		t.Fatalf("cached phase=%s status=%d upstream_calls=%d body=%s", phase, response.Code, upstream.calls(), response.Body.String())
	}
	t.Logf("composed runtime gateway %s decision survived control outage with durable PostgreSQL event and exact TLS upstream semantics", phase)
}

type combinedGatewayRepositoryClient struct {
	repository gatewaycontrol.Repository
	mu         sync.RWMutex
	offline    bool
	lastEvent  gatewaycontrol.DecisionEvent
	recordErr  error
}

func (client *combinedGatewayRepositoryClient) Ready(ctx context.Context) error {
	client.mu.RLock()
	offline := client.offline
	client.mu.RUnlock()
	if offline {
		return errRuntimeUnavailable
	}
	return client.repository.Ready(ctx)
}

func (client *combinedGatewayRepositoryClient) Authority(ctx context.Context, credentialID string) (gatewaycontrol.Authority, error) {
	return client.repository.Authority(ctx, credentialID)
}

func (client *combinedGatewayRepositoryClient) Policy(ctx context.Context, credentialID string, after uint64) (*policy.GatewayPolicyEnvelope, error) {
	return client.repository.Policy(ctx, credentialID, after)
}

func (client *combinedGatewayRepositoryClient) Record(ctx context.Context, event gatewaycontrol.DecisionEvent) error {
	client.mu.RLock()
	offline := client.offline
	client.mu.RUnlock()
	if offline {
		return errRuntimeUnavailable
	}
	err := client.repository.Record(ctx, event)
	client.mu.Lock()
	client.lastEvent, client.recordErr = event, err
	client.mu.Unlock()
	return err
}

func (*combinedGatewayRepositoryClient) Close() error { return nil }

func (client *combinedGatewayRepositoryClient) setOffline() {
	client.mu.Lock()
	client.offline = true
	client.mu.Unlock()
}

func (client *combinedGatewayRepositoryClient) recordFailure() (gatewaycontrol.DecisionEvent, error) {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.lastEvent, client.recordErr
}

func diagnoseCombinedGatewayRecord(ctx context.Context, pool *pgxpool.Pool, event gatewaycontrol.DecisionEvent) error {
	classification, classificationErr := json.Marshal(event.Classification)
	policyIDs, policyErr := json.Marshal(event.PolicyIDs)
	if classificationErr != nil || policyErr != nil {
		return fmt.Errorf("classification=%v policies=%v", classificationErr, policyErr)
	}
	transaction, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var result json.RawMessage
	err = transaction.QueryRow(ctx, `SELECT zasp_runtime_gateway_record_event_v27(
 $1,$2,$3,$4,
 digest(convert_to(jsonb_build_object(
  'credential_id',$1::text,'device_id',$5::text,'event_id',$2::text,
  'expected_floor',$3::bigint,'next_floor',$4::bigint,'policy_version',$6::bigint,
  'decision',$7::text,'action_kind',$8::text,'classification',$9::jsonb,'policy_ids',$10::jsonb,
  'occurred_at',to_char($11::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
 )::text,'UTF8'),'sha256'),
 $6,$7,$8,$9::jsonb,$10::jsonb,$11
)`, event.CredentialID, event.EventID, event.ExpectedFloor, event.NextFloor, event.DeviceID, event.PolicyVersion, event.Decision, event.ActionKind, json.RawMessage(classification), json.RawMessage(policyIDs), event.OccurredAt).Scan(&result)
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected success: %s", result)
}

type combinedGatewayResolver struct{}

func (combinedGatewayResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
}

type combinedGatewayTLSRoundTripper struct {
	target *url.URL
	next   http.RoundTripper
	mu     sync.Mutex
	err    error
}

func (transport *combinedGatewayTLSRoundTripper) RoundTrip(source *http.Request) (*http.Response, error) {
	request := source.Clone(source.Context())
	target := *source.URL
	target.Scheme, target.Host = transport.target.Scheme, transport.target.Host
	request.URL = &target
	request.Host = transport.target.Host
	response, err := transport.next.RoundTrip(request)
	transport.mu.Lock()
	transport.err = err
	transport.mu.Unlock()
	return response, err
}

func (transport *combinedGatewayTLSRoundTripper) lastError() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.err
}

type combinedGatewayTLSUpstream struct {
	mu     sync.Mutex
	count  int
	method string
	target string
	body   string
}

func (upstream *combinedGatewayTLSUpstream) serve(response http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	upstream.mu.Lock()
	upstream.count++
	upstream.method, upstream.target, upstream.body = request.Method, request.URL.String(), string(body)
	upstream.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_, _ = response.Write([]byte(`{"accepted":true}`))
}

func (upstream *combinedGatewayTLSUpstream) calls() int {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.count
}

func (upstream *combinedGatewayTLSUpstream) last() (string, string, string) {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.method, upstream.target, upstream.body
}

func combinedGatewayHeaders(request *http.Request, token, eventID string, capability bool) {
	request.Header.Set("X-Zasp-Gateway-Token", token)
	request.Header.Set("X-Zasp-Event-ID", eventID)
	request.Header.Set("X-Zasp-Principal-ID", "pid_10000004-0000-4000-8000-000000000004")
	request.Header.Set("X-Zasp-Agent-ID", "pid_79000040-0000-4000-8000-000000000040")
	request.Header.Set("X-Zasp-Session-ID", "pid_79000041-0000-4000-8000-000000000041")
	request.Header.Set("X-Zasp-Route-Class", "local")
	request.Header.Set("X-Zasp-Resource-Class", "tool")
	request.Header.Set("X-Zasp-Action", "read")
	request.Header.Set("X-Zasp-Resource", "repository")
	request.Header.Set("Content-Type", "application/json")
	if capability {
		request.Header.Set("X-Zasp-Capability-Agent-ID", "pid_21000001-0000-4000-8000-000000000001")
		request.Header.Set("X-Zasp-Capability-Target-ID", "pid_21000004-0000-4000-8000-000000000004")
		request.Header.Set("X-Zasp-Capability-Category", "identity_assume")
		request.Header.Set("X-Zasp-Capability-Outcome", "assume")
	}
}

var _ gatewayHTTPClient = (*combinedGatewayRepositoryClient)(nil)
