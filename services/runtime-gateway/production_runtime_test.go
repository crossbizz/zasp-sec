package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestBuildProductionGatewayDependenciesUsesExactHTTPSAuthorityAndClosesOnce(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	privateKey := gatewayPrivateKeyFixture()
	credentialID := gatewayRuntimeID(5)
	credentialPath := filepath.Join(directory, "credential.json")
	credential := `{"credential_id":"` + credentialID + `","key_id":"gateway-key-1","private_key":"` + base64.RawURLEncoding.EncodeToString(privateKey) + `"}`
	if err := os.WriteFile(credentialPath, []byte(credential), 0o600); err != nil {
		t.Fatal(err)
	}
	policyKeyPath := filepath.Join(directory, "policy-keys.json")
	policyKey := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err := os.WriteFile(policyKeyPath, []byte(`{"keys":[{"key_id":"gateway-key-1","public_key":"`+policyKey+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGatewayPolicyKeys(policyKeyPath); err != nil {
		t.Fatalf("policy key fixture: %v", err)
	}
	proxyTokenPath := filepath.Join(directory, "proxy-token")
	if err := os.WriteFile(proxyTokenPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := productionGatewayConfig{
		ControlPlaneURL: "https://gateway-control.zasp.example",
		OrganizationID:  gatewayRuntimeID(1), WorkspaceID: gatewayRuntimeID(2), EnvironmentID: gatewayRuntimeID(3), DeviceID: gatewayRuntimeID(4), CredentialID: credentialID,
		PrivateKeyFile: credentialPath, PolicyKeysFile: policyKeyPath, PolicyCacheFile: filepath.Join(directory, "policy-cache.json"), EvidenceStoreDirectory: filepath.Join(directory, "evidence"), EvidenceMaximumBytes: 8 << 30, BootstrapFailureMode: "closed",
		ProxyUpstreamURL: "https://tools.customer.example/v1/actions", ProxyAllowedCIDRs: []string{"203.0.113.0/24"}, ProxyClientTokenFile: proxyTokenPath,
		MaximumRequestBytes: 16 * 1024, MaximumPendingEvents: 16, OperationTimeout: time.Second, SyncInterval: time.Second, ShutdownTimeout: time.Second,
	}
	client := &gatewayHTTPClientStub{authority: gatewaycontrol.Authority{
		OrganizationID: config.OrganizationID, WorkspaceID: config.WorkspaceID, EnvironmentID: config.EnvironmentID, DeviceID: config.DeviceID,
		DeviceVersion: 1, CredentialID: config.CredentialID, CredentialGeneration: 1, KeyID: "gateway-key-1", Algorithm: "Ed25519",
		PublicKey: privateKey.Public().(ed25519.PublicKey), Audience: gatewaycontrol.GatewayAudience, ExpiresAt: gatewayRuntimeTime().Add(time.Hour),
	}}
	var captured gatewaycontrol.HTTPClientConfig
	dependencies, err := buildProductionGatewayDependenciesWithFactory(context.Background(), config, func(value gatewaycontrol.HTTPClientConfig) (gatewayHTTPClient, error) {
		captured = value
		captured.PrivateKey = append(ed25519.PrivateKey(nil), value.PrivateKey...)
		return client, nil
	})
	if err != nil || dependencies.Handler == nil || dependencies.Ready == nil || dependencies.Run == nil || dependencies.Drain == nil || dependencies.Close == nil || dependencies.Metrics == nil || dependencies.AcknowledgeQuarantine == nil {
		t.Fatalf("dependencies=%#v factory=%#v close_calls=%d err=%v", dependencies, captured, client.closeCalls, err)
	}
	if metrics := dependencies.Metrics(); !strings.Contains(metrics, "zasp_gateway_evidence_receipt_capacity_bytes 8589934592\n") || !strings.Contains(metrics, "zasp_gateway_evidence_database_capacity_bytes 17179869184\n") {
		t.Fatalf("metrics=%q", metrics)
	}
	if captured.BaseURL != config.ControlPlaneURL || captured.OrganizationID != config.OrganizationID || captured.WorkspaceID != config.WorkspaceID || captured.EnvironmentID != config.EnvironmentID || captured.DeviceID != config.DeviceID || captured.CredentialID != config.CredentialID || captured.KeyID != "gateway-key-1" || !bytes.Equal(captured.PrivateKey, privateKey) {
		t.Fatalf("captured=%#v", captured)
	}
	clear(privateKey)
	if !bytes.Equal(captured.PrivateKey, gatewayPrivateKeyFixture()) {
		t.Fatal("factory did not receive an isolated private-key copy")
	}
	request := httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, strings.NewReader(`{"operation":"read"}`))
	setGatewayProxyHeaders(request, gatewayRuntimeID(9))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	response := httptest.NewRecorder()
	dependencies.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"policy_blocked"`) {
		t.Fatalf("proxy status=%d body=%s", response.Code, response.Body.String())
	}
	if dependencies.Close() != nil || dependencies.Close() != nil || client.closeCalls != 1 {
		t.Fatalf("close calls=%d", client.closeCalls)
	}
}

func TestGatewayHTTPControlPreservesOnlyExactExpiredRecordOutcome(t *testing.T) {
	client := &gatewayHTTPClientStub{recordErr: gatewaycontrol.ErrRecordExpired}
	control := gatewayHTTPControl{next: client}
	event := gatewayDecisionEvent{CredentialID: gatewayRuntimeID(5), DeviceID: gatewayRuntimeID(4), EventID: gatewayRuntimeID(6), ExpectedFloor: 0, NextFloor: 1, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", PolicyIDs: []string{"policy-runtime"}, Classification: gatewayRuntimeClassification("blocked"), OccurredAt: gatewayRuntimeTime()}
	if err := control.Record(context.Background(), event); !errors.Is(err, errGatewayRecordExpired) {
		t.Fatalf("expired record=%v", err)
	}
	client.recordErr = errors.New("temporary transport failure")
	if err := control.Record(context.Background(), event); !errors.Is(err, errGatewayRuntime) || errors.Is(err, errGatewayRecordExpired) {
		t.Fatalf("ambiguous record=%v", err)
	}
}

func TestProductionGatewayProxyPinsEveryAllowedAnswerAndClearsLocalToken(t *testing.T) {
	directory := t.TempDir()
	token := []byte("0123456789abcdef0123456789abcdef")
	tokenPath := filepath.Join(directory, "proxy-token")
	if err := os.WriteFile(tokenPath, token, 0o600); err != nil {
		t.Fatal(err)
	}
	config := productionGatewayConfig{
		ProxyUpstreamURL: "https://tools.customer.example/v1/actions", ProxyAllowedCIDRs: []string{"203.0.113.0/24"}, ProxyClientTokenFile: tokenPath,
		MaximumRequestBytes: 16 * 1024, OperationTimeout: time.Second,
	}
	resolver := gatewayProxyResolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.12")}, {IP: net.ParseIP("203.0.113.11")}}}
	upstream := &gatewayProxyRoundTripper{response: &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}}
	var pinnedHost, pinnedIP string
	handler, err := newProductionGatewayProxy(gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "http.method", Operator: "equals", Value: http.MethodPost}), config, resolver, func(host, ip string, timeout time.Duration) http.RoundTripper {
		pinnedHost, pinnedIP = host, ip
		if timeout != time.Second {
			t.Fatalf("timeout=%s", timeout)
		}
		return upstream
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, strings.NewReader(`{"operation":"read"}`))
	setGatewayProxyHeaders(request, gatewayRuntimeID(9))
	request.Header.Set("X-Zasp-Gateway-Token", string(token))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || pinnedHost != "tools.customer.example" || pinnedIP != "203.0.113.11" || upstream.calls != 1 {
		t.Fatalf("status=%d host=%q ip=%q calls=%d body=%s", response.Code, pinnedHost, pinnedIP, upstream.calls, response.Body.String())
	}
	if handler.Close() != nil || handler.Close() != nil || len(handler.clientToken) != 0 {
		t.Fatalf("token retained: %q", handler.clientToken)
	}
}

func TestProductionGatewayProxyRejectsForeignDNSAndMutableTokenBeforeNetwork(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "proxy-token")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := productionGatewayConfig{
		ProxyUpstreamURL: "https://tools.customer.example/v1/actions", ProxyAllowedCIDRs: []string{"203.0.113.0/24"}, ProxyClientTokenFile: tokenPath,
		MaximumRequestBytes: 16 * 1024, OperationTimeout: time.Second,
	}
	factoryCalls := 0
	handler, err := newProductionGatewayProxy(gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "http.method", Operator: "equals", Value: http.MethodPost}), config, gatewayProxyResolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.114.1")}}}, func(string, string, time.Duration) http.RoundTripper {
		factoryCalls++
		return &gatewayProxyRoundTripper{}
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, gatewayHTTPProxyPath, strings.NewReader(`{"operation":"read"}`))
	setGatewayProxyHeaders(request, gatewayRuntimeID(8))
	request.Header.Set("X-Zasp-Gateway-Token", "0123456789abcdef0123456789abcdef")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || factoryCalls != 0 {
		t.Fatalf("status=%d factory_calls=%d body=%s", response.Code, factoryCalls, response.Body.String())
	}
	_ = handler.Close()
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if candidate, err := newProductionGatewayProxy(gatewayProxyRuntime(t, "http_request", policy.ActionMonitor, policy.Condition{Field: "http.method", Operator: "equals", Value: http.MethodPost}), config, gatewayProxyResolverStub{}, func(string, string, time.Duration) http.RoundTripper { return &gatewayProxyRoundTripper{} }); err == nil || candidate != nil {
		t.Fatalf("candidate=%#v err=%v", candidate, err)
	}
}

type gatewayProxyResolverStub struct {
	addresses []net.IPAddr
	err       error
}

func (resolver gatewayProxyResolverStub) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), resolver.addresses...), resolver.err
}

type gatewayHTTPClientStub struct {
	authority  gatewaycontrol.Authority
	closeCalls int
	recordErr  error
}

func (*gatewayHTTPClientStub) Ready(context.Context) error { return nil }

func (client *gatewayHTTPClientStub) Authority(context.Context, string) (gatewaycontrol.Authority, error) {
	return client.authority, nil
}

func (*gatewayHTTPClientStub) Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error) {
	return nil, nil
}

func (client *gatewayHTTPClientStub) Record(context.Context, gatewaycontrol.DecisionEvent) error {
	return client.recordErr
}

func (client *gatewayHTTPClientStub) Close() error {
	client.closeCalls++
	return nil
}

func gatewayPrivateKeyFixture() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}
