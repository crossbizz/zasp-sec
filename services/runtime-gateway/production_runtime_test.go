package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
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
	config := productionGatewayConfig{
		ControlPlaneURL: "https://gateway-control.zasp.example",
		OrganizationID:  gatewayRuntimeID(1), WorkspaceID: gatewayRuntimeID(2), EnvironmentID: gatewayRuntimeID(3), DeviceID: gatewayRuntimeID(4), CredentialID: credentialID,
		PrivateKeyFile: credentialPath, PolicyKeysFile: policyKeyPath, PolicyCacheFile: filepath.Join(directory, "policy-cache.json"), BootstrapFailureMode: "closed",
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
	if err != nil || dependencies.Handler == nil || dependencies.Ready == nil || dependencies.Run == nil || dependencies.Drain == nil || dependencies.Close == nil {
		t.Fatalf("dependencies=%#v factory=%#v close_calls=%d err=%v", dependencies, captured, client.closeCalls, err)
	}
	if captured.BaseURL != config.ControlPlaneURL || captured.OrganizationID != config.OrganizationID || captured.WorkspaceID != config.WorkspaceID || captured.EnvironmentID != config.EnvironmentID || captured.DeviceID != config.DeviceID || captured.CredentialID != config.CredentialID || captured.KeyID != "gateway-key-1" || !bytes.Equal(captured.PrivateKey, privateKey) {
		t.Fatalf("captured=%#v", captured)
	}
	clear(privateKey)
	if !bytes.Equal(captured.PrivateKey, gatewayPrivateKeyFixture()) {
		t.Fatal("factory did not receive an isolated private-key copy")
	}
	if dependencies.Close() != nil || dependencies.Close() != nil || client.closeCalls != 1 {
		t.Fatalf("close calls=%d", client.closeCalls)
	}
}

type gatewayHTTPClientStub struct {
	authority  gatewaycontrol.Authority
	closeCalls int
}

func (*gatewayHTTPClientStub) Ready(context.Context) error { return nil }

func (client *gatewayHTTPClientStub) Authority(context.Context, string) (gatewaycontrol.Authority, error) {
	return client.authority, nil
}

func (*gatewayHTTPClientStub) Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error) {
	return nil, nil
}

func (*gatewayHTTPClientStub) Record(context.Context, gatewaycontrol.DecisionEvent) error { return nil }

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
