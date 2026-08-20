package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadProductionGatewayConfigRequiresExactAuthority(t *testing.T) {
	directory := t.TempDir()
	values := map[string]string{
		"ZASP_GATEWAY_CONTROL_BASE_URL":       "https://gateway-control.zasp.example",
		"ZASP_GATEWAY_ORGANIZATION_ID":        gatewayRuntimeID(1),
		"ZASP_GATEWAY_WORKSPACE_ID":           gatewayRuntimeID(2),
		"ZASP_GATEWAY_ENVIRONMENT_ID":         gatewayRuntimeID(3),
		"ZASP_GATEWAY_DEVICE_ID":              gatewayRuntimeID(4),
		"ZASP_GATEWAY_CREDENTIAL_ID":          gatewayRuntimeID(5),
		"ZASP_GATEWAY_PRIVATE_KEY_FILE":       filepath.Join(directory, "credential.json"),
		"ZASP_GATEWAY_POLICY_KEYS_FILE":       filepath.Join(directory, "keys.json"),
		"ZASP_GATEWAY_POLICY_CACHE_FILE":      filepath.Join(directory, "cache.json"),
		"ZASP_GATEWAY_BOOTSTRAP_FAILURE_MODE": "closed",
		"ZASP_GATEWAY_MAX_REQUEST_BYTES":      "16384",
		"ZASP_GATEWAY_MAX_PENDING_EVENTS":     "256",
		"ZASP_GATEWAY_OPERATION_TIMEOUT":      "3s",
		"ZASP_GATEWAY_SYNC_INTERVAL":          "30s",
		"ZASP_GATEWAY_SHUTDOWN_TIMEOUT":       "10s",
	}
	config, err := loadProductionGatewayConfig(func(key string) string { return values[key] })
	if err != nil || config.ControlPlaneURL != "https://gateway-control.zasp.example" || config.MaximumRequestBytes != 16*1024 || config.MaximumPendingEvents != 256 || config.SyncInterval != 30*time.Second {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for key, replacement := range map[string]string{
		"ZASP_GATEWAY_CONTROL_BASE_URL":       "http://gateway-control.zasp.example",
		"ZASP_GATEWAY_CREDENTIAL_ID":          "credential",
		"ZASP_GATEWAY_PRIVATE_KEY_FILE":       "credential.json",
		"ZASP_GATEWAY_POLICY_KEYS_FILE":       "keys.json",
		"ZASP_GATEWAY_POLICY_CACHE_FILE":      directory,
		"ZASP_GATEWAY_BOOTSTRAP_FAILURE_MODE": "fallback",
		"ZASP_GATEWAY_MAX_REQUEST_BYTES":      "999999",
		"ZASP_GATEWAY_MAX_PENDING_EVENTS":     "0",
		"ZASP_GATEWAY_OPERATION_TIMEOUT":      "31s",
		"ZASP_GATEWAY_SYNC_INTERVAL":          "500ms",
		"ZASP_GATEWAY_SHUTDOWN_TIMEOUT":       "0s",
	} {
		prior := values[key]
		values[key] = replacement
		if candidate, err := loadProductionGatewayConfig(func(name string) string { return values[name] }); err == nil || candidate.ControlPlaneURL != "" {
			t.Fatalf("key=%s candidate=%#v err=%v", key, candidate, err)
		}
		values[key] = prior
	}
}

func TestLoadGatewayCredentialUsesCanonicalPrivateFileAndExactConfiguredIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credential.json")
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	credentialID := gatewayRuntimeID(5)
	body := `{"credential_id":"` + credentialID + `","key_id":"gateway-key-1","private_key":"` + base64.RawURLEncoding.EncodeToString(privateKey) + `"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := loadGatewayCredential(path, credentialID)
	if err != nil || credential.CredentialID != credentialID || credential.KeyID != "gateway-key-1" || !bytes.Equal(credential.PrivateKey, privateKey) {
		t.Fatalf("credential=%#v err=%v", credential, err)
	}
	credential.Destroy()
	if len(credential.PrivateKey) != 0 {
		t.Fatal("credential destroy retained private key")
	}
	for _, hostile := range []string{
		`{"credential_id":"` + gatewayRuntimeID(6) + `","key_id":"gateway-key-1","private_key":"` + base64.RawURLEncoding.EncodeToString(privateKey) + `"}`,
		`{"credential_id":"` + credentialID + `","key_id":"gateway-key-1","private_key":"` + base64.RawURLEncoding.EncodeToString(privateKey) + `","secret":"leak"}`,
		`{"credential_id":"` + credentialID + `","key_id":"gateway-key-1","private_key":"AAAA"}`,
	} {
		if err := os.WriteFile(path, []byte(hostile), 0o600); err != nil {
			t.Fatal(err)
		}
		if value, err := loadGatewayCredential(path, credentialID); err == nil || value.CredentialID != "" || len(value.PrivateKey) != 0 {
			t.Fatalf("accepted hostile credential %s: %#v %v", hostile, value, err)
		}
	}
}

func TestLoadGatewayPolicyKeysUsesClosedCanonicalFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "keys.json")
	key := make([]byte, ed25519.PublicKeySize)
	for index := range key {
		key[index] = byte(index + 1)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(`{"keys":[{"key_id":"gateway-key-1","public_key":"`+encoded+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGatewayPolicyKeys(path); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"keys":[]}`,
		`{"keys":[{"key_id":"gateway-key-1","public_key":"` + encoded + `"},{"key_id":"gateway-key-1","public_key":"` + encoded + `"}]}`,
		`{"keys":[{"key_id":"gateway-key-1","public_key":"` + encoded + `","secret":"leak"}]}`,
		`{"keys":[{"key_id":"bad","public_key":"` + encoded + `"}]}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadGatewayPolicyKeys(path); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}
