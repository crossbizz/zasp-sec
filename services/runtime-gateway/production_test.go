package main

import (
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
		"ZASP_DATABASE_URL":                   "postgresql://gateway@database.internal:5432/zasp?sslmode=verify-full",
		"ZASP_GATEWAY_ORGANIZATION_ID":        gatewayRuntimeID(1),
		"ZASP_GATEWAY_WORKSPACE_ID":           gatewayRuntimeID(2),
		"ZASP_GATEWAY_ENVIRONMENT_ID":         gatewayRuntimeID(3),
		"ZASP_GATEWAY_DEVICE_ID":              gatewayRuntimeID(4),
		"ZASP_GATEWAY_CREDENTIAL_ID":          gatewayRuntimeID(5),
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
	if err != nil || config.MaximumRequestBytes != 16*1024 || config.MaximumPendingEvents != 256 || config.SyncInterval != 30*time.Second {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for key, replacement := range map[string]string{
		"ZASP_DATABASE_URL":                   "postgresql://gateway@database.internal:5432/zasp?sslmode=disable",
		"ZASP_GATEWAY_CREDENTIAL_ID":          "credential",
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
		if candidate, err := loadProductionGatewayConfig(func(name string) string { return values[name] }); err == nil || candidate.DatabaseURL != "" {
			t.Fatalf("key=%s candidate=%#v err=%v", key, candidate, err)
		}
		values[key] = prior
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
