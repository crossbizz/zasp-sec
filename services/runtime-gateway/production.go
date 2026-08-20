package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const maximumGatewayKeysFileBytes = 64 * 1024

type productionGatewayConfig struct {
	DatabaseURL          string
	OrganizationID       string
	WorkspaceID          string
	EnvironmentID        string
	DeviceID             string
	CredentialID         string
	PolicyKeysFile       string
	PolicyCacheFile      string
	BootstrapFailureMode string
	MaximumRequestBytes  int64
	MaximumPendingEvents int
	OperationTimeout     time.Duration
	SyncInterval         time.Duration
	ShutdownTimeout      time.Duration
}

func loadProductionGatewayConfig(getenv func(string) string) (productionGatewayConfig, error) {
	if getenv == nil {
		return productionGatewayConfig{}, errRuntimeUnavailable
	}
	maximumRequestBytes, requestErr := strconv.ParseInt(getenv("ZASP_GATEWAY_MAX_REQUEST_BYTES"), 10, 64)
	maximumPendingEvents, pendingErr := strconv.Atoi(getenv("ZASP_GATEWAY_MAX_PENDING_EVENTS"))
	operationTimeout, operationErr := time.ParseDuration(getenv("ZASP_GATEWAY_OPERATION_TIMEOUT"))
	syncInterval, syncErr := time.ParseDuration(getenv("ZASP_GATEWAY_SYNC_INTERVAL"))
	shutdownTimeout, shutdownErr := time.ParseDuration(getenv("ZASP_GATEWAY_SHUTDOWN_TIMEOUT"))
	config := productionGatewayConfig{
		DatabaseURL:          getenv("ZASP_DATABASE_URL"),
		OrganizationID:       getenv("ZASP_GATEWAY_ORGANIZATION_ID"),
		WorkspaceID:          getenv("ZASP_GATEWAY_WORKSPACE_ID"),
		EnvironmentID:        getenv("ZASP_GATEWAY_ENVIRONMENT_ID"),
		DeviceID:             getenv("ZASP_GATEWAY_DEVICE_ID"),
		CredentialID:         getenv("ZASP_GATEWAY_CREDENTIAL_ID"),
		PolicyKeysFile:       getenv("ZASP_GATEWAY_POLICY_KEYS_FILE"),
		PolicyCacheFile:      getenv("ZASP_GATEWAY_POLICY_CACHE_FILE"),
		BootstrapFailureMode: getenv("ZASP_GATEWAY_BOOTSTRAP_FAILURE_MODE"),
		MaximumRequestBytes:  maximumRequestBytes,
		MaximumPendingEvents: maximumPendingEvents,
		OperationTimeout:     operationTimeout,
		SyncInterval:         syncInterval,
		ShutdownTimeout:      shutdownTimeout,
	}
	if requestErr != nil || pendingErr != nil || operationErr != nil || syncErr != nil || shutdownErr != nil || !validProductionGatewayConfig(config) {
		return productionGatewayConfig{}, errRuntimeUnavailable
	}
	return config, nil
}

func validProductionGatewayConfig(config productionGatewayConfig) bool {
	database, err := url.Parse(config.DatabaseURL)
	if err != nil || database.String() != config.DatabaseURL || database.Scheme != "postgres" && database.Scheme != "postgresql" || database.User == nil || database.User.Username() == "" || database.Hostname() == "" || database.Path == "" || database.Fragment != "" {
		return false
	}
	query := database.Query()
	if len(query) != 1 || query.Get("sslmode") != "verify-full" || len(query["sslmode"]) != 1 {
		return false
	}
	return validGatewayProductID(config.OrganizationID) && validGatewayProductID(config.WorkspaceID) && validGatewayProductID(config.EnvironmentID) &&
		validGatewayProductID(config.DeviceID) && validGatewayProductID(config.CredentialID) && validGatewayPath(config.PolicyKeysFile, false) && validGatewayPath(config.PolicyCacheFile, true) &&
		(config.BootstrapFailureMode == "open" || config.BootstrapFailureMode == "closed") &&
		config.MaximumRequestBytes >= 1024 && config.MaximumRequestBytes <= 64*1024 && config.MaximumPendingEvents >= 1 && config.MaximumPendingEvents <= 1024 &&
		config.OperationTimeout >= time.Second && config.OperationTimeout <= 30*time.Second && config.SyncInterval >= time.Second && config.SyncInterval <= 5*time.Minute &&
		config.ShutdownTimeout >= time.Second && config.ShutdownTimeout <= time.Minute
}

func validGatewayPath(path string, rejectDirectory bool) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return false
	}
	if info, err := os.Lstat(path); err == nil {
		return !rejectDirectory || !info.IsDir()
	} else if !os.IsNotExist(err) {
		return false
	}
	return true
}

type gatewayPolicyKeysFile struct {
	Keys []gatewayPolicyKeyEntry `json:"keys"`
}

type gatewayPolicyKeyEntry struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func loadGatewayPolicyKeys(path string) (policy.GatewayPolicyKeys, error) {
	if !validGatewayPath(path, false) {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximumGatewayKeysFileBytes || before.Mode().Perm()&0o022 != 0 {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	file, err := root.Open(name)
	if err != nil {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximumGatewayKeysFileBytes+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !os.SameFile(before, after) || len(raw) < 1 || len(raw) > maximumGatewayKeysFileBytes {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	var payload gatewayPolicyKeysFile
	if strictGatewayJSON(raw, &payload) != nil || len(payload.Keys) < 1 || len(payload.Keys) > 32 {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(raw, canonical) {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	values := make(map[string]ed25519.PublicKey, len(payload.Keys))
	for _, entry := range payload.Keys {
		if _, exists := values[entry.KeyID]; exists || !gatewayRepositoryKeyIDPattern.MatchString(entry.KeyID) {
			return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
		}
		decoded, err := base64.RawURLEncoding.DecodeString(entry.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != entry.PublicKey {
			return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
		}
		values[entry.KeyID] = ed25519.PublicKey(decoded)
	}
	keys, err := policy.NewGatewayPolicyKeys(values)
	if err != nil {
		return policy.GatewayPolicyKeys{}, errRuntimeUnavailable
	}
	return keys, nil
}
