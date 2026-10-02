package main

import (
	"errors"
	"testing"
)

func orderedSigningRuntimeEnvironment() map[string]string {
	return map[string]string{
		"ZASP_WORKER_MODE": "security-agent", "ZASP_POSTGRES_DSN": "postgres://security_agent@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_DATABASE_AUTHORITY": "zasp_security_agent_worker", "ZASP_WORKER_ID": "security-agent-worker-01",
		"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
		"ZASP_SECURITY_AGENT_PLANNER_ENDPOINT": "https://openrouter.ai/api/v1/chat/completions", "ZASP_SECURITY_AGENT_PLANNER_MODEL": "openai/gpt-5-mini",
		"ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE": "/var/run/secrets/zasp-security-agent/openrouter-api-token", "ZASP_SECURITY_AGENT_PLANNER_TIMEOUT": "10s",
		"ZASP_SECURITY_AGENT_PLANNER_MAX_TOKENS": "512", "ZASP_SECURITY_AGENT_PLANNER_POLICY_VERSION": "security-agent-planner-v1",
	}
}

// Ignoring the mounted public-verifier setting would leave the constructor
// deriving trust from its private signer and accepting a misconfigured mount.
func TestOrderedSigningRuntimeRejectsWrongVerifierMount(t *testing.T) {
	for _, path := range []string{"/tmp/keys.json", "/var/run/zasp-policy-verifier/../policy-keys.json", "/var/run/zasp-temporal-provider/gateway-signing-private-key"} {
		environment := orderedSigningRuntimeEnvironment()
		environment["ZASP_GATEWAY_POLICY_KEYS_FILE"] = path
		if _, err := loadWorkerRuntimeConfig(mapLookup(environment)); !errors.Is(err, errWorkerConfiguration) {
			t.Fatal("unrecognized verifier mount was ignored or accepted")
		}
	}
}

func TestOrderedSigningRuntimeReadsVerifierMount(t *testing.T) {
	environment := orderedSigningRuntimeEnvironment()
	environment["ZASP_GATEWAY_POLICY_KEYS_FILE"] = "/var/run/zasp-policy-verifier/policy-keys.json"
	cfg, err := loadWorkerRuntimeConfig(mapLookup(environment))
	if err != nil || cfg.GatewayPolicyKeysFile != environment["ZASP_GATEWAY_POLICY_KEYS_FILE"] {
		t.Fatal("runtime did not retain the independent public verifier mount")
	}
}
