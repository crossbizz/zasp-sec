package runtimeservices

import (
	"testing"
	"time"
)

func localEnvironment() map[string]string {
	return map[string]string{
		"ZASP_RUNTIME_SERVICES_ENABLED": "true", "ZASP_ENVIRONMENT": "development",
		"ZASP_TEMPORAL_ADDRESS": "127.0.0.1:7233", "ZASP_TEMPORAL_NAMESPACE": "zasp-dev",
		"ZASP_TEMPORAL_TASK_QUEUE": "zasp-agent", "ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE": "zasp-discovery",
		"ZASP_OPENFGA_URL": "http://127.0.0.1:8088", "ZASP_OPENFGA_STORE_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"ZASP_OPENFGA_MODEL_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAW", "ZASP_OPENFGA_TOKEN_FILE": "/tmp/fga-token",
		"ZASP_RUNTIME_SERVICES_TIMEOUT": "2s",
	}
}

// Catches missing scope, unsafe transport, malformed flags and unbounded deadlines.
func TestConfigurationAuthority(t *testing.T) {
	base := localEnvironment()
	c, err := Load(func(k string) string { return base[k] })
	if err != nil || !c.Enabled || c.Timeout != 2*time.Second {
		t.Fatalf("valid local config rejected: %v", err)
	}
	for _, field := range []string{"ZASP_TEMPORAL_ADDRESS", "ZASP_TEMPORAL_NAMESPACE", "ZASP_TEMPORAL_TASK_QUEUE", "ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE", "ZASP_OPENFGA_STORE_ID", "ZASP_OPENFGA_MODEL_ID", "ZASP_OPENFGA_TOKEN_FILE"} {
		t.Run(field, func(t *testing.T) {
			values := localEnvironment()
			delete(values, field)
			if _, err := Load(func(k string) string { return values[k] }); err == nil {
				t.Fatal("missing authority accepted")
			}
		})
	}
	for _, change := range []struct{ key, value string }{
		{"ZASP_RUNTIME_SERVICES_ENABLED", "perhaps"}, {"ZASP_ENVIRONMENT", "production"},
		{"ZASP_TEMPORAL_ADDRESS", "public.example:7233"}, {"ZASP_OPENFGA_URL", "http://fga.internal:8080"},
		{"ZASP_TEMPORAL_ADDRESS", "127.0.0.1:bad-port"}, {"ZASP_OPENFGA_URL", "http://127.0.0.1:99999"},
		{"ZASP_OPENFGA_URL", "http://token@127.0.0.1:8088"}, {"ZASP_OPENFGA_MODEL_ID", "latest"},
		{"ZASP_RUNTIME_SERVICES_TIMEOUT", "0s"}, {"ZASP_RUNTIME_SERVICES_TIMEOUT", "1h"},
		{"ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE", "zasp-agent"}, {"ZASP_TEMPORAL_TLS_CERT_FILE", "/tmp/cert"},
	} {
		t.Run(change.key+change.value, func(t *testing.T) {
			values := localEnvironment()
			values[change.key] = change.value
			if _, err := Load(func(k string) string { return values[k] }); err == nil {
				t.Fatal("invalid enabled config accepted")
			}
		})
	}
	if c, err := Load(func(string) string { return "" }); err != nil || c.Enabled {
		t.Fatal("disabled adoption must preserve existing startup")
	}
}
