package main

import (
	"testing"
	"time"
)

func TestLoadSensorAgentConfigRequiresExactProductionAuthority(t *testing.T) {
	t.Parallel()
	values := validSensorAgentEnvironment()
	config, err := loadSensorAgentConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("loadSensorAgentConfig: %v", err)
	}
	if config.ControlPlaneURL != "https://runtime.example.test" || config.TokenFile != "/var/run/secrets/zasp-sensor/token" || config.LogFile != "/var/run/cilium/tetragon/tetragon.log" || config.CursorFile != "/var/lib/zasp-sensor/cursor.json" || config.BatchSize != 100 || config.MaximumProcesses != 10_000 || config.PollInterval != time.Second || config.OperationTimeout != 10*time.Second || config.ShutdownTimeout != 15*time.Second {
		t.Fatalf("config = %#v", config)
	}
	for _, name := range []string{"ZASP_SENSOR_CONTROL_PLANE_URL", "ZASP_SENSOR_TOKEN_FILE", "ZASP_TETRAGON_LOG_FILE", "ZASP_SENSOR_CURSOR_FILE", "ZASP_SENSOR_BATCH_SIZE", "ZASP_SENSOR_MAX_PROCESSES", "ZASP_SENSOR_POLL_INTERVAL", "ZASP_SENSOR_OPERATION_TIMEOUT", "ZASP_SENSOR_SHUTDOWN_TIMEOUT"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed := cloneEnvironment(values)
			delete(changed, name)
			if _, err := loadSensorAgentConfig(func(key string) string { return changed[key] }); err == nil {
				t.Fatalf("missing %s accepted", name)
			}
		})
	}
}

func TestLoadSensorAgentConfigRejectsAmbientOrUnsafeValues(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(map[string]string){
		"http control plane":      func(value map[string]string) { value["ZASP_SENSOR_CONTROL_PLANE_URL"] = "http://runtime.example.test" },
		"control plane path":      func(value map[string]string) { value["ZASP_SENSOR_CONTROL_PLANE_URL"] += "/api" },
		"relative token":          func(value map[string]string) { value["ZASP_SENSOR_TOKEN_FILE"] = "token" },
		"shared token and cursor": func(value map[string]string) { value["ZASP_SENSOR_CURSOR_FILE"] = value["ZASP_SENSOR_TOKEN_FILE"] },
		"oversized batch":         func(value map[string]string) { value["ZASP_SENSOR_BATCH_SIZE"] = "1001" },
		"excess process cache":    func(value map[string]string) { value["ZASP_SENSOR_MAX_PROCESSES"] = "100001" },
		"fast poll":               func(value map[string]string) { value["ZASP_SENSOR_POLL_INTERVAL"] = "49ms" },
		"slow operation":          func(value map[string]string) { value["ZASP_SENSOR_OPERATION_TIMEOUT"] = "31s" },
		"short shutdown":          func(value map[string]string) { value["ZASP_SENSOR_SHUTDOWN_TIMEOUT"] = "4s" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			values := validSensorAgentEnvironment()
			mutate(values)
			if config, err := loadSensorAgentConfig(func(key string) string { return values[key] }); err == nil || config != (sensorAgentConfig{}) {
				t.Fatalf("loadSensorAgentConfig = %#v, %v", config, err)
			}
		})
	}
}

func validSensorAgentEnvironment() map[string]string {
	return map[string]string{
		"ZASP_SENSOR_CONTROL_PLANE_URL": "https://runtime.example.test",
		"ZASP_SENSOR_TOKEN_FILE":        "/var/run/secrets/zasp-sensor/token",
		"ZASP_TETRAGON_LOG_FILE":        "/var/run/cilium/tetragon/tetragon.log",
		"ZASP_SENSOR_CURSOR_FILE":       "/var/lib/zasp-sensor/cursor.json",
		"ZASP_SENSOR_BATCH_SIZE":        "100",
		"ZASP_SENSOR_MAX_PROCESSES":     "10000",
		"ZASP_SENSOR_POLL_INTERVAL":     "1s",
		"ZASP_SENSOR_OPERATION_TIMEOUT": "10s",
		"ZASP_SENSOR_SHUTDOWN_TIMEOUT":  "15s",
	}
}

func cloneEnvironment(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
