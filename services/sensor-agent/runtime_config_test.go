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
	if config.ControlPlaneURL != "https://runtime.example.test" || config.TokenFile != "/var/run/secrets/zasp-sensor/token" || config.LogFile != "/var/run/cilium/tetragon/tetragon.log" || config.CursorFile != "/var/lib/zasp-sensor/cursor.json" || config.Namespace != "agentsec" || config.PodName != "sensor-agent-a" || config.NodeName != "node-a" || config.KernelFile != "/proc/sys/kernel/osrelease" || config.BTFFile != "/sys/kernel/btf/vmlinux" || config.MetricsURL != "http://10.0.0.8:2112/metrics" || config.BatchSize != 100 || config.MaximumProcesses != 10_000 || config.PollInterval != time.Second || config.OperationTimeout != 10*time.Second || config.ShutdownTimeout != 15*time.Second || config.LeaseDuration != 15*time.Second || config.ReportTTL != 30*time.Second {
		t.Fatalf("config = %#v", config)
	}
	for _, name := range []string{"ZASP_SENSOR_CONTROL_PLANE_URL", "ZASP_SENSOR_TOKEN_FILE", "ZASP_TETRAGON_LOG_FILE", "ZASP_SENSOR_CURSOR_FILE", "ZASP_SENSOR_NAMESPACE", "ZASP_SENSOR_POD_NAME", "ZASP_SENSOR_NODE_NAME", "ZASP_SENSOR_KERNEL_FILE", "ZASP_SENSOR_BTF_FILE", "ZASP_TETRAGON_METRICS_URL", "ZASP_SENSOR_BATCH_SIZE", "ZASP_SENSOR_MAX_PROCESSES", "ZASP_SENSOR_POLL_INTERVAL", "ZASP_SENSOR_OPERATION_TIMEOUT", "ZASP_SENSOR_SHUTDOWN_TIMEOUT", "ZASP_SENSOR_LEASE_DURATION", "ZASP_SENSOR_REPORT_TTL"} {
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
		"invalid namespace":       func(value map[string]string) { value["ZASP_SENSOR_NAMESPACE"] = "AgentSec" },
		"relative kernel":         func(value map[string]string) { value["ZASP_SENSOR_KERNEL_FILE"] = "kernel" },
		"shared kernel and btf":   func(value map[string]string) { value["ZASP_SENSOR_BTF_FILE"] = value["ZASP_SENSOR_KERNEL_FILE"] },
		"metrics hostname":        func(value map[string]string) { value["ZASP_TETRAGON_METRICS_URL"] = "http://tetragon:2112/metrics" },
		"metrics wrong port":      func(value map[string]string) { value["ZASP_TETRAGON_METRICS_URL"] = "http://10.0.0.8:2113/metrics" },
		"operation exceeds lease": func(value map[string]string) { value["ZASP_SENSOR_LEASE_DURATION"] = "10s" },
		"report ttl equals lease": func(value map[string]string) { value["ZASP_SENSOR_REPORT_TTL"] = "15s" },
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
		"ZASP_SENSOR_NAMESPACE":         "agentsec",
		"ZASP_SENSOR_POD_NAME":          "sensor-agent-a",
		"ZASP_SENSOR_NODE_NAME":         "node-a",
		"ZASP_SENSOR_KERNEL_FILE":       "/proc/sys/kernel/osrelease",
		"ZASP_SENSOR_BTF_FILE":          "/sys/kernel/btf/vmlinux",
		"ZASP_TETRAGON_METRICS_URL":     "http://10.0.0.8:2112/metrics",
		"ZASP_SENSOR_BATCH_SIZE":        "100",
		"ZASP_SENSOR_MAX_PROCESSES":     "10000",
		"ZASP_SENSOR_POLL_INTERVAL":     "1s",
		"ZASP_SENSOR_OPERATION_TIMEOUT": "10s",
		"ZASP_SENSOR_SHUTDOWN_TIMEOUT":  "15s",
		"ZASP_SENSOR_LEASE_DURATION":    "15s",
		"ZASP_SENSOR_REPORT_TTL":        "30s",
	}
}

func cloneEnvironment(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
