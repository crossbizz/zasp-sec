package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
)

func TestSensorNodeCoverageRuntimeExplicitCompiledPin(t *testing.T) {
	if !validSensorNodeCoverageRuntimeConfig(RuntimeConfig{}) {
		t.Fatal("default must remain off")
	}
	for _, pin := range []string{migrations.SensorNodeCoverageProfileChecksum(), migrations.SensorNodeCoverageAuditProfileChecksum()} {
		c := RuntimeConfig{SensorNodeCoverageRetentionEnabled: true, SensorNodeCoverageProfileChecksum: pin}
		if validSensorNodeCoverageRuntimeConfig(c) {
			t.Fatal("missing current runtime admitted")
		}
		c.RuntimeServices.Enabled = true
		if !validSensorNodeCoverageRuntimeConfig(c) {
			t.Fatal("compiled pin refused")
		}
		c.SensorNodeCoverageProfileChecksum = strings.Repeat("f", 64)
		if validSensorNodeCoverageRuntimeConfig(c) {
			t.Fatal("arbitrary pin admitted")
		}
		c.SensorNodeCoverageRetentionEnabled = false
		if validSensorNodeCoverageRuntimeConfig(c) {
			t.Fatal("disabled profile accepted pin")
		}
	}
	for _, flag := range []string{"TRUE", "1", "yes"} {
		env := fixtureRuntimeEnvironment()
		env["ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED"] = flag
		if _, err := loadRuntimeConfig(func(k string) string { return env[k] }); err == nil {
			t.Fatal("noncanonical enable flag admitted")
		}
	}
}
