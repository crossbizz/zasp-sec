package main

import "testing"

// Catches entrypoint parsers silently ignoring a requested dependency adoption.
func TestRuntimeServicesRejectPartialEnabledConfig(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	values["ZASP_RUNTIME_SERVICES_ENABLED"] = "true"
	if _, err := loadRuntimeConfig(func(k string) string { return values[k] }); err == nil {
		t.Fatal("enabled Temporal/OpenFGA configuration without authority accepted")
	}
}
