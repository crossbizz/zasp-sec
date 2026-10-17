package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This group exercises the real configuration loader. It does not establish
// database readiness, authenticated delivery, or coverage of an Agent.
func TestNodeCoverageRetentionConfigRefusesImplicitAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, enabled, pin, profile string
		wantOK                      bool
	}{
		{"legacy-default", "", "", "", true},
		{"explicit-disabled", "false", "", "", true},
		{"disabled-with-pin", "false", strings.Repeat("a", 64), migrations.AuthorizationRuntimeProfileName, false},
		{"implicit-enable-from-pin", "", strings.Repeat("a", 64), migrations.AuthorizationRuntimeProfileName, false},
		{"unknown-flag", "yes", "", migrations.AuthorizationRuntimeProfileName, false},
		{"whitespace-flag", " true", "", migrations.AuthorizationRuntimeProfileName, false},
		{"enabled-missing-pin", "true", "", migrations.AuthorizationRuntimeProfileName, false},
		{"enabled-wrong-pin", "true", strings.Repeat("a", 64), migrations.AuthorizationRuntimeProfileName, false},
		{"enabled-legacy-parent", "true", strings.Repeat("a", 64), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := validProductionIngestEnvironment()
			values["ZASP_SENSOR_NODE_COVERAGE_RETENTION_ENABLED"] = tc.enabled
			values["ZASP_SENSOR_NODE_COVERAGE_PROFILE_CHECKSUM"] = tc.pin
			values["ZASP_RUNTIME_DATABASE_PROFILE"] = tc.profile
			_, err := loadProductionIngestConfig(func(key string) string { return values[key] })
			if tc.wantOK && err != nil || !tc.wantOK && !errors.Is(err, errRuntimeUnavailable) {
				t.Fatal("retained coverage configuration did not preserve explicit current authority")
			}
		})
	}
}
