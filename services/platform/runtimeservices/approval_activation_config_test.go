package runtimeservices

import (
	"strings"
	"testing"
)

func TestApprovalActivationRequiresExplicitMaintenanceSelection(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, activation, approval, connector, enabled string
		valid                                          bool
	}{
		{"complete", pin, pin, pin, "true", true},
		{"absent", "", "", "", "true", true},
		{"missing approval", pin, "", pin, "true", false},
		{"missing connector", pin, pin, "", "true", false},
		{"noncanonical", strings.ToUpper(pin), pin, pin, "true", false},
		{"disabled", pin, pin, pin, "false", false},
		{"disabled activation alone", pin, "", "", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := localEnvironment()
			values["ZASP_RUNTIME_SERVICES_ENABLED"] = tc.enabled
			values["ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM"] = tc.activation
			values["ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM"] = tc.approval
			values["ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM"] = tc.connector
			cfg, err := Load(func(k string) string { return values[k] })
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
			if tc.valid && cfg.ApprovalActivationProfileChecksum != tc.activation {
				t.Fatal("explicit selection lost")
			}
		})
	}
}
