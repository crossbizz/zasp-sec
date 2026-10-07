package runtimeservices

import (
	"strings"
	"testing"
)

func TestApprovalMaintenanceProfileSelectionConfiguration(t *testing.T) {
	for _, pin := range []string{"", strings.Repeat("a", 64)} {
		values := localEnvironment()
		values["ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM"] = pin
		got, err := Load(func(key string) string { return values[key] })
		if err != nil || got.ApprovalMaintenanceProfileChecksum != pin {
			t.Fatal("exact optional profile selection rejected")
		}
	}
	for _, pin := range []string{"latest", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), " " + strings.Repeat("a", 64)} {
		values := localEnvironment()
		values["ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM"] = pin
		if _, err := Load(func(key string) string { return values[key] }); err == nil {
			t.Fatal("noncanonical profile selection accepted")
		}
	}
	values := localEnvironment()
	values["ZASP_RUNTIME_SERVICES_ENABLED"] = "false"
	values["ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM"] = strings.Repeat("a", 64)
	if _, err := Load(func(key string) string { return values[key] }); err == nil {
		t.Fatal("profile selection silently ignored with services disabled")
	}
}
