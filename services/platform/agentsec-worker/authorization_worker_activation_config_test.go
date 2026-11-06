package main

import (
	"strings"
	"testing"
)

func TestTemporalWorkerRetainsExplicitApprovalActivationSelection(t *testing.T) {
	values := orderedSigningRuntimeEnvironment()
	for k, v := range map[string]string{
		"ZASP_RUNTIME_SERVICES_ENABLED": "true", "ZASP_ENVIRONMENT": "test", "ZASP_RUNTIME_SERVICES_TIMEOUT": "5s",
		"ZASP_TEMPORAL_ADDRESS": "127.0.0.1:7233", "ZASP_TEMPORAL_NAMESPACE": "zasp-test", "ZASP_TEMPORAL_TASK_QUEUE": "zasp-security", "ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE": "zasp-discovery",
		"ZASP_OPENFGA_URL": "http://127.0.0.1:8080", "ZASP_OPENFGA_STORE_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "ZASP_OPENFGA_MODEL_ID": "01ARZ3NDEKTSV4RRFFQ69G5FAW", "ZASP_OPENFGA_TOKEN_FILE": "/var/run/zasp-token",
		"ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM": strings.Repeat("a", 64), "ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM": strings.Repeat("b", 64), "ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM": strings.Repeat("c", 64),
	} {
		values[k] = v
	}
	cfg, err := loadWorkerRuntimeConfig(mapLookup(values))
	if err != nil || cfg.RuntimeServices.ApprovalActivationProfileChecksum != values["ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM"] {
		t.Fatalf("explicit activation not retained: %v", err)
	}
	for _, missing := range []string{"ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM", "ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM"} {
		bad := cloneStringMap(values)
		delete(bad, missing)
		if _, err := loadWorkerRuntimeConfig(mapLookup(bad)); err == nil {
			t.Fatalf("activation without %s admitted", missing)
		}
	}
}
