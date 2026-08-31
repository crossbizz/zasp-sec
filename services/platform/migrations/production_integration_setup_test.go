package migrations

import (
	"strings"
	"testing"
)

func TestProductionIntegrationSetupPinsTenantScopedReadOnlyAuthority(t *testing.T) {
	metadata := ProductionIntegrationSetup()
	fingerprint := ProductionIntegrationSetupSemanticFingerprint()
	if metadata.Version() != 34 || metadata.Name() != "production_integration_setup" || len(metadata.Checksum()) != 64 || len(fingerprint) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), fingerprint)
	}
	for _, required := range []string{
		"zasp_production_security_agent_attack_path_readiness",
		"zasp_execution_integration_setup_status",
		"organization_value,workspace_value,environment_value,integration_value",
		"zasp_discovery_connection_subjects",
		"zasp_connector_credentials",
		"github_organization",
		"repository_selection",
		"okta.apps.read",
		"zasp_sensor_heartbeats",
		"unsupported_kernel",
		"missing_gateway",
		"GRANT EXECUTE ON FUNCTION public.zasp_execution_integration_setup_status(text,text,text,text,text,text) TO zasp_discovery_api",
		"NOT has_table_privilege('zasp_discovery_api','public.zasp_connector_credentials','SELECT')",
		"NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>34)",
		"production_integration_setup_fingerprint', '" + fingerprint,
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"credential_reference'", "installation_id'", "refresh_token", "client_secret"} {
		if strings.Contains(metadata.UpSQL()[strings.Index(metadata.UpSQL(), "RETURN jsonb_build_object('integration_id'"):], forbidden) {
			t.Errorf("public result contains forbidden authority %q", forbidden)
		}
	}
	if !strings.Contains(metadata.DownSQL(), fingerprint) || !strings.Contains(metadata.DownSQL(), "DROP FUNCTION public.zasp_execution_integration_setup_status") || !strings.Contains(metadata.DownSQL(), `later_release."version" > 33`) {
		t.Fatalf("down migration does not restore exact v33 authority")
	}
}
