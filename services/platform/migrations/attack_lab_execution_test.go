package migrations

import (
	"strings"
	"testing"
)

func TestProductionAttackLabExecutionPinsDerivedMultiTenantAuthority(t *testing.T) {
	metadata := ProductionAttackLabExecution()
	if metadata.Version() != 26 || metadata.Name() != "attack_lab_execution" || len(metadata.Checksum()) != 64 || len(ProductionAttackLabExecutionSemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionAttackLabExecutionSemanticFingerprint())
	}
	for _, required := range []string{
		"zasp_attack_lab_runs", "zasp_attack_lab_attempts", "zasp_attack_lab_outbox", "zasp_attack_lab_request_receipts", "zasp_attack_lab_audit",
		"zasp_attack_lab_register_principals", "zasp_attack_lab_preflight", "zasp_attack_lab_create_run", "zasp_attack_lab_cancel_run", "zasp_attack_lab_rerun", "zasp_attack_lab_execution_readiness",
		"source_run_id", "state,verdict)=(organization_value,workspace_value,environment_value,source_run_value,'complete','fail')", "zasp_red_team_target_binding_valid",
		"decision_digest", "decision_expires_at", "credential_binding_version", "target_attributes_digest",
		"'evidence_version_id'", "'evidence_checksum'", "'evidence_size'",
		"'cpu','500m'", "'memory','1Gi'", "'ephemeral_storage','2Gi'", "'timeout_seconds',300", "attack-lab-jobs", "organization_id,workspace_id,environment_id",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("v26 up migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"production_write", "'environment','production'", "client_destination", "client_credential", "shell_command"} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("v26 migration admits client or production authority %q", forbidden)
		}
	}
	if !strings.Contains(metadata.DownSQL(), "attack lab execution rollback rejected") || !strings.Contains(metadata.DownSQL(), "zasp_attack_lab_execution_live_fingerprint") {
		t.Fatal("v26 down is not live-authority guarded")
	}
}
