package migrations

import (
	"strings"
	"testing"
)

func TestProductionDiscoveryExecutionMigrationOwnsLeasedExecutionAuthority(t *testing.T) {
	metadata := ProductionDiscoveryExecution()
	if metadata.Version() != 13 || metadata.Name() != "production_discovery_execution" || len(metadata.Checksum()) != 64 {
		t.Fatalf("production discovery execution metadata = v%d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, required := range []string{
		"zasp_discovery_execution_principals",
		"zasp_discovery_connection_subjects",
		"zasp_discovery_execution_quotas",
		"zasp_discovery_generation_reservations",
		"zasp_discovery_job_authorities",
		"zasp_discovery_job_checkpoints",
		"zasp_discovery_snapshot_inputs",
		"zasp_discovery_snapshot_projection_items",
		"zasp_discovery_projection_cursors",
		"zasp_execution_claim_delivery",
		"zasp_execution_claim_jobs",
		"zasp_execution_job_input",
		"zasp_execution_heartbeat_job",
		"zasp_execution_checkpoint_partial",
		"zasp_execution_finish_job",
		"zasp_execution_request_scheduled_sync",
		"zasp_execution_complete_schedule",
		"zasp_execution_schedule_input",
		"zasp_execution_heartbeat_schedule",
		"zasp_execution_apply_complete_snapshot",
		"zasp_execution_snapshot_projection_page",
		"zasp_execution_advance_projection_cursor",
		"zasp_execution_sync_detail",
		"zasp_execution_sync_history",
		"zasp_execution_schedule_detail",
		"zasp_execution_last_good_freshness",
		"zasp_execution_public_request_sync",
		"zasp_execution_public_put_schedule",
		"zasp_execution_public_delete_schedule",
		"zasp_execution_heartbeat_projection",
		"zasp_discovery_projection_receipts",
		"integration_sync",
		"integration_schedule",
		"zasp_execution_readiness",
		"production_discovery_execution_fingerprint",
		"SECURITY DEFINER",
		"SET search_path TO pg_catalog, public",
		"attempt<5",
		"SELECT * INTO input_row FROM zasp_discovery_snapshot_inputs",
		"shobj_description",
		"pg_auth_members",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("production discovery execution migration missing %q", required)
		}
	}
	if fingerprint := ProductionDiscoveryExecutionSemanticFingerprint(); len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) || !strings.Contains(metadata.DownSQL(), fingerprint) {
		t.Fatalf("production discovery execution fingerprint = %q", fingerprint)
	}
	if strings.Contains(metadata.UpSQL(), "SELECT * INTO STRICT input_row FROM zasp_discovery_snapshot_inputs") {
		t.Fatal("freshness fails on legacy snapshots without v13 snapshot input authority")
	}
	if strings.Contains(metadata.UpSQL(), "attempt<100") {
		t.Fatal("projection claim index permits attempts beyond the terminal budget")
	}
	for _, required := range []string{"semantic schema drift blocks rollback", "production discovery execution data blocks rollback", "requestIntegrationSync", "putIntegrationSchedule", "deleteIntegrationSchedule", "reference-authorization-v1"} {
		if !strings.Contains(metadata.DownSQL(), required) {
			t.Fatalf("production discovery execution rollback missing %q", required)
		}
	}
}
