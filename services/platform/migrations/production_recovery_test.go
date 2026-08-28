package migrations

import (
	"strings"
	"testing"
)

func TestProductionRecoveryPinsTenantScopedExecutionAuthority(t *testing.T) {
	metadata := ProductionRecovery()
	if metadata.Version() != 27 || metadata.Name() != "production_recovery" || len(metadata.Checksum()) != 64 || len(ProductionRecoverySemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionRecoverySemanticFingerprint())
	}
	for _, required := range []string{
		"zasp_recovery_backups", "zasp_recovery_restores", "zasp_recovery_holds", "zasp_recovery_outbox", "zasp_recovery_fairness", "zasp_recovery_principal_bindings",
		"organization_id,workspace_id,environment_id", "recovery-backup-jobs", "recovery-restore-jobs", "cleanup_required", "failed_cleanup",
		"zasp_recovery_register_principals", "zasp_recovery_create_backup", "zasp_recovery_create_restore", "zasp_recovery_claim_outbox", "zasp_recovery_claim_operation", "zasp_recovery_claim_delivery",
		"zasp_recovery_heartbeat_operation", "zasp_recovery_begin_hold", "zasp_recovery_release_hold", "zasp_recovery_capture_page", "zasp_recovery_finish_backup", "zasp_recovery_finish_restore",
		"zasp_recovery_validate_scope",
		"zasp_recovery_scope_mutable", "zasp_recovery_execution_readiness", "zasp_recovery_execution_live_fingerprint", "zasp_recovery_execution_security_ready",
		"class.relname NOT LIKE 'zasp_recovery_%'", "TG_OP IN('UPDATE','DELETE')", "TG_OP IN('INSERT','UPDATE')",
		"'security_agent:'||definition.definition_id", "'snapshot_inputs'", "'projection_cursors'", "'counts'",
		"manifest_value->>'schema'<>'recovery_signed_manifest_v1'", "manifest_value->>'signing_key_id'", "jsonb_object_keys(manifest_value)",
		"target_environment text NOT NULL CHECK", "target_value='production'", "target_value=environment_value", "'target_environment',target_value", "'manifest',manifest_value",
		"'target_environment',target_environment", "attempt<100", "attempt>=100", "validation_value->'expected_counts'<>observed_value", "next_state='rebuilding'",
		"zasp_recovery_create_restore(text,text,text,text,text,text,text,text,text,text,bytea,jsonb,bytea)",
		"ADD COLUMN policy_ids jsonb", "zasp_runtime_gateway_record_event_v27", "zasp_policy_list_runtime_decisions",
		"zasp_runtime_gateway_events_policy_ids_v27_idx", "USING gin (policy_ids)", "CREATE INDEX zasp_runtime_gateway_events_policy_history_v27_idx ON public.zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,occurred_at DESC,event_id ASC)",
		"policy_ids_value", "jsonb_array_length(value)<=512", "policy_ids ? policy_value", "ORDER BY event.occurred_at DESC,event.event_id ASC",
		"GRANT EXECUTE ON FUNCTION public.zasp_recovery_execution_readiness(text,text) TO zasp_discovery_api,zasp_security_agent_api,zasp_recovery_worker,zasp_recovery_outbox_worker",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("v27 up migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"client_dsn", "database_password", "aws_secret_access_key", "s3_object_key", "neon_api_key"} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("v27 migration admits caller cloud authority %q", forbidden)
		}
	}
	if !strings.Contains(metadata.DownSQL(), "production recovery rollback rejected") || !strings.Contains(metadata.DownSQL(), "zasp_recovery_execution_live_fingerprint") || !strings.Contains(metadata.DownSQL(), "DROP FUNCTION public.zasp_policy_list_runtime_decisions") || !strings.Contains(metadata.DownSQL(), "DROP INDEX public.zasp_runtime_gateway_events_policy_ids_v27_idx") || !strings.Contains(metadata.DownSQL(), "DROP INDEX public.zasp_runtime_gateway_events_policy_history_v27_idx") || !strings.Contains(metadata.DownSQL(), "DROP COLUMN policy_ids") {
		t.Fatal("v27 down is not live-authority guarded")
	}
}

func TestProductionRecoveryFunctionsFenceScopeLeaseAndDigest(t *testing.T) {
	up := ProductionRecovery().UpSQL()
	for _, required := range []string{
		"octet_length(request_digest)=32", "octet_length(lease_token)=32", "attempt BETWEEN 0 AND 100", "retention_days BETWEEN 7 AND 90",
		"FOR UPDATE", "lease_expires_at>transaction_timestamp()", "request_digest<>request_digest_value", "manifest_digest", "payload_digest", "'ack_terminal'", "'retry_later'", "'exhausted'",
		"ENABLE ROW LEVEL SECURITY", "FORCE ROW LEVEL SECURITY", "SECURITY DEFINER SET search_path TO pg_catalog, public",
		"zasp_recovery_worker", "zasp_recovery_outbox_worker", "NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v27 authority missing %q", required)
		}
	}
	if !strings.Contains(up, `to_char(collected_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`) || !strings.Contains(up, `to_char(evidence.collected_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`) {
		t.Fatal("v27 recovery evidence timestamps are not canonical UTC at capture and validation boundaries")
	}
	if strings.Count(up, `'committed_at',to_char(cursor.committed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`) != 2 || strings.Count(up, `'updated_at',to_char(cursor.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`) != 2 {
		t.Fatal("v27 recovery projection timestamps are not canonical UTC at capture and validation boundaries")
	}
}
