package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionRuntimeDataPlaneRegistersImmutableV15Authority(t *testing.T) {
	metadata := ProductionRuntimeDataPlane()
	if metadata.Version() != 15 || metadata.Name() != "runtime_data_plane" || len(metadata.Checksum()) != 64 || metadata.UpSQL() == "" || metadata.DownSQL() == "" {
		t.Fatalf("runtime data plane metadata = v%d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, required := range []string{
		"zasp_runtime_data_plane_readiness",
		"zasp_runtime_data_plane_security_ready",
		"zasp_runtime_data_plane_live_fingerprint",
		"runtime_data_plane_fingerprint",
		"runtime-data-plane-v1",
		"zasp_runtime_authenticate_sensor",
		"zasp_runtime_sensor_heartbeat",
		"zasp_runtime_sensor_mutations",
		"zasp_runtime_public_sensor_page",
		"zasp_runtime_public_sensor_detail",
		"zasp_runtime_public_sensor_coverage",
		"zasp_runtime_public_sensor_token_authority",
		"zasp_runtime_public_create_sensor",
		"zasp_runtime_public_update_sensor",
		"zasp_runtime_public_delete_sensor",
		"zasp_runtime_public_rotate_sensor",
		"zasp_runtime_reconcile_batch",
		"zasp_runtime_commit_reserved_batch",
		"zasp_runtime_claim_outbox",
		"zasp_runtime_heartbeat_outbox",
		"zasp_runtime_ack_outbox",
		"zasp_runtime_retry_outbox",
		"zasp_runtime_gateway_enrollment_secret_hash",
		"zasp_runtime_issue_gateway_enrollment",
		"zasp_runtime_authenticate_gateway_enrollment",
		"zasp_runtime_gateway_enroll",
		"zasp_runtime_gateway_credential_authority",
		"zasp_runtime_gateway_advance_replay",
		"zasp_runtime_gateway_put_policy_bundle",
		"zasp_runtime_gateway_policy_bundle",
		"zasp_runtime_gateway_record_event",
		"runtime-gateway-policy",
		"Ed25519",
		"locator_digest",
		"token_generation",
		"sensor_version_at_issue",
		"last_authenticated_at",
		"zasp_runtime_coordinator",
		"zasp_runtime_archive_worker",
		"zasp_runtime_index_worker",
		"zasp_runtime_correlation_worker",
		"zasp_runtime_projection_worker",
		"zasp_gateway_control",
		"SECURITY DEFINER",
		"SET search_path TO pg_catalog, public",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("runtime data plane migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"ALTER TABLE zasp_sensor_tokens ADD COLUMN locator ",
		"ALTER TABLE zasp_sensor_tokens ADD COLUMN secret ",
		"CREATE TABLE zasp_runtime_raw_events",
		"GRANT SELECT ON zasp_sensor_tokens",
		"zasp_sensor_v1.",
	} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("runtime data plane migration persists or grants secret authority %q", forbidden)
		}
	}
	fingerprint := ProductionRuntimeDataPlaneSemanticFingerprint()
	if len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) || !strings.Contains(metadata.DownSQL(), fingerprint) {
		t.Fatalf("runtime data plane fingerprint = %q", fingerprint)
	}
}

func TestRunnerProductionRuntimeDataPlaneRequiresExactV14AndV15Readiness(t *testing.T) {
	adjacent := []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover()}
	runtime := append(append([]Metadata(nil), adjacent...), ProductionRuntimeDataPlane())

	t.Run("preflight drift is mutation free", func(t *testing.T) {
		transaction := &fakeTransaction{rows: append(exactReleaseRows(adjacent...), fakeRow{values: []any{false}})}
		database := &fakeDatabase{transaction: transaction}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionRuntimeDataPlane(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("preflight error = %v", err)
		}
		if contains(database.events, "exec:"+compactSQL(ProductionRuntimeDataPlane().UpSQL())) {
			t.Fatal("preflight drift mutated v15")
		}
	})

	t.Run("postflight drift rolls back", func(t *testing.T) {
		rows := append(exactReleaseRows(adjacent...), fakeRow{values: []any{true}})
		rows = append(rows, exactReleaseRows(runtime...)...)
		rows = append(rows, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionRuntimeDataPlane(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("postflight error = %v", err)
		}
		if !contains(database.events, "rollback") {
			t.Fatalf("postflight events = %#v", database.events)
		}
	})

	t.Run("used runtime authority blocks rollback before mutation", func(t *testing.T) {
		rows := append(exactReleaseRows(runtime...), fakeRow{values: []any{true}}, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.DownProductionRuntimeDataPlane(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("runtime rollback error = %v", err)
		}
		if contains(database.events, "exec:"+compactSQL(deleteRowSQL)) || contains(database.events, "exec:"+compactSQL(ProductionRuntimeDataPlane().DownSQL())) {
			t.Fatalf("blocked rollback mutated v15: %#v", database.events)
		}
	})
}
