package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionIdentityAdministrationMetadataOwnsDurableProviderAuthority(t *testing.T) {
	metadata := ProductionIdentityAdministration()
	if metadata.Version() != 19 || metadata.Name() != "identity_administration" || len(metadata.Checksum()) != 64 {
		t.Fatalf("metadata = (%d, %q, %q)", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, expected := range []string{
		"zasp_identity_administration_state", "zasp_identity_provider_connections", "zasp_identity_provider_mutations",
		"zasp_identity_secret_reveal_grants", "zasp_identity_webhook_events", "zasp_identity_admin_reserve_mutation",
		"zasp_identity_member_groups", "zasp_identity_admin_effective_scopes", "zasp_identity_admin_resolve_session", "zasp_group_mappings_scope_fkey",
		"zasp_identity_admin_complete_mutation", "zasp_identity_admin_mark_unknown", "zasp_identity_admin_connection_page",
		"zasp_identity_admin_reveal_secret", "zasp_identity_admin_ack_secret", "zasp_identity_admin_reconcile_deprovision",
		"zasp_identity_administration_live_fingerprint", "zasp_identity_administration_readiness",
	} {
		if !strings.Contains(metadata.UpSQL(), expected) || !strings.Contains(metadata.DownSQL(), expected) {
			t.Fatalf("migration missing %q", expected)
		}
	}
	if fingerprint := ProductionIdentityAdministrationSemanticFingerprint(); len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
}

func TestRunnerProductionIdentityAdministrationRequiresExactV18AndV19Readiness(t *testing.T) {
	throughV18 := []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation(), ProductionSecurityAgentExecution()}
	t.Run("rejects v18 drift before mutation", func(t *testing.T) {
		database := &fakeDatabase{transaction: &fakeTransaction{rows: append(exactReleaseRows(throughV18...), fakeRow{values: []any{false}})}}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionIdentityAdministration(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("UpProductionIdentityAdministration() error = %v", err)
		}
	})
	t.Run("rejects v19 readiness drift", func(t *testing.T) {
		metadata := ProductionIdentityAdministration()
		rows := append(exactReleaseRows(throughV18...), fakeRow{values: []any{true}})
		rows = append(rows, exactReleaseRows(append(throughV18, metadata)...)...)
		rows = append(rows, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionIdentityAdministration(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("UpProductionIdentityAdministration() error = %v", err)
		}
	})
}
