package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionRuntimeGatewayReconciliationRegistersImmutableV16Authority(t *testing.T) {
	metadata := ProductionRuntimeGatewayReconciliation()
	if metadata.Version() != 16 || metadata.Name() != "runtime_gateway_reconciliation" || len(metadata.Checksum()) != 64 || metadata.UpSQL() == "" || metadata.DownSQL() == "" || len(ProductionRuntimeGatewayReconciliationSemanticFingerprint()) != 64 {
		t.Fatalf("runtime gateway reconciliation metadata=v%d/%q/%q fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionRuntimeGatewayReconciliationSemanticFingerprint())
	}
	for _, required := range []string{
		"zasp_runtime_gateway_reconciliation_state",
		"zasp_runtime_gateway_reconciliation_live_fingerprint",
		"zasp_runtime_gateway_reconciliation_security_ready",
		"zasp_runtime_gateway_reconciliation_readiness",
		"runtime_gateway_reconciliation_fingerprint",
		"zasp_runtime_gateway_record_event",
		"zasp_inventory_record_capability_evidence",
		"capability_category",
		"capability_outcome",
		"zasp_workflow_mutate",
		"zasp_risk_mutate",
		"release.\"version\" = 16",
		"runtime_gateway_reconciliation",
		"used_at=COALESCE(used_at,transaction_timestamp())",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("runtime gateway reconciliation migration missing %q", required)
		}
	}
	fingerprint := ProductionRuntimeGatewayReconciliationSemanticFingerprint()
	if !strings.Contains(metadata.UpSQL(), fingerprint) || !strings.Contains(metadata.DownSQL(), fingerprint) {
		t.Fatalf("runtime gateway reconciliation fingerprint=%q", fingerprint)
	}
	existingEvent := strings.Index(metadata.UpSQL(), "SELECT * INTO existing_value FROM zasp_runtime_gateway_events")
	expiredEvent := strings.Index(metadata.UpSQL(), "IF occurred_value<transaction_timestamp()-interval '24 hours'")
	capabilityEvidence := strings.Index(metadata.UpSQL(), "PERFORM zasp_inventory_record_capability_evidence")
	advanceFloor := strings.Index(metadata.UpSQL(), "PERFORM zasp_runtime_gateway_advance_replay")
	if existingEvent < 0 || expiredEvent < 0 || capabilityEvidence < 0 || advanceFloor < 0 || !(existingEvent < expiredEvent && expiredEvent < capabilityEvidence && capabilityEvidence < advanceFloor) {
		t.Fatalf("exact replay and age gate must precede capability/replay mutation: existing=%d expired=%d evidence=%d advance=%d", existingEvent, expiredEvent, capabilityEvidence, advanceFloor)
	}
	if !strings.Contains(metadata.DownSQL(), "PERFORM zasp_inventory_record_capability_evidence") {
		t.Fatal("v16 down does not restore v15 capability evidence authority")
	}
}

func TestRunnerProductionRuntimeGatewayReconciliationRequiresExactV15AndV16Readiness(t *testing.T) {
	throughV15 := []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane()}
	throughV16 := append(append([]Metadata(nil), throughV15...), ProductionRuntimeGatewayReconciliation())

	t.Run("preflight drift is mutation free", func(t *testing.T) {
		transaction := &fakeTransaction{rows: append(exactReleaseRows(throughV15...), fakeRow{values: []any{false}})}
		database := &fakeDatabase{transaction: transaction}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionRuntimeGatewayReconciliation(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("preflight error=%v", err)
		}
		if contains(database.events, "exec:"+compactSQL(ProductionRuntimeGatewayReconciliation().UpSQL())) {
			t.Fatalf("preflight drift mutated v16: %#v", database.events)
		}
	})

	t.Run("used reconciliation blocks rollback before mutation", func(t *testing.T) {
		rows := append(exactReleaseRows(throughV16...), fakeRow{values: []any{true}}, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.DownProductionRuntimeGatewayReconciliation(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("rollback error=%v", err)
		}
		if contains(database.events, "exec:"+compactSQL(deleteRowSQL)) || contains(database.events, "exec:"+compactSQL(ProductionRuntimeGatewayReconciliation().DownSQL())) {
			t.Fatalf("blocked rollback mutated v16: %#v", database.events)
		}
	})
}
