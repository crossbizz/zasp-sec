package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionRuntimeIngestReconciliationRegistersImmutableV17(t *testing.T) {
	metadata := ProductionRuntimeIngestReconciliation()
	if metadata.Version() != 17 || metadata.Name() != "runtime_ingest_reconciliation" || len(metadata.Checksum()) != 64 || metadata.UpSQL() == "" || metadata.DownSQL() == "" {
		t.Fatalf("runtime ingest reconciliation metadata=v%d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, required := range []string{
		"zasp_runtime_ingest_reconciliation_readiness",
		"zasp_runtime_ingest_reconciliation_security_ready",
		"zasp_runtime_ingest_reconciliation_live_fingerprint",
		"runtime_ingest_reconciliation_fingerprint",
		"zasp_runtime_reserve_batch_v17",
		"zasp_runtime_finalize_batch_v17",
		"zasp_runtime_claim_reconciliation",
		"zasp_runtime_release_reconciliation",
		"zasp_runtime_finish_reconciliation",
		"zasp_runtime_quarantine_reconciliation",
		"zasp_runtime_reserve_batch_v15_internal",
		"zasp_runtime_finalize_batch_v15_internal",
		"zasp_runtime_ingest_reconciliation_state",
		"zasp_runtime_ingest_reconciliation_work",
		"SECURITY DEFINER",
		"SET search_path TO pg_catalog, public",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("runtime ingest reconciliation migration missing %q", required)
		}
	}
	fingerprint := ProductionRuntimeIngestReconciliationSemanticFingerprint()
	if len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) || !strings.Contains(metadata.DownSQL(), fingerprint) {
		t.Fatalf("runtime ingest reconciliation fingerprint=%q", fingerprint)
	}
}

func TestRunnerProductionRuntimeIngestReconciliationRequiresExactV16AndV17Readiness(t *testing.T) {
	throughV16 := []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation()}
	throughV17 := append(append([]Metadata(nil), throughV16...), ProductionRuntimeIngestReconciliation())

	t.Run("preflight drift is mutation free", func(t *testing.T) {
		transaction := &fakeTransaction{rows: append(exactReleaseRows(throughV16...), fakeRow{values: []any{false}})}
		database := &fakeDatabase{transaction: transaction}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionRuntimeIngestReconciliation(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("preflight error=%v", err)
		}
		if contains(database.events, "exec:"+compactSQL(ProductionRuntimeIngestReconciliation().UpSQL())) {
			t.Fatalf("preflight drift mutated v17: %#v", database.events)
		}
	})

	t.Run("postflight drift rolls back", func(t *testing.T) {
		rows := append(exactReleaseRows(throughV16...), fakeRow{values: []any{true}})
		rows = append(rows, exactReleaseRows(throughV17...)...)
		rows = append(rows, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionRuntimeIngestReconciliation(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("postflight error=%v", err)
		}
		if !contains(database.events, "rollback") {
			t.Fatalf("postflight events=%#v", database.events)
		}
	})
}
