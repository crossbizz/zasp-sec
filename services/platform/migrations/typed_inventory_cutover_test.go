package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionTypedInventoryCutoverRegistersImmutableV14Authority(t *testing.T) {
	metadata := ProductionTypedInventoryCutover()
	if metadata.Version() != 14 || metadata.Name() != "typed_inventory_cutover" || len(metadata.Checksum()) != 64 || metadata.UpSQL() == "" || metadata.DownSQL() == "" {
		t.Fatalf("typed inventory metadata = v%d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, required := range []string{
		"zasp_inventory_authority",
		"zasp_inventory_cutover_state",
		"expanded",
		"backfilled",
		"equivalent",
		"cutover",
		"zasp_inventory_readiness",
		"zasp_inventory_apply_findings",
		"risk projection item set conflict",
		"zasp_execution_apply_risk_projection",
		"GRANT SELECT,INSERT,UPDATE,DELETE ON public.zasp_risk_findings,public.zasp_risk_finding_evidence,public.zasp_risk_attack_paths,public.zasp_risk_attack_path_nodes,public.zasp_risk_attack_path_evidence,public.zasp_risk_break_options TO zasp_discovery_authority",
		"risk attack path ownership conflict",
		"relationship.kind IN('assigned_to','binds','uses_policy','uses_identity','has_permission','depends_on','member_of','trusts')",
		"relationship.kind='trusts'",
		"typed_inventory_cutover_fingerprint",
		"44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30",
		"zasp_execution_readiness",
		"SECURITY DEFINER",
		"SET search_path TO pg_catalog, public",
		"GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api,zasp_discovery_worker,zasp_runtime_ingest,zasp_runtime_worker,zasp_outbox_worker,zasp_runtime_gateway,zasp_discovery_scheduler,zasp_projection_risk_worker,zasp_projection_graph_worker,zasp_projection_search_worker",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("typed inventory migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"DROP TABLE zasp_inventory_entities", "ALTER TABLE zasp_inventory_entities"} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("expand migration contains destructive cutover %q", forbidden)
		}
	}
	fingerprint := ProductionTypedInventoryCutoverSemanticFingerprint()
	if len(fingerprint) != 64 || !strings.Contains(metadata.UpSQL(), fingerprint) || !strings.Contains(metadata.DownSQL(), fingerprint) {
		t.Fatalf("typed inventory fingerprint = %q", fingerprint)
	}
	for _, required := range []string{"typed inventory cutover blocks rollback", "phase='cutover'", "zasp_execution_readiness"} {
		if !strings.Contains(metadata.DownSQL(), required) {
			t.Fatalf("typed inventory rollback missing %q", required)
		}
	}
}

func TestRunnerProductionTypedInventoryCutoverRequiresExactV13AndV14Readiness(t *testing.T) {
	adjacent := []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution()}
	typed := append(append([]Metadata(nil), adjacent...), ProductionTypedInventoryCutover())

	t.Run("preflight drift is mutation free", func(t *testing.T) {
		transaction := &fakeTransaction{rows: append(exactReleaseRows(adjacent...), fakeRow{values: []any{false}})}
		database := &fakeDatabase{transaction: transaction}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionTypedInventoryCutover(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("preflight error = %v", err)
		}
		if contains(database.events, "exec:"+compactSQL(ProductionTypedInventoryCutover().UpSQL())) {
			t.Fatal("preflight drift mutated v14")
		}
	})

	t.Run("postflight drift rolls back", func(t *testing.T) {
		rows := append(exactReleaseRows(adjacent...), fakeRow{values: []any{true}})
		rows = append(rows, exactReleaseRows(typed...)...)
		rows = append(rows, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionTypedInventoryCutover(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("postflight error = %v", err)
		}
		if !contains(database.events, "rollback") {
			t.Fatalf("postflight events = %#v", database.events)
		}
	})

	t.Run("cutover blocks rollback before mutation", func(t *testing.T) {
		rows := append(exactReleaseRows(typed...), fakeRow{values: []any{true}}, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.DownProductionTypedInventoryCutover(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("cutover rollback error = %v", err)
		}
		if contains(database.events, "exec:"+compactSQL(deleteRowSQL)) || contains(database.events, "exec:"+compactSQL(ProductionTypedInventoryCutover().DownSQL())) {
			t.Fatalf("blocked rollback mutated v14: %#v", database.events)
		}
	})
}
