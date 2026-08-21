package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionSecurityAgentExecutionMetadataOwnsTheCompleteScopedAuthority(t *testing.T) {
	metadata := ProductionSecurityAgentExecution()
	if metadata.Version() != 18 || metadata.Name() != "security_agent_execution" || len(metadata.Checksum()) != 64 {
		t.Fatalf("security agent execution metadata=v%d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{
		"zasp_security_agent_definitions",
		"zasp_security_agent_definition_versions",
		"zasp_security_agent_trigger_receipts",
		"zasp_security_agent_plans",
		"zasp_security_agent_runs",
		"zasp_security_agent_steps",
		"zasp_security_agent_approvals",
		"zasp_security_agent_effects",
		"zasp_security_agent_controls",
		"zasp_security_agent_audit",
		"zasp_security_agent_kill_switches",
		"zasp_security_agent_api",
		"zasp_security_agent_worker",
		"zasp_security_agent_principal_bindings",
		"zasp_security_agent_register_principals",
		"zasp_security_agent_principal_ready",
		"zasp_security_agent_principals_ready",
		"zasp_security_agent_readiness",
		"security_agent_execution_fingerprint",
	} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("security agent execution up migration missing %q", fragment)
		}
	}
	if fingerprint := ProductionSecurityAgentExecutionSemanticFingerprint(); len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("security agent execution fingerprint=%q", fingerprint)
	}
	for _, fragment := range []string{
		"DROP TABLE public.zasp_security_agent_definitions",
		"DROP ROLE zasp_security_agent_worker",
		"DROP ROLE zasp_security_agent_api",
	} {
		if !strings.Contains(metadata.DownSQL(), fragment) {
			t.Fatalf("security agent execution down migration missing %q", fragment)
		}
	}
}

func TestRunnerProductionSecurityAgentExecutionRequiresExactV17AndV18Readiness(t *testing.T) {
	throughV17 := []Metadata{Baseline(), ProductionCore(), ProductionWorkflows(), WorkflowReceipts(), WorkflowReceiptSafety(), WorkflowReceiptProvenance(), ProductionAdministration(), APITokenRevealGrants(), ProductionRiskProjection(), ProductionDiscovery(), ConnectorAuthorization(), ReferenceAuthorization(), ProductionDiscoveryExecution(), ProductionTypedInventoryCutover(), ProductionRuntimeDataPlane(), ProductionRuntimeGatewayReconciliation(), ProductionRuntimeIngestReconciliation()}
	throughV18 := append(append([]Metadata(nil), throughV17...), ProductionSecurityAgentExecution())

	t.Run("preflight drift is mutation free", func(t *testing.T) {
		transaction := &fakeTransaction{rows: append(exactReleaseRows(throughV17...), fakeRow{values: []any{false}})}
		database := &fakeDatabase{transaction: transaction}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionSecurityAgentExecution(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("preflight error=%v", err)
		}
		if contains(database.events, "exec:"+compactSQL(ProductionSecurityAgentExecution().UpSQL())) {
			t.Fatalf("preflight drift mutated v18: %#v", database.events)
		}
	})

	t.Run("postflight drift rolls back", func(t *testing.T) {
		rows := append(exactReleaseRows(throughV17...), fakeRow{values: []any{true}})
		rows = append(rows, exactReleaseRows(throughV18...)...)
		rows = append(rows, fakeRow{values: []any{false}})
		database := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
		runner, _ := NewRunner(database)
		if err := runner.UpProductionSecurityAgentExecution(context.Background()); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("postflight error=%v", err)
		}
		if !contains(database.events, "rollback") {
			t.Fatalf("postflight events=%#v", database.events)
		}
	})
}
