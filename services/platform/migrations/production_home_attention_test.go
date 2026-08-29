package migrations

import (
	"strings"
	"testing"
)

func TestProductionHomeAttentionPinsTenantScopedSummaryAuthority(t *testing.T) {
	metadata := ProductionHomeAttention()
	if metadata.Version() != 29 || metadata.Name() != "production_home_attention" || len(metadata.Checksum()) != 64 || len(ProductionHomeAttentionSemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionHomeAttentionSemanticFingerprint())
	}
	up := metadata.UpSQL()
	for _, required := range []string{
		"CREATE FUNCTION public.zasp_inventory_home_summary_v29",
		"approval.organization_id=organization_value",
		"run.organization_id=organization_value",
		"approval.state='pending'",
		"run.state='needs_human'",
		"run.state='failed'",
		"run.state='inconclusive'",
		"run.state='contained'",
		"run.state='remediated'",
		"CREATE FUNCTION public.zasp_production_home_attention_readiness",
		"ALTER FUNCTION public.zasp_policy_deployment_execution_readiness(text,text) RENAME TO zasp_policy_deployment_execution_readiness_v28",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v29 missing %q", required)
		}
	}
	for _, forbidden := range []string{"evidence_reference", "lease_token", "credential_reference"} {
		if strings.Contains(up, forbidden) {
			t.Fatalf("v29 summary leaks %q", forbidden)
		}
	}
}
