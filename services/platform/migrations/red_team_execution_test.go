package migrations

import (
	"strings"
	"testing"
)

func TestProductionRedTeamExecutionMetadataPinsDurableTenantAuthority(t *testing.T) {
	metadata := ProductionRedTeamExecution()
	if metadata.Version() != 25 || metadata.Name() != "red_team_execution" || len(metadata.Checksum()) != 64 {
		t.Fatalf("metadata = (%d, %q, %q)", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, required := range []string{
		"zasp_red_team_definitions",
		"zasp_red_team_runs",
		"zasp_red_team_attempts",
		"zasp_red_team_outbox",
		"zasp_red_team_audit",
		"zasp_red_team_request_receipts",
		"zasp_red_team_register_principals",
		"zasp_red_team_mutation_result",
		"zasp_red_team_create_definition",
		"zasp_red_team_run_test",
		"zasp_red_team_cancel_run",
		"zasp_red_team_claim_outbox",
		"zasp_red_team_claim_run",
		"zasp_red_team_finish_run",
		"zasp_red_team_cancel_claimed_run",
		"zasp_red_team_resolve_target",
		"zasp_red_team_target_adapter_readiness",
		"zasp_red_team_execution_readiness",
		"zasp_red_team_worker",
		"zasp_red_team_adapter",
		"organization_id,workspace_id,environment_id",
		"count(DISTINCT item#>>'{}')",
		"test-jobs",
	} {
		if !strings.Contains(metadata.UpSQL(), required) {
			t.Fatalf("v25 up migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"shell_command", "target_url", "custom_prompt"} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("v25 migration admits forbidden authority %q", forbidden)
		}
	}
	if !strings.Contains(metadata.UpSQL(), "IF run_row.cancel_requested THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team run cancellation wins';END IF;") {
		t.Fatal("v25 completion does not preserve an accepted cancellation before writing evidence")
	}
	if !strings.Contains(metadata.DownSQL(), "red team execution rollback rejected") || !strings.Contains(metadata.DownSQL(), "zasp_red_team_execution_live_fingerprint") {
		t.Fatal("v25 down migration is not guarded by exact live authority")
	}
	if !strings.Contains(metadata.UpSQL(), "red_team_execution_prior_permissions_owner") ||
		!strings.Contains(metadata.UpSQL(), "MESSAGE='noncanonical inherited permissions ACL'") ||
		!strings.Contains(metadata.UpSQL(), "aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner)))") ||
		!strings.Contains(metadata.DownSQL(), "ALTER FUNCTION public.zasp_effective_scope_permissions(jsonb,text) OWNER TO %I") ||
		!strings.Contains(metadata.DownSQL(), "DELETE FROM public.zasp_schema_metadata WHERE key='red_team_execution_prior_permissions_owner'") {
		t.Fatal("v25 does not preserve and restore the inherited permissions function owner")
	}
}
