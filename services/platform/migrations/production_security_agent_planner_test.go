package migrations

import (
	"strings"
	"testing"
)

func TestProductionSecurityAgentPlannerPinsLeaseFencedFailClosedAuthority(t *testing.T) {
	metadata := ProductionSecurityAgentPlanner()
	if metadata.Version() != 32 || metadata.Name() != "production_security_agent_planner" || len(metadata.Checksum()) != 64 || len(ProductionSecurityAgentPlannerSemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionSecurityAgentPlannerSemanticFingerprint())
	}
	up := metadata.UpSQL()
	for _, required := range []string{
		"production_workflow_compatibility prerequisite rejected",
		"later_release.\"version\" > 32",
		"later.\"version\">32",
		"workflow v32 compatibility evolution failed",
		"risk v32 compatibility evolution failed",
		"CREATE TABLE public.zasp_security_agent_planner_receipts",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"zasp_security_agent_planner_context",
		"zasp_security_agent_accept_planner_candidate",
		"zasp_security_agent_fail_planner",
		"planner_unavailable",
		"planner_rejected",
		"zasp_security_agent_prepare_run_v24",
		"zasp_production_security_agent_planner_security_ready",
		"zasp_production_security_agent_planner_readiness",
		"GRANT EXECUTE ON FUNCTION public.zasp_security_agent_planner_context",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v32 missing %q", required)
		}
	}
	for _, forbidden := range []string{"GRANT SELECT ON TABLE public.zasp_security_agent_planner_receipts", "provider_error", "raw_evidence", "secret_value"} {
		if strings.Contains(up, forbidden) {
			t.Fatalf("v32 retained forbidden authority %q", forbidden)
		}
	}
	down := metadata.DownSQL()
	for _, required := range []string{
		"planner receipts block rollback",
		"later_release.\"version\" > 31",
		"later.\"version\">31",
		"workflow v31 compatibility restoration failed",
		"risk v31 compatibility restoration failed",
		"DROP FUNCTION public.zasp_security_agent_fail_planner",
		"DROP FUNCTION public.zasp_security_agent_accept_planner_candidate",
		"DROP FUNCTION public.zasp_security_agent_planner_context",
		"DROP TABLE public.zasp_security_agent_planner_receipts",
	} {
		if !strings.Contains(down, required) {
			t.Fatalf("v32 down missing %q", required)
		}
	}
}

func TestProductionSecurityAgentPlannerContextAndCandidateAreStructurallyBounded(t *testing.T) {
	up := ProductionSecurityAgentPlanner().UpSQL()
	for _, required := range []string{
		"jsonb_build_object('purpose','security_response_plan'",
		"'operator_goal','Select the safest bounded response'",
		"'maximum_steps'",
		"'allowed_actions'",
		"'allowed_targets'",
		"'untrusted_evidence'",
		"candidate_value->>'version' IS DISTINCT FROM '1'",
		"jsonb_array_length(candidate_value->'steps')",
		"candidate_value->'steps'->0->>'action'",
		"candidate_value->'steps'->0->>'target_id'",
		"jsonb_typeof(candidate_value->'summary') IS DISTINCT FROM 'string'",
		"jsonb_typeof(candidate_value->'steps'->0->'action') IS DISTINCT FROM 'string'",
		"jsonb_typeof(candidate_value->'steps'->0->'target_id') IS DISTINCT FROM 'string'",
		"candidate_value->'steps'->0->>'action' IS DISTINCT FROM context_value->'allowed_actions'->>0",
		"candidate_value->'steps'->0->>'target_id' IS DISTINCT FROM context_value->'allowed_targets'->>0",
		"octet_length(input_digest_value)<>32",
		"octet_length(output_digest_value)<>32",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v32 planner binding missing %q", required)
		}
	}
}
