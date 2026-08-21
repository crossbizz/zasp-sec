package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionSecurityAgentTemporaryPolicyOwnsSeparateActionWorkerAuthority(t *testing.T) {
	t.Parallel()
	metadata := ProductionSecurityAgentTemporaryPolicy()
	if metadata.Version() != 22 || metadata.Name() != "security_agent_temporary_policy" || len(metadata.Checksum()) != 64 {
		t.Fatalf("metadata=%d/%s/%s", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, contract := range []string{
		"zasp_security_agent_action_worker",
		"zasp_security_agent_register_action_principal",
		"zasp_security_agent_temporary_policy_targets",
		"zasp_security_agent_schedule_temporary_policy_triggers",
		"zasp_security_agent_schedule_triggers_v22",
		"zasp_security_agent_claim_runs_v22",
		"zasp_security_agent_prepare_temporary_policy_run",
		"zasp_security_agent_prepare_run_v22",
		"zasp_security_agent_dispatch_temporary_policy_run",
		"zasp_security_agent_execute_run_v22",
		"zasp_security_agent_claim_temporary_policy_effects",
		"zasp_security_agent_heartbeat_temporary_policy_effect",
		"zasp_security_agent_store_temporary_policy_target",
		"zasp_security_agent_read_temporary_policy_target",
		"zasp_security_agent_finish_temporary_policy_effect",
		"zasp_security_agent_temporary_policy_readiness",
	} {
		if !strings.Contains(metadata.UpSQL(), contract) {
			t.Fatalf("up migration missing %s", contract)
		}
	}
	for _, forbidden := range []string{
		"GRANT zasp_security_agent_worker TO zasp_security_agent_action_worker",
		"GRANT zasp_gateway_control TO zasp_security_agent_action_worker",
		"GRANT zasp_security_agent_action_worker TO zasp_security_agent_worker",
	} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("cross-authority grant present: %s", forbidden)
		}
	}
	if fingerprint := ProductionSecurityAgentTemporaryPolicySemanticFingerprint(); len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint=%q", fingerprint)
	}
}

func TestProductionSecurityAgentTemporaryPolicyRunnerRejectsMissingDatabase(t *testing.T) {
	t.Parallel()
	runner := &Runner{}
	if err := runner.UpProductionSecurityAgentTemporaryPolicy(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("up err=%v", err)
	}
	if err := runner.DownProductionSecurityAgentTemporaryPolicy(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("down err=%v", err)
	}
}
