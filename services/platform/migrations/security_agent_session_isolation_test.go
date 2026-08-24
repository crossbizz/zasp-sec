package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionSecurityAgentSessionIsolationOwnsExactGatewaySessionAuthority(t *testing.T) {
	t.Parallel()
	metadata := ProductionSecurityAgentSessionIsolation()
	if metadata.Version() != 24 || metadata.Name() != "security_agent_session_isolation" || len(metadata.Checksum()) != 64 {
		t.Fatalf("metadata=%d/%s/%s", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, contract := range []string{
		"zasp_security_agent_session_isolation_readiness",
		"zasp_security_agent_schedule_session_isolation_triggers",
		"zasp_security_agent_prepare_session_isolation_run",
		"zasp_security_agent_dispatch_session_isolation_run",
		"zasp_security_agent_claim_session_policy_effects",
		"zasp_security_agent_run_v24",
		"zasp_runtime_gateway_record_event",
		"isolate_session",
		"runtime_decision",
		"gateway_decision",
		"session_id",
		"classification->>'session_id'",
		"zasp_security_agent_session_isolation_supervised_check",
	} {
		if !strings.Contains(metadata.UpSQL(), contract) {
			t.Fatalf("up migration missing %s", contract)
		}
	}
	for _, forbidden := range []string{
		"GRANT zasp_gateway_control TO zasp_security_agent_action_worker",
		"GRANT zasp_security_agent_worker TO zasp_security_agent_action_worker",
		"classification->>'session_id' = ''",
	} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("unsafe authority present: %s", forbidden)
		}
	}
	if fingerprint := ProductionSecurityAgentSessionIsolationSemanticFingerprint(); len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint=%q", fingerprint)
	}
}

func TestProductionSecurityAgentSessionIsolationRunnerRejectsMissingDatabase(t *testing.T) {
	t.Parallel()
	runner := &Runner{}
	if err := runner.UpProductionSecurityAgentSessionIsolation(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("up err=%v", err)
	}
	if err := runner.DownProductionSecurityAgentSessionIsolation(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("down err=%v", err)
	}
}
