package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionSecurityAgentControlsOwnsVersionedExecutionSwitchAuthority(t *testing.T) {
	metadata := ProductionSecurityAgentControls()
	if metadata.Version() != 20 || metadata.Name() != "security_agent_controls" || len(metadata.Checksum()) != 64 {
		t.Fatalf("metadata version=%d name=%q checksum=%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, contract := range []string{
		"security_agent_execution_controls_fingerprint",
		"zasp_security_agent_execution_control_detail",
		"zasp_security_agent_mutate_execution_control",
		"setSecurityAgentExecutionControl",
		"update_finding_response",
		"fresh_auth_expires_value",
		"zasp_security_agent_request_receipts",
		"zasp_security_agent_controls_readiness",
		"zasp_security_agent_controls_live_fingerprint",
		"REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_set_kill_switch",
		"GRANT SELECT ON TABLE public.zasp_environments TO zasp_discovery_authority",
	} {
		if !strings.Contains(metadata.UpSQL(), contract) {
			t.Fatalf("v20 up migration omitted %q", contract)
		}
	}
	for _, forbidden := range []string{"CREATE TABLE public.zasp_security_agent_kill_switches", "DROP TABLE public.zasp_security_agent_kill_switches"} {
		if strings.Contains(metadata.UpSQL(), forbidden) || strings.Contains(metadata.DownSQL(), forbidden) {
			t.Fatalf("v20 changed immutable v18 table authority with %q", forbidden)
		}
	}
	for _, contract := range []string{
		"DROP FUNCTION public.zasp_security_agent_mutate_execution_control",
		"DROP FUNCTION public.zasp_security_agent_execution_control_detail",
		"DROP FUNCTION public.zasp_security_agent_controls_readiness",
		"DROP FUNCTION public.zasp_security_agent_controls_live_fingerprint",
		"GRANT EXECUTE ON FUNCTION public.zasp_security_agent_set_kill_switch",
		"REVOKE SELECT ON TABLE public.zasp_environments FROM zasp_discovery_authority",
		"zasp_security_agent_controls_live_fingerprint()<>",
	} {
		if !strings.Contains(metadata.DownSQL(), contract) {
			t.Fatalf("v20 down migration omitted %q", contract)
		}
	}
}

func TestProductionSecurityAgentControlsSemanticFingerprintIsPinned(t *testing.T) {
	if fingerprint := ProductionSecurityAgentControlsSemanticFingerprint(); len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("invalid semantic fingerprint %q", fingerprint)
	}
}

func TestProductionSecurityAgentControlsRunnerRejectsMissingDatabase(t *testing.T) {
	var runner *Runner
	if err := runner.UpProductionSecurityAgentControls(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("up error=%v", err)
	}
	if err := runner.DownProductionSecurityAgentControls(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("down error=%v", err)
	}
}
