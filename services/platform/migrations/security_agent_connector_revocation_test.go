package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionSecurityAgentConnectorRevocationOwnsSupervisedProviderReconciliation(t *testing.T) {
	t.Parallel()
	metadata := ProductionSecurityAgentConnectorRevocation()
	if metadata.Version() != 23 || metadata.Name() != "security_agent_connector_revocation" || len(metadata.Checksum()) != 64 {
		t.Fatalf("metadata=%d/%s/%s", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, contract := range []string{
		"zasp_security_agent_connector_revocations",
		"zasp_security_agent_schedule_connector_revocation_triggers",
		"zasp_security_agent_prepare_connector_revocation_run",
		"zasp_security_agent_dispatch_connector_revocation_run",
		"zasp_security_agent_reconcile_connector_revocations",
		"revoke_integration_connection",
		"connection_state",
		"approval_required",
		"zasp_connector_complete_revocation",
		"zasp_security_agent_connector_revocation_readiness",
		"pg_attribute",
		"pg_constraint",
		"pg_index",
		"pg_policy",
		"row_number() OVER (PARTITION BY definition.organization_id",
		"definition_ordinal=1",
		"connection.provider IN('github','okta')",
		"credential.credential_class='github_installation_reference'",
		"credential.credential_class='okta_refresh_reference'",
		"connector_state_drift",
	} {
		if !strings.Contains(metadata.UpSQL(), contract) {
			t.Fatalf("up migration missing %s", contract)
		}
	}
	for _, forbidden := range []string{
		"GRANT zasp_discovery_worker TO zasp_security_agent_action_worker",
		"GRANT zasp_discovery_authority TO zasp_security_agent_action_worker",
		"GRANT zasp_security_agent_worker TO zasp_security_agent_action_worker",
		"LOCK TABLE zasp_inventory_evidence",
		"MESSAGE='connector revocation verification drift'",
	} {
		if strings.Contains(metadata.UpSQL(), forbidden) {
			t.Fatalf("cross-authority grant present: %s", forbidden)
		}
	}
	if fingerprint := ProductionSecurityAgentConnectorRevocationSemanticFingerprint(); len(fingerprint) != 64 || strings.Trim(fingerprint, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint=%q", fingerprint)
	}
}

func TestProductionSecurityAgentConnectorRevocationRunnerRejectsMissingDatabase(t *testing.T) {
	t.Parallel()
	runner := &Runner{}
	if err := runner.UpProductionSecurityAgentConnectorRevocation(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("up err=%v", err)
	}
	if err := runner.DownProductionSecurityAgentConnectorRevocation(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("down err=%v", err)
	}
}
