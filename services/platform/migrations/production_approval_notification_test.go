package migrations

import (
	"strings"
	"testing"
)

func TestProductionApprovalNotificationPinsDurableMinimalTenantAuthority(t *testing.T) {
	metadata := ProductionApprovalNotification()
	if metadata.Version() != 30 || metadata.Name() != "production_approval_notification" || len(metadata.Checksum()) != 64 || len(ProductionApprovalNotificationSemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionApprovalNotificationSemanticFingerprint())
	}
	up := metadata.UpSQL()
	for _, required := range []string{
		"CREATE TABLE public.zasp_security_agent_approval_notifications",
		"CREATE TRIGGER zasp_security_agent_enqueue_approval_notification_v30",
		"security_agent.approval_required",
		"zasp_security_agent_claim_approval_notification",
		"zasp_security_agent_complete_approval_notification",
		"zasp_security_agent_fail_approval_notification",
		"NEW.organization_id",
		"NEW.workspace_id",
		"NEW.environment_id",
		"UNIQUE(organization_id,workspace_id,environment_id,approval_id)",
		"CREATE FUNCTION public.zasp_production_approval_notification_readiness",
		"GRANT EXECUTE ON FUNCTION public.zasp_production_approval_notification_readiness(text,text) TO zasp_security_agent_api",
		"string_agg(CASE WHEN role_oid=0 THEN 'PUBLIC' ELSE role_value.rolname END",
		"destination_host LIKE '%..%'",
		"destination_host~'^[0-9.]+$'",
		"IF NEW.state<>'pending' THEN RETURN NEW;END IF",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v30 missing %q", required)
		}
	}
	for _, forbidden := range []string{"evidence_ids", "credential_reference", "plan_hash", "policy_value.polroles::text"} {
		if strings.Contains(up, forbidden) {
			t.Fatalf("v30 payload leaks %q", forbidden)
		}
	}
}
