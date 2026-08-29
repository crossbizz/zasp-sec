package migrations

import (
	"strings"
	"testing"
)

func TestProductionPolicyDeploymentPinsSingleWriterAuthority(t *testing.T) {
	metadata := ProductionPolicyDeployment()
	if metadata.Version() != 28 || metadata.Name() != "production_policy_deployment" || len(metadata.Checksum()) != 64 || len(ProductionPolicyDeploymentSemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionPolicyDeploymentSemanticFingerprint())
	}
	up := metadata.UpSQL()
	for _, required := range []string{
		"CREATE TABLE public.zasp_policy_deployment_work",
		"concat_ws('|','column'",
		"CREATE FUNCTION public.zasp_policy_deployment_enqueue_device",
		"CREATE FUNCTION public.zasp_policy_deployment_claim",
		"CREATE FUNCTION public.zasp_policy_deployment_heartbeat",
		"CREATE FUNCTION public.zasp_policy_deployment_store",
		"CREATE FUNCTION public.zasp_policy_deployment_read",
		"CREATE FUNCTION public.zasp_policy_deployment_finish",
		"CREATE FUNCTION public.zasp_security_agent_expire_approvals_v28",
		"state='expired'",
		"last_error_code='approval_expired'",
		"ALTER FUNCTION public.zasp_recovery_execution_readiness(text,text) RENAME TO zasp_recovery_execution_readiness_v27",
		"CREATE FUNCTION public.zasp_recovery_execution_readiness(expected_checksum text,expected_fingerprint text)",
		"value='production-recovery-v1'",
		"CREATE TRIGGER zasp_workflow_records_policy_deployment",
		"CREATE TRIGGER zasp_gateway_devices_policy_deployment",
		"CREATE TRIGGER zasp_gateway_credentials_policy_deployment",
		"zasp_policy_deployment_worker",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v28 missing %q", required)
		}
	}
	if strings.Contains(up, "value='production-policy-deployment-v1'") {
		t.Fatal("v28 changed the unchanged public product schema marker")
	}
}

func TestProductionPolicyDeploymentTemporaryTargetsOnlyEnqueueCentralWriter(t *testing.T) {
	up := ProductionPolicyDeployment().UpSQL()
	for _, required := range []string{
		"ALTER FUNCTION public.zasp_security_agent_store_temporary_policy_target",
		"ALTER FUNCTION public.zasp_security_agent_store_session_policy_target",
		"CREATE FUNCTION public.zasp_policy_deployment_store_temporary_source",
		"UPDATE zasp_security_agent_temporary_policy_targets target SET state='stored'",
		"desired_generation",
		"zasp_policy_deployment_target_verify_guard",
		"SELECT min(target.expires_at) FROM zasp_security_agent_temporary_policy_targets target",
		"LEAST(transaction_timestamp()+interval '12 hours'",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v28 temporary source fencing missing %q", required)
		}
	}
	if strings.Count(up, "INSERT INTO zasp_runtime_gateway_policy_bundles") != 1 {
		t.Fatalf("live bundle writer count=%d", strings.Count(up, "INSERT INTO zasp_runtime_gateway_policy_bundles"))
	}
	for _, forbidden := range []string{
		"result_value:=zasp_security_agent_store_temporary_policy_target_v27(",
		"result_value:=zasp_security_agent_store_session_policy_target_v27(",
	} {
		if strings.Contains(up, forbidden) {
			t.Fatalf("temporary source store still invokes legacy live-bundle writer %q", forbidden)
		}
	}
}
