package securityagent

import "sort"

const (
	actionProductionAvailable = "production-available"
	actionComponentOnly       = "component-only"
	actionAutonomyNone        = "none"
)

type ActionReadiness struct {
	Key              string
	ProductionState  string
	MaximumAutonomy  string
	Provider         string
	Reversible       bool
	ApprovalFloor    string
	VerificationKind string
	CleanupKind      string
	CurrentEvidence  string
}

var productionActionReadiness = []ActionReadiness{
	{Key: "create_evidence_export", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "evidence_export", Reversible: true, ApprovalFloor: "none", VerificationKind: "export", CleanupKind: "artifact_expiry", CurrentEvidence: "component contract only; durable export worker and canary pending"},
	{Key: "create_temporary_policy", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "runtime_policy", Reversible: true, ApprovalFloor: "operator", VerificationKind: "policy_state", CleanupKind: "ttl_disable", CurrentEvidence: "component contract only; signed distribution verification and cleanup pending"},
	{Key: "isolate_session", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "runtime_gateway", Reversible: true, ApprovalFloor: "operator", VerificationKind: "gateway_decision", CleanupKind: "ttl_release", CurrentEvidence: "component contract only; gateway enforcement verification and cleanup pending"},
	{Key: "rerun_test", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "red_team", Reversible: true, ApprovalFloor: "none", VerificationKind: "test_run", CleanupKind: "none", CurrentEvidence: "component contract only; durable test worker and canary pending"},
	{Key: "revoke_integration_connection", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "connector_broker", Reversible: false, ApprovalFloor: "admin", VerificationKind: "connection_state", CleanupKind: "provider_reconciliation", CurrentEvidence: "component contract only; approved broker execution and provider canary pending"},
	{Key: "run_test", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "red_team", Reversible: true, ApprovalFloor: "none", VerificationKind: "test_run", CleanupKind: "none", CurrentEvidence: "component contract only; durable test worker and canary pending"},
	{Key: "send_response_webhook", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "configured_webhook", Reversible: false, ApprovalFloor: "operator", VerificationKind: "signed_delivery", CleanupKind: "delivery_reconciliation", CurrentEvidence: "component contract only; destination authority delivery receipt and canary pending"},
	{Key: "start_attack_lab", ProductionState: actionComponentOnly, MaximumAutonomy: actionAutonomyNone, Provider: "attack_lab", Reversible: true, ApprovalFloor: "operator", VerificationKind: "attack_lab_run", CleanupKind: "sandbox_cleanup", CurrentEvidence: "component contract only; isolated sandbox deployment and canary pending"},
	{Key: "update_finding_response", ProductionState: actionProductionAvailable, MaximumAutonomy: string(AutonomyAutonomous), Provider: "risk_store", Reversible: true, ApprovalFloor: "none", VerificationKind: "finding_state", CleanupKind: "state_revert", CurrentEvidence: "v21 tenant-scoped supervised and autonomous execution with exact finding-state verification and browser E2E at 95477059"},
}

func ProductionActionReadiness() []ActionReadiness {
	values := append([]ActionReadiness(nil), productionActionReadiness...)
	sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	return values
}

func ProductionActionAvailable(key string, autonomy Autonomy) bool {
	if autonomy != AutonomySupervised && autonomy != AutonomyAutonomous {
		return false
	}
	for _, value := range productionActionReadiness {
		if value.Key != key || value.ProductionState != actionProductionAvailable {
			continue
		}
		return value.MaximumAutonomy == string(AutonomyAutonomous) || value.MaximumAutonomy == string(autonomy)
	}
	return false
}

func ProductionActionMetadata() []ActionMetadata {
	metadata := make(map[string]ActionMetadata)
	for _, value := range BuiltInResponseActionMetadata() {
		metadata[value.Key] = value
	}
	temporary := TemporaryPolicyActionMetadata()
	metadata[temporary.Key] = temporary
	result := []ActionMetadata{}
	for _, readiness := range ProductionActionReadiness() {
		if readiness.ProductionState != actionProductionAvailable {
			continue
		}
		value, ok := metadata[readiness.Key]
		if !ok || value.Reversible != readiness.Reversible || value.ApprovalFloor != readiness.ApprovalFloor || value.VerificationKind != readiness.VerificationKind {
			return []ActionMetadata{}
		}
		value.InputSchema = cloneParameters(value.InputSchema)
		value.TargetTypes = cloneStrings(value.TargetTypes)
		result = append(result, value)
	}
	return result
}
