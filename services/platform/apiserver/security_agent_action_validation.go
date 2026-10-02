package apiserver

import (
	"encoding/json"
	"time"
)

// Validate public authority values before header filtering. The database
// projection proves provenance; this check prevents malformed authority adapters
// from bypassing field safety or contradicting the displayed execution.
func validSecurityAgentActionDetails(detail SecurityAgentRunDetail) bool {
	if detail.ActionDetails == nil {
		return true
	}
	if detail.Plan == nil {
		return len(detail.ActionDetails) == 0
	}
	if len(detail.ActionDetails) != len(detail.Plan.Steps) || len(detail.Execution) != len(detail.Plan.Steps) {
		return false
	}
	executions := make(map[string]SecurityAgentExecutionStep, len(detail.Execution))
	for _, execution := range detail.Execution {
		executions[execution.StepID] = execution
	}
	for index, value := range detail.ActionDetails {
		if value.StepID != detail.Plan.Steps[index].ID || value.Action != detail.Plan.Steps[index].Action || value.ControlExpiresAt != nil && (value.ControlExpiresAt.IsZero() || value.ControlExpiresAt.Location() != time.UTC) {
			return false
		}
		raw, err := json.Marshal(value.Arguments)
		if err != nil {
			return false
		}
		if _, err := decodeSecurityAgentActionArguments(value.Action, raw); err != nil {
			return false
		}
		if value.Action == "create_evidence_export" && (value.Arguments == nil || value.Arguments.TargetID != detail.Run.ID) {
			return false
		}
		policy := stringIn(value.Action, "create_temporary_policy", "isolate_session")
		if policy && value.Arguments != nil {
			if value.TTLSeconds == nil || *value.TTLSeconds != value.Arguments.TTLSeconds {
				return false
			}
		} else if value.TTLSeconds != nil {
			return false
		}
		execution, found := executions[value.StepID]
		if !found {
			return false
		}
		state := ""
		if value.Result != nil {
			result := value.Result
			state = result.State
			if value.Action == "create_evidence_export" && !stringIn(state, "pending", "succeeded", "known_failure", "cleanup_pending") {
				return false
			}
			if !stringIn(state, "pending", "leased", "succeeded", "known_failure", "unknown_outcome", "verified", "cleanup_pending", "cleaned", "cleanup_failed") || (result.OutcomeID == "") != (result.ResultDigest == "") || result.OutcomeID != "" && (!validProductID(result.OutcomeID) || !securityAgentPlanHashPattern.MatchString(result.ResultDigest)) || result.OutcomeID != execution.OutcomeID || result.ResultDigest != execution.ResultDigest || stringIn(state, "verified", "cleaned") && result.OutcomeID == "" {
				return false
			}
		} else if execution.OutcomeID != "" || execution.ResultDigest != "" || value.ControlExpiresAt != nil {
			return false
		}
		if !validSecurityAgentExistingTestPublic(value.ExistingTest, value) {
			return false
		}
		if !validSecurityAgentAttackLabPublic(value.AttackLab, value) {
			return false
		}
		if policy {
			if value.Verification.Source != "policy_targets" || !stringIn(value.Verification.State, "unavailable", "pending", "verified") || value.Rollback.Verification.Source != "policy_targets" || !stringIn(value.Rollback.Verification.State, "unavailable", "pending", "verified") || value.Rollback.Support != "automatic" {
				return false
			}
			if state == "" && (value.Verification.State != "unavailable" || value.Rollback.Verification.State != "unavailable") {
				return false
			}
			rollback := "not_started"
			switch state {
			case "cleanup_pending":
				rollback = "pending"
			case "cleaned":
				rollback = "completed"
			case "cleanup_failed":
				rollback = "failed"
			case "leased":
				if value.Verification.State == "verified" || value.Rollback.Verification.State != "unavailable" {
					rollback = "pending"
				}
			}
			if value.Rollback.State != rollback {
				return false
			}
		} else {
			support := "manual"
			if stringIn(value.Action, "revoke_integration_connection", "run_test", "rerun_test", "start_attack_lab", "create_evidence_export") {
				support = "not_supported"
			}
			if value.ControlExpiresAt != nil || value.Rollback.Support != support || value.Rollback.State != "unavailable" || value.Rollback.Verification != (SecurityAgentActionVerification{State: "unavailable", Source: "none"}) || stringIn(state, "cleaned", "cleanup_failed") || state == "cleanup_pending" && value.Action != "create_evidence_export" {
				return false
			}
			expected := SecurityAgentActionVerification{State: "pending", Source: "effect_record"}
			switch state {
			case "":
				expected = SecurityAgentActionVerification{State: "unavailable", Source: "none"}
			case "verified":
				expected.State = "verified"
			case "known_failure":
				expected.State = "failed"
			case "unknown_outcome", "cleanup_pending":
				expected.State = "inconclusive"
			}
			if value.Verification != expected {
				return false
			}
		}
	}
	return true
}
