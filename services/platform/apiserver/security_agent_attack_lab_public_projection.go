package apiserver

import (
	"bytes"
	"encoding/json"
)

// The SQL snapshot remains private authority inside the repository. Every
// approval response (detail, page, decision and nested run detail) uses this
// one allowlist when encoding the public response.
func (approval SecurityAgentApproval) MarshalJSON() ([]byte, error) {
	type plain SecurityAgentApproval
	public := plain(approval)
	if len(approval.AttackLab) == 0 {
		return json.Marshal(public)
	}
	var snapshot map[string]json.RawMessage
	if json.Unmarshal(approval.AttackLab, &snapshot) != nil {
		return nil, ErrRepositoryUnavailable
	}
	var ref SecurityAgentExistingTestReference
	if json.Unmarshal(snapshot["definition_id"], &ref.DefinitionID) != nil || json.Unmarshal(snapshot["definition_version"], &ref.DefinitionVersion) != nil || !validSecurityAgentAttackLabSnapshot(approval.AttackLab, ref) {
		return nil, ErrRepositoryUnavailable
	}
	var preflight map[string]json.RawMessage
	if json.Unmarshal(snapshot["preflight"], &preflight) != nil {
		return nil, ErrRepositoryUnavailable
	}
	var destination, targetKind string
	if json.Unmarshal(preflight["destination"], &destination) != nil || !validAttackLabDestination(destination) || json.Unmarshal(snapshot["target_kind"], &targetKind) != nil || !stringIn(targetKind, "agent_endpoint", "mcp_server", "coding_agent") {
		return nil, ErrRepositoryUnavailable
	}
	value := map[string]json.RawMessage{}
	for _, key := range []string{"source_run_id", "source_attempt", "definition_id", "definition_version", "target_id", "target_kind"} {
		value[key] = snapshot[key]
	}
	for _, key := range []string{"environment", "credential_class", "destination", "decision_expires_at", "limits"} {
		value[key] = preflight[key]
	}
	// Free text can contain copied secrets or prompt material. Apply the same
	// bounded redaction contract as displayed planner rationale, item by item.
	var effects []string
	if json.Unmarshal(preflight["expected_side_effects"], &effects) != nil || len(effects) < 1 || len(effects) > 16 {
		return nil, ErrRepositoryUnavailable
	}
	for i, item := range effects {
		safe, ok := sanitizeSecurityAgentRationale(item)
		if !ok {
			effects[i] = "Expected side effect withheld"
		} else {
			effects[i] = safe
		}
	}
	value["expected_side_effects"], _ = json.Marshal(effects)
	var err error
	public.AttackLab, err = json.Marshal(value)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return json.Marshal(public)
}

func (result SecurityAgentApprovalResult) MarshalJSON() ([]byte, error) {
	type plain SecurityAgentApprovalResult
	public := plain(result)
	if len(result.AttackLab) != 0 {
		encoded, err := json.Marshal(SecurityAgentApproval{AttackLab: result.AttackLab})
		if err != nil {
			return nil, err
		}
		var redacted struct {
			AttackLab json.RawMessage `json:"attack_lab"`
		}
		if json.Unmarshal(encoded, &redacted) != nil {
			return nil, ErrRepositoryUnavailable
		}
		public.AttackLab = redacted.AttackLab
	}
	return json.Marshal(public)
}

type SecurityAgentAttackLabSettlement struct {
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	ProofDigest string `json:"proof_digest"`
}

// Metadata only. Storage keys, provider identities and credential references
// never cross the tenant-authorized public read boundary.
type SecurityAgentAttackLabDetail struct {
	DefinitionID      string                                     `json:"definition_id"`
	DefinitionVersion int64                                      `json:"definition_version"`
	SourceRunID       string                                     `json:"source_run_id"`
	SourceAttempt     int                                        `json:"source_attempt"`
	ExecutionID       string                                     `json:"execution_id"`
	Attempt           int                                        `json:"attempt"`
	State             string                                     `json:"state"`
	Verdict           *string                                    `json:"verdict"`
	CleanupState      string                                     `json:"cleanup_state"`
	CleanupComplete   bool                                       `json:"cleanup_complete"`
	CancelRequested   bool                                       `json:"cancel_requested"`
	Evidence          *SecurityAgentExistingTestArtifactIdentity `json:"evidence"`
	Settlement        *SecurityAgentAttackLabSettlement          `json:"settlement"`
}

func decodeSecurityAgentAttackLabPublic(raw json.RawMessage, action SecurityAgentActionDetail) (*SecurityAgentAttackLabDetail, error) {
	object, ok := existingTestPublicObject(raw, []string{"verdict", "evidence", "settlement"}, "definition_id", "definition_version", "source_run_id", "source_attempt", "execution_id", "attempt", "state", "verdict", "cleanup_state", "cleanup_complete", "cancel_requested", "evidence", "settlement")
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	for key, fields := range map[string][]string{"evidence": {"reference_digest", "version_id", "sha256", "size_bytes"}, "settlement": {"outcome", "reason", "proof_digest"}} {
		if !bytes.Equal(bytes.TrimSpace(object[key]), []byte("null")) {
			if _, ok := existingTestPublicObject(object[key], nil, fields...); !ok {
				return nil, ErrRepositoryUnavailable
			}
		}
	}
	var value SecurityAgentAttackLabDetail
	if decodeStrictDiscovery(raw, &value) != nil || !validSecurityAgentAttackLabPublic(&value, action) {
		return nil, ErrRepositoryUnavailable
	}
	return &value, nil
}

func validSecurityAgentAttackLabPublic(v *SecurityAgentAttackLabDetail, a SecurityAgentActionDetail) bool {
	if v == nil {
		return a.Action != "start_attack_lab" || a.Result == nil
	}
	if a.Action != "start_attack_lab" || a.ExistingTest != nil || a.Arguments == nil || a.Result == nil || !validProductID(a.Result.OutcomeID) || !validProductID(v.DefinitionID) || v.DefinitionID != a.Arguments.TargetID || v.DefinitionVersion != a.Arguments.ExpectedVersion || v.DefinitionVersion < 1 || v.DefinitionVersion > 1000000 || !validProductID(v.SourceRunID) || !validProductID(v.ExecutionID) || v.SourceRunID == v.ExecutionID || v.SourceAttempt < 1 || v.SourceAttempt > 5 || v.Attempt < 0 || v.Attempt > 5 || !stringIn(v.State, "queued", "leased", "running", "retryable", "cleanup", "complete", "failed", "cancelled") || !stringIn(v.CleanupState, "pending", "in_progress", "complete", "failed") || v.Verdict != nil && !stringIn(*v.Verdict, "verified", "not_reproduced", "inconclusive") {
		return false
	}
	if v.CleanupComplete && (v.CleanupState != "complete" || !stringIn(v.State, "complete", "failed", "cancelled")) || v.Evidence != nil && !validExistingTestPublicArtifact(*v.Evidence, 16777216) {
		return false
	}
	s := v.Settlement
	if s == nil {
		return true
	}
	if !v.CleanupComplete || s.ProofDigest != a.Result.ResultDigest || !securityAgentPlanHashPattern.MatchString(s.ProofDigest) {
		return false
	}
	switch s.Outcome {
	case "needs_human":
		return a.Result.State == "succeeded" && v.State == "complete" && v.Evidence != nil && v.Verdict != nil && (s.Reason == "attack_lab_unsafe_condition_reproduced" && *v.Verdict == "verified" || s.Reason == "attack_lab_not_reproduced_in_bounded_run" && *v.Verdict == "not_reproduced")
	case "inconclusive":
		return a.Result.State == "unknown_outcome" && stringIn(s.Reason, "attack_lab_evidence_unavailable", "attack_lab_outcome_unknown")
	case "failed":
		return a.Result.State == "known_failure" && v.State == "failed" && s.Reason == "attack_lab_pre_execution_denied"
	case "cancelled":
		return a.Result.State == "known_failure" && v.State == "cancelled" && v.CancelRequested && s.Reason == "attack_lab_cancelled"
	}
	return false
}
