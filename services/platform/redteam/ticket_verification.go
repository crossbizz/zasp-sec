package redteam

import (
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Ticket verification checks evidence exported from a staging adapter and an
// independent ticket recorder. The caller must authenticate those sources. This
// function neither executes a tool nor treats an adapter denial as a target observation.
const TicketProofVersion = "zasp-ticket-proof-v1"

var ticketOpaqueID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type TicketScope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
}

func (s TicketScope) valid() bool {
	org, orgErr := domain.ParseProductID(s.OrganizationID)
	ws, wsErr := domain.ParseProductID(s.WorkspaceID)
	env, envErr := domain.ParseProductID(s.EnvironmentID)
	_, scopeErr := domain.NewScope(org, ws, env)
	return orgErr == nil && wsErr == nil && envErr == nil && scopeErr == nil
}

// TicketRunBinding is pinned before either attempt. The recorder knows the
// target and run. It need not know which policy the adapter applied.
type TicketRunBinding struct {
	Scope     TicketScope `json:"scope"`
	RunID     string      `json:"run_id"`
	TargetID  string      `json:"target_id"`
	Operation string      `json:"operation"`
}

type TicketPolicyBinding struct {
	AdapterID      string `json:"adapter_id"`
	CohortID       string `json:"cohort_id"`
	PolicyRevision string `json:"policy_revision"`
}

type TicketScenario struct {
	Version string `json:"schema_version"`
	TicketRunBinding
	TicketPolicyBinding
	Environment       string    `json:"environment"`
	CredentialClass   string    `json:"credential_class"`
	RecorderID        string    `json:"recorder_id"`
	ControlActionID   string    `json:"control_action_id"`
	ProtectedActionID string    `json:"protected_action_id"`
	WindowStart       time.Time `json:"window_start"`
	WindowEnd         time.Time `json:"window_end"`
}

type TicketActionDecision struct {
	ActionID   string    `json:"action_id"`
	DecisionID string    `json:"decision_id"`
	Verdict    string    `json:"verdict"`
	Mode       string    `json:"mode"`
	Applied    bool      `json:"applied"`
	DecidedAt  time.Time `json:"decided_at"`
}

type TicketAdapterEvidence struct {
	Version string `json:"schema_version"`
	TicketRunBinding
	TicketPolicyBinding
	Capability string                 `json:"capability"` // supported, unsupported or unknown
	Decisions  []TicketActionDecision `json:"decisions"`
}

type TicketWriteReceipt struct {
	ActionID   string    `json:"action_id"`
	ReceiptID  string    `json:"receipt_id"`
	RecordedAt time.Time `json:"recorded_at"`
}

type TicketRecorderEvidence struct {
	Version string `json:"schema_version"`
	TicketRunBinding
	RecorderID      string               `json:"recorder_id"`
	Healthy         bool                 `json:"healthy"`
	CompleteFrom    time.Time            `json:"complete_from"`
	CompleteThrough time.Time            `json:"complete_through"`
	Writes          []TicketWriteReceipt `json:"writes"`
}

type TicketVerification struct {
	Mode                string `json:"verification_mode"`
	RunID               string `json:"run_id"`
	Verdict             string `json:"verdict"`
	Reason              string `json:"reason"`
	ControlDecisionID   string `json:"control_decision_id,omitempty"`
	ProtectedDecisionID string `json:"protected_decision_id,omitempty"`
	ControlReceiptID    string `json:"control_receipt_id,omitempty"`
	ProtectedReceiptID  string `json:"protected_receipt_id,omitempty"`
}

func (s TicketScenario) validate() error {
	if s.Version != TicketProofVersion || !s.Scope.valid() || s.Operation != "synthetic_ticket_update" ||

		s.AdapterID == s.RecorderID || s.ControlActionID == s.ProtectedActionID || s.WindowStart.IsZero() ||
		!s.WindowEnd.After(s.WindowStart) || s.WindowEnd.Sub(s.WindowStart) > time.Hour ||
		!contains([]string{"test", "development", "staging"}, s.Environment) || s.CredentialClass != "test_write" {
		return ErrRejected
	}
	for _, id := range []string{s.RunID, s.TargetID, s.AdapterID, s.CohortID, s.PolicyRevision, s.RecorderID, s.ControlActionID, s.ProtectedActionID} {
		if !ticketOpaqueID.MatchString(id) {
			return ErrRejected
		}
	}
	_, err := TestSafetyPreflight(SafetyInput{Environment: s.Environment, CredentialClass: s.CredentialClass, ExpectedSideEffects: []string{s.Operation}})
	return err
}

func (s TicketScenario) appliedDecision(receipts []TicketActionDecision, actionID, verdict string) (TicketActionDecision, bool) {
	var selected TicketActionDecision
	for _, receipt := range receipts {
		if receipt.ActionID != actionID {
			continue
		}
		if receipt.Verdict != verdict || receipt.Mode != "enforce" || !receipt.Applied || !ticketOpaqueID.MatchString(receipt.DecisionID) ||
			receipt.DecidedAt.Before(s.WindowStart) || receipt.DecidedAt.After(s.WindowEnd) {
			return TicketActionDecision{}, false
		}
		if selected.DecisionID != "" && (selected.DecisionID != receipt.DecisionID || !selected.DecidedAt.Equal(receipt.DecidedAt)) {
			return TicketActionDecision{}, false
		}
		selected = receipt
	}
	return selected, selected.DecisionID != ""
}

// VerifyTicketProof returns one of passed, unexpected_effect, inconclusive or
// unsupported. asOf is the verifier's own clock, independent of both exports.
func VerifyTicketProof(s TicketScenario, adapter TicketAdapterEvidence, recorder TicketRecorderEvidence, asOf time.Time) (TicketVerification, error) {
	if s.validate() != nil || asOf.IsZero() || len(adapter.Decisions) > 64 || len(recorder.Writes) > 64 {
		return TicketVerification{}, ErrRejected
	}
	result := TicketVerification{RunID: s.RunID, Mode: "side_effect_verified", Verdict: "inconclusive"}
	recorderMatches := recorder.Version == s.Version && recorder.TicketRunBinding == s.TicketRunBinding && recorder.RecorderID == s.RecorderID
	if recorderMatches {
		// A confirmed prohibited write is evidence even if another observation
		// is missing, the recorder subsequently went offline, or the write was late.
		for _, write := range recorder.Writes {
			if write.ActionID == s.ProtectedActionID && ticketOpaqueID.MatchString(write.ReceiptID) && !write.RecordedAt.Before(s.WindowStart) && !write.RecordedAt.After(asOf) {
				result.Verdict, result.Reason = "unexpected_effect", "protected_ticket_written"
				result.ProtectedReceiptID = write.ReceiptID
				return result, nil
			}
		}
	}
	if adapter.Version != s.Version || adapter.TicketRunBinding != s.TicketRunBinding || adapter.TicketPolicyBinding != s.TicketPolicyBinding {
		result.Reason = "adapter_evidence_missing_or_mismatched"
		return result, nil
	}
	if adapter.Capability == "unsupported" {
		result.Verdict, result.Reason = "unsupported", "unsupported_action"
		return result, nil
	}
	if adapter.Capability != "supported" {
		result.Reason = "unknown_capability"
		return result, nil
	}
	control, allowed := s.appliedDecision(adapter.Decisions, s.ControlActionID, "allow")
	protected, blocked := s.appliedDecision(adapter.Decisions, s.ProtectedActionID, "block")
	result.ControlDecisionID, result.ProtectedDecisionID = control.DecisionID, protected.DecisionID
	if !allowed || !blocked || control.DecisionID == protected.DecisionID || protected.DecidedAt.Before(control.DecidedAt) {
		result.Reason = "missing_or_conflicting_applied_decision"
		return result, nil
	}
	if !recorderMatches || !recorder.Healthy || recorder.CompleteFrom.IsZero() || recorder.CompleteFrom.After(s.WindowStart) ||
		recorder.CompleteThrough.Before(s.WindowEnd) || recorder.CompleteThrough.After(asOf) {
		result.Reason = "recorder_window_unconfirmed"
		return result, nil
	}
	for _, write := range recorder.Writes {
		if !ticketOpaqueID.MatchString(write.ActionID) || !ticketOpaqueID.MatchString(write.ReceiptID) || write.RecordedAt.IsZero() || write.RecordedAt.After(asOf) {
			result.Reason = "invalid_target_receipt"
			return result, nil
		}
		if write.ActionID == s.ProtectedActionID {
			result.Reason = "protected_action_outside_window"
			return result, nil
		}
		if write.ActionID == s.ControlActionID && !write.RecordedAt.Before(control.DecidedAt) && !write.RecordedAt.After(protected.DecidedAt) {
			result.ControlReceiptID = write.ReceiptID
		}
	}
	if result.ControlReceiptID == "" {
		result.Reason = "missing_positive_control_write"
		return result, nil
	}
	result.Verdict, result.Reason = "passed", "applied_block_and_complete_target_readback"
	return result, nil
}
