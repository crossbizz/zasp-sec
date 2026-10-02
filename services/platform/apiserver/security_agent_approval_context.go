package apiserver

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

type SecurityAgentApprovalRequester struct {
	State string  `json:"state"`
	ID    *string `json:"id"`
}

type SecurityAgentApprovalReason struct {
	Code   string `json:"code"`
	Source string `json:"source"`
}

type SecurityAgentApprovalRisk struct {
	Class  string `json:"class"`
	Source string `json:"source"`
}

type SecurityAgentApprovalContext struct {
	AgentID         string                         `json:"agent_id"`
	Action          string                         `json:"action"`
	TargetID        *string                        `json:"target_id"`
	PlanHash        string                         `json:"plan_hash"`
	CatalogVersion  string                         `json:"catalog_version"`
	Requester       SecurityAgentApprovalRequester `json:"requester"`
	Reason          SecurityAgentApprovalReason    `json:"reason"`
	Risk            SecurityAgentApprovalRisk      `json:"risk"`
	Rationale       *SecurityAgentRationale        `json:"rationale"`
	ExportSelection []SecurityAgentExportSelection `json:"export_selection,omitempty"`
	FindingResponse *SecurityAgentActionArguments  `json:"finding_response,omitempty"`
}

const findingResponseApprovalEffect = "Assign investigator and update finding response"

func requiredFindingApprovalContext(value SecurityAgentApproval) bool {
	return value.ExpectedEffect == findingResponseApprovalEffect && value.Context != nil && value.Context.FindingResponse != nil && validSecurityAgentApproval(value)
}

func validApprovalContext(approval SecurityAgentApproval) bool {
	value := approval.Context
	if value == nil {
		return approval.ExpectedEffect != findingResponseApprovalEffect
	}
	if value.FindingResponse != nil && value.Action != "update_finding_response" {
		return false
	}
	if value.Action != "create_evidence_export" && value.ExportSelection != nil {
		return false
	}
	if !validProductID(value.AgentID) || value.TargetID != nil && !validProductID(*value.TargetID) || !securityAgentPlanHashPattern.MatchString(value.PlanHash) || value.CatalogVersion != "security-agent-actions-v1" || value.Reason.Code != "operator_approval_required" || value.Reason.Source != "persisted_step" || value.Risk.Source != "action_catalog" {
		return false
	}
	switch value.Action {
	case "create_evidence_export":
		if value.Risk.Class != "low" || approval.ExpectedEffect != "Create run-scoped evidence export" || value.TargetID == nil || *value.TargetID != approval.RunID || !validAgentExportDownloadBinding(SecurityAgentExportBinding{RunID: approval.RunID, StepID: approval.StepID, Selection: value.ExportSelection}) {
			return false
		}
	case "start_attack_lab":
		if value.Risk.Class != "moderate" || approval.ExpectedEffect != "Run a bounded Attack Lab reproduction; human interpretation required" || len(approval.AttackLab) == 0 {
			return false
		}
	case "run_test":
		if value.Risk.Class != "low" || approval.ExpectedEffect != "Run existing test" {
			return false
		}
	case "rerun_test":
		if value.Risk.Class != "low" || approval.ExpectedEffect != "Rerun existing test" {
			return false
		}
	case "update_finding_response":
		if value.Risk.Class != "low" {
			return false
		}
		if value.FindingResponse == nil {
			if approval.ExpectedEffect != "Move finding to under review" {
				return false
			}
		} else {
			raw, err := json.Marshal(value.FindingResponse)
			args, decodeErr := decodeSecurityAgentActionArguments(value.Action, raw)
			if err != nil || decodeErr != nil || args == nil || args.AssigneeID == "" || value.TargetID == nil || args.TargetID != *value.TargetID || approval.ExpectedEffect != findingResponseApprovalEffect {
				return false
			}
		}
	case "create_temporary_policy":
		if value.Risk.Class != "containment" || approval.ExpectedEffect != "Apply temporary containment policy" {
			return false
		}
	case "isolate_session":
		if value.Risk.Class != "containment" || approval.ExpectedEffect != "Isolate runtime session" {
			return false
		}
	case "revoke_integration_connection":
		if value.Risk.Class != "destructive" || approval.ExpectedEffect != "Revoke integration connection" {
			return false
		}
	default:
		return false
	}
	if !(value.Requester.State == "withheld" && value.Requester.ID == nil || value.Requester.State == "available" && value.Requester.ID != nil && validProductID(*value.Requester.ID)) {
		return false
	}
	if value.Rationale == nil {
		return true
	}
	if value.Rationale.State == "withheld" {
		return value.Rationale.Summary == ""
	}
	if value.Rationale.State != "available" {
		return false
	}
	safe, ok := sanitizeSecurityAgentRationale(value.Rationale.Summary)
	return ok && safe == value.Rationale.Summary
}

// The caller must obtain this private projection from the full-scope SQL
// authority. No raw requester or planner text is copied into the public value.
func decodeSecurityAgentApprovalContext(raw json.RawMessage, approval SecurityAgentApproval) (*SecurityAgentApprovalContext, error) {
	var wire struct {
		ApprovalID       string          `json:"approval_id"`
		RunID            string          `json:"run_id"`
		StepID           string          `json:"step_id"`
		AgentID          string          `json:"agent_id"`
		ApprovalPlanHash string          `json:"approval_plan_hash"`
		PlanHash         string          `json:"plan_hash"`
		CatalogVersion   string          `json:"catalog_version"`
		Action           string          `json:"action"`
		Authorization    string          `json:"authorization"`
		Arguments        json.RawMessage `json:"arguments"`
		RequesterID      string          `json:"requester_id"`
		PlannerReceipt   json.RawMessage `json:"planner_receipt"`
	}
	if len(raw) > 65536 || !utf8.Valid(raw) || !validSecurityAgentApprovalShape(approval) || !exactJSONFields(raw, "approval_id", "run_id", "step_id", "agent_id", "approval_plan_hash", "plan_hash", "catalog_version", "action", "authorization", "arguments", "requester_id", "planner_receipt") || decodeStrictDiscovery(raw, &wire) != nil || wire.ApprovalID != approval.ID || wire.RunID != approval.RunID || wire.StepID != approval.StepID || !validProductID(wire.AgentID) || !securityAgentPlanHashPattern.MatchString(wire.PlanHash) || wire.ApprovalPlanHash != wire.PlanHash || wire.CatalogVersion != "security-agent-actions-v1" || wire.Authorization != "approval_required" {
		return nil, ErrRepositoryUnavailable
	}
	args, err := decodeSecurityAgentActionArguments(wire.Action, wire.Arguments)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	risk, effect := "", ""
	switch wire.Action {
	case "create_evidence_export":
		risk, effect = "low", "Create run-scoped evidence export"
		if args == nil || args.TargetID != approval.RunID {
			return nil, ErrRepositoryUnavailable
		}
	case "start_attack_lab":
		risk, effect = "moderate", "Run a bounded Attack Lab reproduction; human interpretation required"
	case "run_test":
		risk, effect = "low", "Run existing test"
	case "rerun_test":
		risk, effect = "low", "Rerun existing test"
	case "update_finding_response":
		risk, effect = "low", "Move finding to under review"
		if args != nil && args.AssigneeID != "" {
			effect = findingResponseApprovalEffect
		}
	case "create_temporary_policy":
		risk, effect = "containment", "Apply temporary containment policy"
	case "isolate_session":
		risk, effect = "containment", "Isolate runtime session"
	case "revoke_integration_connection":
		risk, effect = "destructive", "Revoke integration connection"
	default:
		return nil, ErrRepositoryUnavailable
	}
	if approval.ExpectedEffect != effect || args != nil && args.TTLSeconds != approval.TTLSeconds {
		return nil, ErrRepositoryUnavailable
	}
	value := &SecurityAgentApprovalContext{AgentID: wire.AgentID, Action: wire.Action, PlanHash: wire.PlanHash, CatalogVersion: wire.CatalogVersion,
		Requester: SecurityAgentApprovalRequester{State: "withheld"},
		Reason:    SecurityAgentApprovalReason{Code: "operator_approval_required", Source: "persisted_step"},
		Risk:      SecurityAgentApprovalRisk{Class: risk, Source: "action_catalog"}}
	if args != nil {
		target := args.TargetID
		value.TargetID = &target
		if wire.Action == "create_evidence_export" {
			value.ExportSelection = append([]SecurityAgentExportSelection(nil), args.EvidenceIDs...)
		}
		if wire.Action == "update_finding_response" && args.AssigneeID != "" {
			value.FindingResponse = args
		}
	}
	if validProductID(wire.RequesterID) {
		value.Requester = SecurityAgentApprovalRequester{State: "available", ID: &wire.RequesterID}
	}
	if !bytes.Equal(bytes.TrimSpace(wire.PlannerReceipt), []byte("null")) {
		var receipt struct {
			RunID    string          `json:"run_id"`
			PlanHash string          `json:"plan_hash"`
			Outcome  string          `json:"outcome"`
			Summary  json.RawMessage `json:"summary"`
		}
		if !exactJSONFields(wire.PlannerReceipt, "run_id", "plan_hash", "outcome", "summary") || decodeStrictDiscovery(wire.PlannerReceipt, &receipt) != nil || receipt.RunID != approval.RunID || receipt.PlanHash != wire.PlanHash || receipt.Outcome != "accepted" {
			return nil, ErrRepositoryUnavailable
		}
		value.Rationale = &SecurityAgentRationale{State: "withheld"}
		var summary string
		if json.Unmarshal(receipt.Summary, &summary) == nil {
			if safe, ok := sanitizeSecurityAgentRationale(summary); ok {
				value.Rationale = &SecurityAgentRationale{State: "available", Summary: safe}
			}
		}
	}
	return value, nil
}
