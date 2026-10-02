package apiserver

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// This private envelope is produced by the scoped database projection. It is
// never itself a public response, and decoder errors must not include its bytes.
func decodeSecurityAgentRunContextEnvelope(payload json.RawMessage, runID string) (SecurityAgentRunDetail, error) {
	var envelope struct {
		Detail  json.RawMessage `json:"detail"`
		Context json.RawMessage `json:"context"`
		Actions json.RawMessage `json:"action_details"`
	}
	withActions := exactJSONFields(payload, "detail", "context", "action_details")
	if !utf8.Valid(payload) || !withActions && !exactJSONFields(payload, "detail", "context") || decodeStrictDiscovery(payload, &envelope) != nil {
		return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
	}
	result, err := decodeSecurityAgentStoredRunDetail(envelope.Detail, runID)
	if err != nil {
		return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
	}
	var context struct {
		PreflightStopReason string          `json:"preflight_stop_reason"`
		Trigger             json.RawMessage `json:"trigger"`
		PlannerReceipt      json.RawMessage `json:"planner_receipt"`
	}
	withPreflightStop := exactJSONFields(envelope.Context, "trigger", "planner_receipt", "preflight_stop_reason")
	if !withPreflightStop && !exactJSONFields(envelope.Context, "trigger", "planner_receipt") || decodeStrictDiscovery(envelope.Context, &context) != nil || withPreflightStop && context.PreflightStopReason != "attack_lab_preflight_unavailable" {
		return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
	}
	projection := &SecurityAgentRunContext{PreflightStopReason: context.PreflightStopReason}
	if !bytes.Equal(bytes.TrimSpace(context.Trigger), []byte("null")) {
		var trigger SecurityAgentRunTrigger
		_, fieldErr := auditExportClosedObject(context.Trigger, 1024, "kind", "id", "version")
		if fieldErr != nil || decodeStrictDiscovery(context.Trigger, &trigger) != nil {
			return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
		}
		projection.Trigger = &trigger
	}
	if !bytes.Equal(bytes.TrimSpace(context.PlannerReceipt), []byte("null")) {
		var receipt struct {
			RunID    string          `json:"run_id"`
			PlanHash string          `json:"plan_hash"`
			Outcome  string          `json:"outcome"`
			Summary  json.RawMessage `json:"summary"`
		}
		if !exactJSONFields(context.PlannerReceipt, "run_id", "plan_hash", "outcome", "summary") || decodeStrictDiscovery(context.PlannerReceipt, &receipt) != nil || receipt.Outcome != "accepted" || receipt.RunID != runID || result.Plan == nil || receipt.PlanHash != result.Plan.PlanHash {
			return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
		}
		projection.Rationale = &SecurityAgentRationale{State: "withheld"}
		var raw string
		if json.Unmarshal(receipt.Summary, &raw) == nil {
			if summary, ok := sanitizeSecurityAgentRationale(raw); ok {
				projection.Rationale = &SecurityAgentRationale{State: "available", Summary: summary}
			}
		}
	}
	result.RunContext = projection
	if withActions {
		result.ActionDetails, err = decodeSecurityAgentActionDetails(envelope.Actions, result)
		if err != nil {
			return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
		}
	}
	if !validSecurityAgentRunDetail(result, runID) {
		return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
	}
	return result, nil
}
