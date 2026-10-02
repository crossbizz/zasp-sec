package apiserver

import (
	"encoding/json"
	"slices"
)

type SecurityAgentActivityTarget struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type SecurityAgentActivityTargetPage struct {
	Items    []SecurityAgentActivityTarget
	Coverage string
	NextID   string
}

func projectSecurityAgentActivityTargets(raw json.RawMessage, runID, kind, afterID string, limit int) (SecurityAgentActivityTargetPage, error) {
	fail := SecurityAgentActivityTargetPage{}
	if !validProductID(runID) || !stringIn(kind, "finding", "attack_path", "session") || afterID != "" && !validProductID(afterID) || limit < 1 || limit > 100 {
		return fail, ErrRepositoryOperation
	}
	if len(raw) > 16*1024*1024 {
		return fail, ErrRepositoryUnavailable
	}
	detail, err := decodeSecurityAgentRunContextEnvelope(raw, runID)
	if err != nil || detail.Run.State == "simulated" {
		return fail, ErrRepositoryUnavailable
	}
	result := SecurityAgentActivityTargetPage{Items: []SecurityAgentActivityTarget{}, Coverage: "complete"}
	targets := make(map[string]bool)
	triggerKind := map[string]string{"finding": "finding", "attack_path": "attack_path", "session": "runtime_decision"}[kind]
	if detail.RunContext == nil || detail.RunContext.Trigger == nil {
		result.Coverage = "partial"
	} else if detail.RunContext.Trigger.Kind == triggerKind {
		targets[detail.RunContext.Trigger.ID] = true
	}
	actions := make(map[string]SecurityAgentActionDetail, len(detail.ActionDetails))
	for _, action := range detail.ActionDetails {
		actions[action.StepID] = action
	}
	if detail.Plan != nil {
		for _, step := range detail.Plan.Steps {
			if !stringIn(step.Action, "update_finding_response", "create_temporary_policy", "isolate_session", "revoke_integration_connection") {
				result.Coverage = "partial"
				continue
			}
			if !(kind == "finding" && step.Action == "update_finding_response" || kind == "session" && step.Action == "isolate_session") {
				continue
			}
			action, known := actions[step.ID]
			if !known || action.Arguments == nil {
				result.Coverage = "partial"
				continue
			}
			// The envelope decoder has validated action type, run/step binding and
			// target/session equality. Generic evidence and policy scope IDs never
			// enter the target set.
			targets[action.Arguments.TargetID] = true
		}
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		if id > afterID {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) > limit {
		ids = ids[:limit]
		result.NextID = ids[len(ids)-1]
	}
	for _, id := range ids {
		result.Items = append(result.Items, SecurityAgentActivityTarget{Kind: kind, ID: id})
	}
	return result, nil
}
