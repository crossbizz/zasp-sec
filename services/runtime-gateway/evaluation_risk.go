package main

import (
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func resolvedGatewayEvaluation(request gatewayEvaluationRequest, decision string, matched []policy.CompiledPolicy) *gatewaycontrol.EvaluationEvidence {
	action, agent, session := request.Attributes["action"], request.Attributes["agent_id"], request.Attributes["session_id"]
	// Sparse legacy evaluation callers have no normalized action context. Do not
	// invent provenance for those events; configured runtime matching excludes them.
	if !boundedGatewayText(action, 64) || !validGatewayProductID(agent) || !validGatewayProductID(session) || request.Classification["session_id"] != session {
		return nil
	}
	value := &gatewaycontrol.EvaluationEvidence{Version: 1, Action: action, AgentID: agent, SessionID: session, ContributingPolicyIDs: []string{}}
	ranks := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	complete := true
	for _, compiled := range matched {
		if string(compiled.Action) != decision {
			continue
		}
		value.ContributingPolicyIDs = append(value.ContributingPolicyIDs, compiled.ID)
		if compiled.Risk == "" {
			complete = false
		}
		if ranks[compiled.Risk] > ranks[value.Risk] {
			value.Risk = compiled.Risk
		}
	}
	if !complete {
		value.Risk = ""
	}
	sort.Strings(value.ContributingPolicyIDs)
	return value
}

func cloneGatewayEvaluation(value *gatewaycontrol.EvaluationEvidence) *gatewaycontrol.EvaluationEvidence {
	if value == nil {
		return nil
	}
	result := *value
	result.ContributingPolicyIDs = cloneGatewayStringSlice(value.ContributingPolicyIDs)
	return &result
}

func sameGatewayEvaluation(left, right *gatewaycontrol.EvaluationEvidence) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Version == right.Version && left.Action == right.Action && left.AgentID == right.AgentID && left.SessionID == right.SessionID && left.Risk == right.Risk && sameGatewayStringSlice(left.ContributingPolicyIDs, right.ContributingPolicyIDs)
}
