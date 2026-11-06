package main

import (
	"context"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// evaluateGatewayPolicyRules evaluates only the supplied envelope's rules.
// The caller verifies the envelope and controls evidence recording and dispatch.
// This function does not read the policy cache or mutate runtime evidence.
func evaluateGatewayPolicyRules(ctx context.Context, request gatewayEvaluationRequest, envelope policy.GatewayPolicyEnvelope) (gatewayEvaluationResult, []policy.CompiledPolicy, error) {
	result := gatewayEvaluationResult{Decision: "allow", MatchedPolicyIDs: []string{}, PolicyVersion: envelope.PolicyVersion, CacheState: policy.GatewayPolicyValid}
	var matched []policy.CompiledPolicy
	trigger := gatewayTrigger(request.ActionKind)
	for _, compiled := range envelope.Policies {
		if compiled.Trigger != trigger {
			continue
		}
		decision, err := policy.Evaluate(ctx, compiled, request.Attributes)
		if err != nil {
			return gatewayEvaluationResult{}, nil, errGatewayRuntime
		}
		if !decision.Matched {
			continue
		}
		result.MatchedPolicyIDs = append(result.MatchedPolicyIDs, compiled.ID)
		matched = append(matched, compiled)
		if decision.Action == policy.ActionBlock {
			result.Decision = "block"
		} else if result.Decision == "allow" {
			result.Decision = "monitor"
		}
	}
	sort.Strings(result.MatchedPolicyIDs)
	return result, matched, nil
}
