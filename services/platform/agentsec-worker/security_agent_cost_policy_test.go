package main

import (
	"context"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Only this test file can produce a positive bound. Its profile is a synthetic
// transport contract, never an approved production account or price source.
type controlledSecurityAgentPreparedPlan struct {
	prepared *productionSecurityAgentPreparedPlan
	bound    *securityAgentVerifiedCostBound
}

func controlledPreparedPlan(prepared *productionSecurityAgentPreparedPlan) *controlledSecurityAgentPreparedPlan {
	return &controlledSecurityAgentPreparedPlan{prepared: prepared, bound: &securityAgentVerifiedCostBound{
		request: prepared.identity, model: "openai/gpt-5-mini", unit: "openrouter_credit", accountProfile: "controlled-transport", policyVersion: "controlled-transport-v1",
		expiresAt: time.Now().Add(time.Minute), maximumTokens: 1000, maximumCostNanoCredits: 200,
	}}
}

func (p *controlledSecurityAgentPreparedPlan) PlannerBudget() apiserver.SecurityAgentBudgetReservation {
	return p.bound.reservationFor(p.prepared.identity, "controlled-transport", time.Now())
}
func (p *controlledSecurityAgentPreparedPlan) Dispatch(ctx context.Context) securityAgentPlannerResult {
	if p.PlannerBudget().MaximumTokens == 0 {
		return securityAgentPlannerResult{Failure: securityAgentPlannerUnavailable}
	}
	return p.prepared.Dispatch(ctx)
}

func TestSecurityAgentPreparedCostAuthorityRefusesUnboundValues(t *testing.T) {
	for _, mode := range []string{"valid", "absent", "request", "model", "unit", "profile", "unsupported_profile", "expired", "empty_policy", "tokens", "cost"} {
		t.Run(mode, func(t *testing.T) {
			transport := bindingResponseTransport()
			planner := requestBindingPlanner(t, transport)
			value, err := planner.Prepare(context.Background(), testSecurityAgentPlannerContext())
			if err != nil {
				t.Fatal(err)
			}
			p := controlledPreparedPlan(value.(*productionSecurityAgentPreparedPlan))
			switch mode {
			case "absent":
				p.bound = nil
			case "request":
				p.bound.request.BodyDigest = "sha256:wrong"
			case "model":
				p.bound.model = "another/model"
			case "unit":
				p.bound.unit = "usd"
			case "profile":
				p.bound.accountProfile = "other-account"
			case "unsupported_profile":
				p.bound.accountProfile = ""
			case "expired":
				p.bound.expiresAt = time.Now().Add(-time.Second)
			case "empty_policy":
				p.bound.policyVersion = ""
			case "tokens":
				p.bound.maximumTokens = 12001
			case "cost":
				p.bound.maximumCostNanoCredits = 1000000000001
			}
			budget := p.PlannerBudget()
			result := p.Dispatch(context.Background())
			if mode == "valid" {
				if budget.MaximumTokens != 1000 || budget.MaximumCostNanoCredits != 200 || result.Failure != "" || transport.calls != 1 {
					t.Fatalf("valid bound lost: %+v %+v calls=%d", budget, result, transport.calls)
				}
			} else if budget.MaximumTokens != 0 || budget.MaximumCostNanoCredits != 0 || budget.CostPolicyVersion != "" || result.Failure == "" || transport.calls != 0 {
				t.Fatalf("unbound request sent: budget=%+v result=%+v calls=%d", budget, result, transport.calls)
			}
		})
	}
}
