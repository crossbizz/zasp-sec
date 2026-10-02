package main

import (
	"context"
	"net/http"
	"slices"
	"sync/atomic"
	"time"
)

type securityAgentOrderedRequestIdentity struct {
	BodyDigest    string
	Model         string
	Endpoint      string
	PolicyVersion string
	MaximumTokens int
}

type securityAgentOrderedPreparedPlan struct {
	planner            *productionSecurityAgentPlanner
	preparationContext context.Context
	contextValue       securityAgentOrderedPlannerContext
	body               string
	identity           securityAgentOrderedRequestIdentity
	client             *http.Client
	consumed           atomic.Bool
}

func cloneSecurityAgentOrderedPlannerContext(value securityAgentOrderedPlannerContext) securityAgentOrderedPlannerContext {
	value.ManualTrigger = slices.Clone(value.ManualTrigger)
	value.AttackLab = slices.Clone(value.AttackLab)
	value.ExportSelection = slices.Clone(value.ExportSelection)
	value.AllowedActions = slices.Clone(value.AllowedActions)
	value.AllowedTargets = slices.Clone(value.AllowedTargets)
	value.Evidence = slices.Clone(value.Evidence)
	if value.ExistingTest != nil {
		reference := *value.ExistingTest
		value.ExistingTest = &reference
	}
	return value
}

type securityAgentOrderedCostBound struct {
	request                securityAgentOrderedRequestIdentity
	model                  string
	unit                   string
	accountProfile         string
	policyVersion          string
	expiresAt              time.Time
	maximumTokens          int64
	maximumCostNanoCredits int64
}

func (bound *securityAgentOrderedCostBound) validFor(request securityAgentOrderedRequestIdentity, supportedProfile string, now time.Time) bool {
	return bound != nil && bound.request == request && request.BodyDigest != "" && bound.model == request.Model && bound.unit == "openrouter_credit" && supportedProfile != "" && bound.accountProfile == supportedProfile && validSecurityAgentPlannerToken(bound.policyVersion, 63, false) && bound.expiresAt.After(now) && bound.maximumTokens >= 1 && bound.maximumTokens <= 12000 && bound.maximumCostNanoCredits >= 1 && bound.maximumCostNanoCredits <= 1000000000000
}
