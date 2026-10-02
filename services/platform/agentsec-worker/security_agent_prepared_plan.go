package main

import (
	"context"
	"net/http"
	"slices"
	"sync/atomic"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type securityAgentPreparedPlan interface {
	PlannerBudget() apiserver.SecurityAgentBudgetReservation
	Dispatch(context.Context) securityAgentPlannerResult
}

// The body digest includes provider routing parameters, data collection policy,
// schema and token limits. Credentials and the canonical database input digest
// are deliberately absent from this local request identity.
type securityAgentPreparedRequestIdentity struct {
	BodyDigest    string
	Model         string
	Endpoint      string
	PolicyVersion string
	MaximumTokens int
}

type productionSecurityAgentPreparedPlan struct {
	planner            *productionSecurityAgentPlanner
	preparationContext context.Context
	contextValue       securityAgentPlannerContext
	body               string
	identity           securityAgentPreparedRequestIdentity
	client             *http.Client
	consumed           atomic.Bool
}

func cloneSecurityAgentPlannerContext(value securityAgentPlannerContext) securityAgentPlannerContext {
	if value.ManualTrigger != nil {
		manual := *value.ManualTrigger
		value.ManualTrigger = &manual
	}
	value.AllowedActions = slices.Clone(value.AllowedActions)
	value.AllowedTargets = slices.Clone(value.AllowedTargets)
	value.Evidence = slices.Clone(value.Evidence)
	value.ExportSelection = slices.Clone(value.ExportSelection)
	if value.ExistingTest != nil {
		// The reference currently contains only string/int64 fields.
		reference := *value.ExistingTest
		value.ExistingTest = &reference
	}
	return value
}

func (prepared *productionSecurityAgentPreparedPlan) PlannerBudget() apiserver.SecurityAgentBudgetReservation {
	if prepared == nil {
		return apiserver.SecurityAgentBudgetReservation{}
	}
	// Production has no approved pricing producer. Unknown maxima must reach
	// durable reservation so the run records its stop before any dispatch.
	return apiserver.SecurityAgentBudgetReservation{Model: prepared.identity.Model, CostUnit: "openrouter_credit"}
}

func (prepared *productionSecurityAgentPreparedPlan) Dispatch(ctx context.Context) securityAgentPlannerResult {
	failure := securityAgentPlannerResult{Failure: securityAgentPlannerUnavailable}
	if prepared == nil || !prepared.consumed.CompareAndSwap(false, true) {
		return failure
	}
	failure.Model, failure.PolicyVersion = prepared.identity.Model, prepared.identity.PolicyVersion
	if ctx == nil || ctx.Err() != nil || prepared.preparationContext.Err() != nil {
		return failure
	}
	p := prepared.planner
	p.mu.RLock()
	i := prepared.identity
	if p.closed || p.client == nil || p.client != prepared.client || p.model != i.Model || p.endpoint != i.Endpoint || p.policyVersion != i.PolicyVersion || p.maximumTokens != i.MaximumTokens || len(p.token) == 0 {
		p.mu.RUnlock()
		return failure
	}
	// Credentials are read only after the one-shot and configuration checks.
	token := string(p.token)
	p.mu.RUnlock()
	return prepared.send(ctx, token)
}
