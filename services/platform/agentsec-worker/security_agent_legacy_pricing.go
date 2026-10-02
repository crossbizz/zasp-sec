package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"sync/atomic"
	"time"
)

// Transitional installed70 composition. P9 retires this adapter with the old
// processor. Pricing authority remains the registered request-bound lookup.
type installedLegacyPricedPlanner struct {
	planner  *productionSecurityAgentPlanner
	database multisteppricing.Database
	bindings []securityAgentMultistepPricingBinding
}

func (p *installedLegacyPricedPlanner) Close() error { return p.planner.Close() }
func (p *installedLegacyPricedPlanner) Prepare(ctx context.Context, value securityAgentPlannerContext) (securityAgentPreparedPlan, error) {
	prepared, err := p.planner.Prepare(ctx, value)
	if err != nil {
		return nil, err
	}
	result := &installedLegacyPricedPlan{prepared: prepared.(*productionSecurityAgentPreparedPlan), database: p.database}
	found := false
	for _, b := range p.bindings {
		if b.OrganizationID == value.OrganizationID && b.WorkspaceID == value.WorkspaceID && b.EnvironmentID == value.EnvironmentID {
			if found {
				return result, nil
			}
			result.selection = b
			found = true
		}
	}
	if !found {
		return result, nil
	}
	bound, credential, err := result.lookup(ctx)
	if err == nil {
		result.approved = bound
		result.credential = credential
		result.hasBound = true
	}
	return result, nil
}

type installedLegacyPricedPlan struct {
	prepared   *productionSecurityAgentPreparedPlan
	database   multisteppricing.Database
	selection  securityAgentMultistepPricingBinding
	approved   multisteppricing.Bound
	credential string
	hasBound   bool
	consumed   atomic.Bool
}

func (p *installedLegacyPricedPlan) PlannerBudget() apiserver.SecurityAgentBudgetReservation {
	unknown := apiserver.SecurityAgentBudgetReservation{Model: p.prepared.identity.Model, CostUnit: "openrouter_credit"}
	if !p.hasBound {
		return unknown
	}
	expires, err := time.Parse(time.RFC3339Nano, p.approved.Policy.ExpiresAt)
	if err != nil {
		return unknown
	}
	bound := securityAgentVerifiedCostBound{request: p.prepared.identity, model: p.approved.Policy.Model, unit: p.approved.Policy.CostUnit, accountProfile: p.selection.AccountProfile, policyVersion: p.approved.CostPolicyVersion, expiresAt: expires, maximumTokens: p.approved.MaximumTokens, maximumCostNanoCredits: p.approved.MaximumCostNanoCredits}
	return bound.reservationFor(p.prepared.identity, p.selection.AccountProfile, time.Now())
}
func (p *installedLegacyPricedPlan) Dispatch(ctx context.Context) securityAgentPlannerResult {
	failure := securityAgentPlannerResult{Failure: securityAgentPlannerUnavailable}
	if p == nil || !p.consumed.CompareAndSwap(false, true) || !p.hasBound || ctx == nil || ctx.Err() != nil {
		return failure
	}
	current, credential, err := p.lookup(ctx)
	if err != nil || current != p.approved || credential != p.credential || p.PlannerBudget().MaximumTokens == 0 {
		return failure
	}
	expires, err := time.Parse(time.RFC3339Nano, current.Policy.ExpiresAt)
	if err != nil {
		return failure
	}
	work, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	return p.prepared.Dispatch(work)
}
func (p *installedLegacyPricedPlan) lookup(ctx context.Context) (multisteppricing.Bound, string, error) {
	empty := multisteppricing.Bound{}
	if ctx == nil || ctx.Err() != nil || p.prepared == nil || p.prepared.planner == nil || p.prepared.preparationContext == nil {
		return empty, "", errWorkerExecution
	}
	credential, ok := legacyPreparedCredential(p.prepared)
	if !ok {
		return empty, "", errWorkerExecution
	}
	value := p.prepared.contextValue
	s := p.selection
	if value.OrganizationID != s.OrganizationID || value.WorkspaceID != s.WorkspaceID || value.EnvironmentID != s.EnvironmentID {
		return empty, "", errWorkerExecution
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	repository, err := multisteppricing.New(p.database, "worker")
	if err != nil {
		return empty, "", errWorkerExecution
	}
	i := p.prepared.identity
	q := multisteppricing.LookupRequest{Scope: s.Scope, Provider: "openrouter", Model: i.Model, AccountProfile: s.AccountProfile, CostUnit: "openrouter_credit", CredentialReference: s.CredentialReference, CredentialDigest: credential, RequestPolicyVersion: i.PolicyVersion, RequestTokenLimit: int64(i.MaximumTokens), Body: p.prepared.body, BodyDigest: i.BodyDigest, PolicyID: s.PolicyID, PolicyVersion: s.PolicyVersion, PolicyDigest: s.PolicyDigest, AccountID: s.AccountID, AccountVersion: s.AccountVersion}
	raw, err := json.Marshal(q)
	if err != nil {
		return empty, "", errWorkerExecution
	}
	approved, err := repository.Lookup(ctx, raw)
	if err != nil {
		return empty, "", errWorkerExecution
	}
	after, ok := legacyPreparedCredential(p.prepared)
	if !ok || after != credential || ctx.Err() != nil {
		return empty, "", errWorkerExecution
	}
	return approved, credential, nil
}
func legacyPreparedCredential(prepared *productionSecurityAgentPreparedPlan) (string, bool) {
	if prepared.consumed.Load() || prepared.preparationContext.Err() != nil {
		return "", false
	}
	p := prepared.planner
	p.mu.RLock()
	defer p.mu.RUnlock()
	i := prepared.identity
	if p.closed || p.client == nil || p.client != prepared.client || p.model != i.Model || p.endpoint != i.Endpoint || i.Endpoint != "https://openrouter.ai/api/v1/chat/completions" || p.policyVersion != i.PolicyVersion || p.maximumTokens != i.MaximumTokens || !validSecurityAgentPlannerCredential(p.token) {
		return "", false
	}
	body := sha256.Sum256([]byte(prepared.body))
	if "sha256:"+hex.EncodeToString(body[:]) != i.BodyDigest {
		return "", false
	}
	credential := sha256.Sum256(p.token)
	return "sha256:" + hex.EncodeToString(credential[:]), true
}
