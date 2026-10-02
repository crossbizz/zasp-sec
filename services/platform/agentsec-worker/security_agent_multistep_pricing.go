package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
)

// This scoped selection contains references and pins, never credentials. A
// caller must already own a prepared request and its resolved credential. No
// default planner, token-file loader, reservation, or dispatch uses this path.
type securityAgentMultistepPricingBinding struct {
	multisteppricing.Scope
	AccountProfile      string `json:"account_profile"`
	CredentialReference string `json:"credential_reference"`
	PolicyID            string `json:"policy_id"`
	PolicyVersion       int64  `json:"policy_version"`
	PolicyDigest        string `json:"policy_digest"`
	AccountID           string `json:"account_id"`
	AccountVersion      int64  `json:"account_version"`
}

// The existing verified-bound type carries an administrator-approved ceiling.
// It is not a provider rate proof or dispatch permit. The future planning stage
// must recheck current authority, reserve, and settle actual reported usage.
func lookupSecurityAgentMultistepCost(ctx context.Context, db multisteppricing.Database, prepared *securityAgentOrderedPreparedPlan, selection securityAgentMultistepPricingBinding) (*securityAgentOrderedCostBound, error) {
	if ctx == nil || ctx.Err() != nil || prepared == nil || prepared.planner == nil || prepared.preparationContext == nil || prepared.contextValue.OrganizationID != selection.OrganizationID || prepared.contextValue.WorkspaceID != selection.WorkspaceID || prepared.contextValue.EnvironmentID != selection.EnvironmentID {
		return nil, errWorkerExecution
	}
	repository, err := multisteppricing.New(db, "worker")
	if err != nil {
		return nil, errWorkerExecution
	}
	credential, ok := orderedPreparedCredential(prepared)
	if !ok {
		return nil, errWorkerExecution
	}
	i := prepared.identity
	request := multisteppricing.LookupRequest{Scope: selection.Scope, Provider: "openrouter", Model: i.Model, AccountProfile: selection.AccountProfile, CostUnit: "openrouter_credit", CredentialReference: selection.CredentialReference, CredentialDigest: credential, RequestPolicyVersion: i.PolicyVersion, RequestTokenLimit: int64(i.MaximumTokens), Body: prepared.body, BodyDigest: i.BodyDigest, PolicyID: selection.PolicyID, PolicyVersion: selection.PolicyVersion, PolicyDigest: selection.PolicyDigest, AccountID: selection.AccountID, AccountVersion: selection.AccountVersion}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, errWorkerExecution
	}
	approved, err := repository.Lookup(ctx, raw)
	if err != nil {
		return nil, errWorkerExecution
	}
	current, ok := orderedPreparedCredential(prepared)
	if !ok || current != credential || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	expires, err := time.Parse(time.RFC3339Nano, approved.Policy.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return nil, errWorkerExecution
	}
	return &securityAgentOrderedCostBound{request: i, model: i.Model, unit: approved.Policy.CostUnit, accountProfile: selection.AccountProfile, policyVersion: approved.CostPolicyVersion, expiresAt: expires, maximumTokens: approved.MaximumTokens, maximumCostNanoCredits: approved.MaximumCostNanoCredits}, nil
}

func orderedPreparedCredential(prepared *securityAgentOrderedPreparedPlan) (string, bool) {
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
