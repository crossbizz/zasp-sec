package main

import (
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// An authority result is bound to one request and account profile. There is
// deliberately no production constructor or producer in this batch. Structural
// checks here cannot establish pricing provenance or approve an account.
type securityAgentVerifiedCostBound struct {
	request                securityAgentPreparedRequestIdentity
	model                  string
	unit                   string
	accountProfile         string
	policyVersion          string
	expiresAt              time.Time
	maximumTokens          int64
	maximumCostNanoCredits int64
}

func (bound *securityAgentVerifiedCostBound) reservationFor(request securityAgentPreparedRequestIdentity, supportedProfile string, now time.Time) apiserver.SecurityAgentBudgetReservation {
	unknown := apiserver.SecurityAgentBudgetReservation{Model: request.Model, CostUnit: "openrouter_credit"}
	if bound == nil || bound.request != request || request.BodyDigest == "" || bound.model != request.Model || bound.unit != "openrouter_credit" || supportedProfile == "" || bound.accountProfile != supportedProfile || !validSecurityAgentPlannerToken(bound.policyVersion, 63, false) || !bound.expiresAt.After(now) || bound.maximumTokens < 1 || bound.maximumTokens > 12000 || bound.maximumCostNanoCredits < 1 || bound.maximumCostNanoCredits > 1000000000000 {
		return unknown
	}
	return apiserver.SecurityAgentBudgetReservation{Model: request.Model, CostUnit: bound.unit, CostPolicyVersion: bound.policyVersion, MaximumTokens: bound.maximumTokens, MaximumCostNanoCredits: bound.maximumCostNanoCredits}
}
