package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"
)

type SecurityAgentBudgetReservation struct {
	ReservationID, InputDigest, Model, CostPolicyVersion, CostUnit string
	MaximumTokens, MaximumCostNanoCredits                          int64
}

type SecurityAgentBudgetPermit struct {
	Reservation SecurityAgentBudgetReservation
	Version     int64
	ExpiresAt   time.Time
}

type SecurityAgentBudgetUsage struct {
	ReservationID, OutputDigest                                  string
	Known                                                        bool
	PromptTokens, CompletionTokens, TotalTokens, CostNanoCredits int64
}

// SecurityAgentBudgetSettlement acknowledges accounting, not permission to run.
type SecurityAgentBudgetSettlement struct {
	ReservationID string
	Known         bool
	StopReason    string
}

func (repository *SecurityAgentWorkerRepository) ReserveSecurityAgentPlannerBudget(ctx context.Context, claim SecurityAgentRunClaim, workerID, leaseToken string, request SecurityAgentBudgetReservation) (SecurityAgentBudgetPermit, error) {
	zero := SecurityAgentBudgetPermit{}
	input, ok := decodeSecurityAgentDigest(request.InputDigest)
	if !ok || !validSecurityAgentText(request.ReservationID, 128) || !repository.budgetReady(ctx, claim, workerID, leaseToken) {
		return zero, ErrRepositoryUnavailable
	}
	statement, export, err := repository.exportPlannerStatement(ctx, claim, workerID, leaseToken, `SELECT zasp_security_agent_budget_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, postgresSecurityAgentExportReservePlannerSQL)
	if err != nil {
		return zero, err
	}
	if !export {
		existingTests, err := repository.existingTestPlannerRelease(ctx)
		if err != nil {
			return zero, err
		}
		if existingTests {
			statement = postgresSecurityAgentExistingTestReservePlannerSQL
		}
		statement, _, err = repository.attackLabStatement(ctx, claim, workerID, leaseToken, statement)
		if err != nil {
			return zero, err
		}
	}
	payload, err := repository.database.QueryJSON(ctx, statement, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, leaseToken, claim.Attempt, request.ReservationID, input, request.Model, request.CostPolicyVersion, request.CostUnit, request.MaximumTokens, request.MaximumCostNanoCredits)
	if err != nil {
		return zero, discoveryProviderError(err)
	}
	envelope, ok := budgetJSONObject(payload)
	if !ok || len(envelope) != 1 {
		return zero, ErrRepositoryUnavailable
	}
	if stop, exists := envelope["budget_stop"]; exists {
		if _, valid := budgetJSONObject(stop); valid && validSecurityAgentBudgetStop(payload, claim) {
			return zero, ErrSecurityAgentBudgetStopped
		}
		return zero, ErrRepositoryUnavailable
	}
	raw := envelope["budget_permit"]
	if !budgetJSONFields(raw, "organization_id", "workspace_id", "environment_id", "run_id", "attempt", "version", "reservation_id", "input_digest", "model", "cost_policy_version", "cost_unit", "maximum_tokens", "maximum_cost_nano_credits", "expires_at") {
		return zero, ErrRepositoryUnavailable
	}
	var permit struct {
		budgetResponseScope
		Version                int64     `json:"version"`
		ReservationID          string    `json:"reservation_id"`
		InputDigest            string    `json:"input_digest"`
		Model                  string    `json:"model"`
		CostPolicyVersion      string    `json:"cost_policy_version"`
		CostUnit               string    `json:"cost_unit"`
		MaximumTokens          int64     `json:"maximum_tokens"`
		MaximumCostNanoCredits int64     `json:"maximum_cost_nano_credits"`
		ExpiresAt              time.Time `json:"expires_at"`
	}
	if decodeStrictDiscovery(raw, &permit) != nil {
		return zero, ErrRepositoryUnavailable
	}
	actual := SecurityAgentBudgetReservation{permit.ReservationID, permit.InputDigest, permit.Model, permit.CostPolicyVersion, permit.CostUnit, permit.MaximumTokens, permit.MaximumCostNanoCredits}
	// PostgreSQL renders timestamptz in the connection's timezone. Compare the
	// instant, not its presentation offset, and expose UTC to downstream callers.
	permit.ExpiresAt = permit.ExpiresAt.UTC()
	now := time.Now().UTC()
	// Heartbeats advance the current lease beyond the original claim. SQL binds
	// expiry to that lease and the durable deadline; this is only a sanity bound.
	// No positive clock-skew allowance: a clock mismatch fails closed.
	if !permit.matches(claim) || permit.Version < claim.Version || permit.Version > 1000000 || actual != request || !validSecurityAgentText(actual.Model, 256) || !validSecurityAgentText(actual.CostPolicyVersion, 256) || actual.CostUnit != "openrouter_credit" || actual.MaximumTokens < 1 || actual.MaximumTokens > 12000 || actual.MaximumCostNanoCredits < 1 || actual.MaximumCostNanoCredits > 1000000000000 || permit.ExpiresAt.Location() != time.UTC || !permit.ExpiresAt.After(now) || permit.ExpiresAt.After(now.Add(300*time.Second)) {
		return zero, ErrRepositoryUnavailable
	}
	return SecurityAgentBudgetPermit{Reservation: actual, Version: permit.Version, ExpiresAt: permit.ExpiresAt}, nil
}

func (repository *SecurityAgentWorkerRepository) SettleSecurityAgentPlannerBudget(ctx context.Context, claim SecurityAgentRunClaim, workerID, leaseToken string, usage SecurityAgentBudgetUsage) (SecurityAgentBudgetSettlement, error) {
	zero := SecurityAgentBudgetSettlement{}
	if !validSecurityAgentText(usage.ReservationID, 128) || !repository.budgetReady(ctx, claim, workerID, leaseToken) {
		return zero, ErrRepositoryUnavailable
	}
	var output, prompt, completion, total, cost any
	if usage.Known {
		digest, ok := decodeSecurityAgentDigest(usage.OutputDigest)
		if !ok || usage.PromptTokens < 0 || usage.CompletionTokens < 0 || usage.TotalTokens < usage.PromptTokens || usage.TotalTokens-usage.PromptTokens != usage.CompletionTokens || usage.CostNanoCredits < 0 {
			return zero, ErrRepositoryUnavailable
		}
		output, prompt, completion, total, cost = digest, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens, usage.CostNanoCredits
	}
	// Unknown usage is SQL NULL, never an invented zero-charge settlement.
	payload, err := repository.database.QueryJSON(ctx, `SELECT zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, leaseToken, claim.Attempt, usage.ReservationID, output, prompt, completion, total, cost)
	if err != nil {
		return zero, discoveryProviderError(err)
	}
	envelope, ok := budgetJSONObject(payload)
	if !ok || len(envelope) != 1 {
		return zero, ErrRepositoryUnavailable
	}
	raw := envelope["budget_settlement"]
	if !budgetJSONFields(raw, "organization_id", "workspace_id", "environment_id", "run_id", "attempt", "reservation_id", "known", "stop_reason") {
		return zero, ErrRepositoryUnavailable
	}
	var response struct {
		budgetResponseScope
		ReservationID string `json:"reservation_id"`
		Known         bool   `json:"known"`
		StopReason    string `json:"stop_reason"`
	}
	if decodeStrictDiscovery(raw, &response) != nil || !response.matches(claim) || response.ReservationID != usage.ReservationID || response.Known != usage.Known || (!response.Known && response.StopReason == "") {
		return zero, ErrRepositoryUnavailable
	}
	if response.StopReason != "" && !validBudgetStopReason(response.StopReason) {
		return zero, ErrRepositoryUnavailable
	}
	return SecurityAgentBudgetSettlement{response.ReservationID, response.Known, response.StopReason}, nil
}

func (repository *SecurityAgentWorkerRepository) budgetReady(ctx context.Context, claim SecurityAgentRunClaim, workerID, leaseToken string) bool {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validSecurityAgentRunClaim(claim) || !validSecurityAgentWorkerIdentity(workerID, leaseToken) {
		return false
	}
	verifier, ok := repository.database.(interface{ VerifySecurityAgentBudgetRelease(context.Context) error })
	return ok && verifier.VerifySecurityAgentBudgetRelease(ctx) == nil
}

type budgetResponseScope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	RunID          string `json:"run_id"`
	Attempt        int    `json:"attempt"`
}

func (scope budgetResponseScope) matches(claim SecurityAgentRunClaim) bool {
	return scope.OrganizationID == claim.OrganizationID && scope.WorkspaceID == claim.WorkspaceID && scope.EnvironmentID == claim.EnvironmentID && scope.RunID == claim.RunID && scope.Attempt == claim.Attempt
}

func validBudgetStopReason(reason string) bool {
	switch reason {
	case "budget_deadline_exceeded", "budget_steps_exceeded", "budget_tokens_exceeded", "budget_cost_exceeded", "budget_usage_unknown":
		return true
	}
	return false
}

// Decode a single object without silently overwriting duplicate keys or
// accepting null values as the zero value of an authority field.
func budgetJSONObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func budgetJSONFields(raw json.RawMessage, names ...string) bool {
	fields, ok := budgetJSONObject(raw)
	if !ok || len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, exists := fields[name]; !exists {
			return false
		}
	}
	return true
}
