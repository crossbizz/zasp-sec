package main

import (
	"context"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type securityAgentBudgetAuthority interface {
	ReserveSecurityAgentPlannerBudget(context.Context, apiserver.SecurityAgentRunClaim, string, string, apiserver.SecurityAgentBudgetReservation) (apiserver.SecurityAgentBudgetPermit, error)
	SettleSecurityAgentPlannerBudget(context.Context, apiserver.SecurityAgentRunClaim, string, string, apiserver.SecurityAgentBudgetUsage) (apiserver.SecurityAgentBudgetSettlement, error)
}

func (processor *securityAgentProcessor) planWithBudget(ctx context.Context, claim apiserver.SecurityAgentRunClaim, leaseToken, inputDigest string, plannerContext securityAgentPlannerContext) (securityAgentPlannerResult, error) {
	zero := securityAgentPlannerResult{}
	authority, ok := processor.config.Authority.(securityAgentBudgetAuthority)
	if !ok {
		return zero, errWorkerExecution
	}
	prepared, err := processor.config.Planner.Prepare(ctx, plannerContext)
	if err != nil || prepared == nil {
		return zero, errWorkerExecution
	}
	request := prepared.PlannerBudget()
	// Stable within an attempt. Lost responses must not create a second permit.
	request.ReservationID = claim.RunID + "/planner/" + strconv.Itoa(claim.Attempt)
	request.InputDigest = inputDigest
	permit, err := authority.ReserveSecurityAgentPlannerBudget(ctx, claim, processor.config.WorkerID, leaseToken, request)
	if err != nil {
		return zero, err
	}
	if ctx.Err() != nil || permit.Reservation != request || permit.Version < claim.Version || permit.Version > 1000000 || request.MaximumTokens < 1 || request.MaximumTokens > 12000 || request.MaximumCostNanoCredits < 1 || request.MaximumCostNanoCredits > 1000000000000 || request.Model == "" || request.CostPolicyVersion == "" || request.CostUnit != "openrouter_credit" || !permit.ExpiresAt.After(time.Now()) {
		return zero, errWorkerExecution
	}
	providerCtx, cancel := context.WithDeadline(ctx, permit.ExpiresAt)
	result := prepared.Dispatch(providerCtx)
	cancel()
	usage := apiserver.SecurityAgentBudgetUsage{ReservationID: request.ReservationID, OutputDigest: result.OutputDigest}
	if result.Usage != nil && result.Model == request.Model {
		usage.Known = true
		usage.PromptTokens = result.Usage.PromptTokens
		usage.CompletionTokens = result.Usage.CompletionTokens
		usage.TotalTokens = result.Usage.TotalTokens
		usage.CostNanoCredits = result.Usage.CostNanoCredits
	}
	// A captured response still needs durable accounting after parent/heartbeat
	// cancellation. This bounded context cannot authorize Accept or Fail.
	settleCtx, settleCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer settleCancel()
	ack, err := authority.SettleSecurityAgentPlannerBudget(settleCtx, claim, processor.config.WorkerID, leaseToken, usage)
	if err != nil {
		return zero, err
	}
	if ack.ReservationID != request.ReservationID || ack.Known != usage.Known {
		return zero, errWorkerExecution
	}
	if ack.StopReason != "" {
		switch ack.StopReason {
		case "budget_deadline_exceeded", "budget_steps_exceeded", "budget_tokens_exceeded", "budget_cost_exceeded", "budget_usage_unknown":
			return zero, apiserver.ErrSecurityAgentBudgetStopped
		default:
			return zero, errWorkerExecution
		}
	}
	if !usage.Known || ctx.Err() != nil || !permit.ExpiresAt.After(time.Now()) {
		return zero, errWorkerExecution
	}
	return result, nil
}
