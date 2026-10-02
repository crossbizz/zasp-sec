package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type budgetRuntimeAuthority struct {
	securityAgentWorkerAuthorityStub
	events                *[]string
	reserveErr, settleErr error
	stopReason            string
	usage                 apiserver.SecurityAgentBudgetUsage
	request               apiserver.SecurityAgentBudgetReservation
	permitChange          func(*apiserver.SecurityAgentBudgetPermit)
}

func (a *budgetRuntimeAuthority) ReserveSecurityAgentPlannerBudget(_ context.Context, claim apiserver.SecurityAgentRunClaim, _, _ string, request apiserver.SecurityAgentBudgetReservation) (apiserver.SecurityAgentBudgetPermit, error) {
	*a.events = append(*a.events, "reserve")
	a.request = request
	permit := apiserver.SecurityAgentBudgetPermit{Reservation: request, Version: claim.Version, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if a.permitChange != nil {
		a.permitChange(&permit)
	}
	return permit, a.reserveErr
}
func (a *budgetRuntimeAuthority) SettleSecurityAgentPlannerBudget(ctx context.Context, _ apiserver.SecurityAgentRunClaim, _, _ string, usage apiserver.SecurityAgentBudgetUsage) (apiserver.SecurityAgentBudgetSettlement, error) {
	*a.events = append(*a.events, "settle")
	if ctx.Err() != nil {
		return apiserver.SecurityAgentBudgetSettlement{}, ctx.Err()
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
		return apiserver.SecurityAgentBudgetSettlement{}, errors.New("accounting context is not bounded")
	}
	a.usage = usage
	return apiserver.SecurityAgentBudgetSettlement{ReservationID: usage.ReservationID, Known: usage.Known, StopReason: a.stopReason}, a.settleErr
}

type budgetRuntimePlanner struct {
	securityAgentPlannerStub
	events *[]string
	cancel context.CancelFunc
}

func (p *budgetRuntimePlanner) Prepare(ctx context.Context, value securityAgentPlannerContext) (securityAgentPreparedPlan, error) {
	*p.events = append(*p.events, "prepare")
	prepared, err := p.securityAgentPlannerStub.Prepare(ctx, value)
	if err != nil {
		return nil, err
	}
	return &securityAgentPreparedStub{budget: prepared.PlannerBudget(), dispatch: func(ctx context.Context) securityAgentPlannerResult {
		*p.events = append(*p.events, "plan")
		result := prepared.Dispatch(ctx)
		if p.cancel != nil {
			p.cancel()
		}
		return result
	}}, nil
}

func TestSecurityAgentProcessorBudgetDispatchAndAccountingOrder(t *testing.T) {
	for _, mode := range []string{"known", "reserve_stop", "reserve_error", "unknown", "unavailable", "settle_error", "cancel_after_response", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			events := []string{}
			a := &budgetRuntimeAuthority{events: &events}
			p := &budgetRuntimePlanner{securityAgentPlannerStub: *successfulSecurityAgentPlanner(), events: &events}
			p.result.Usage = &securityAgentBudgetUsage{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "reserve_stop":
				a.reserveErr = apiserver.ErrSecurityAgentBudgetStopped
			case "reserve_error":
				a.reserveErr = apiserver.ErrRepositoryUnavailable
			case "unknown":
				p.result.Usage = nil
				a.stopReason = "budget_usage_unknown"
			case "unavailable":
				p.result.Usage = nil
				p.result.Failure = securityAgentPlannerUnavailable
				p.result.OutputDigest = ""
				a.stopReason = "budget_usage_unknown"
			case "settle_error":
				a.settleErr = apiserver.ErrRepositoryUnavailable
			case "cancel_after_response":
				p.cancel = cancel
			case "rejected":
				p.result.Failure = securityAgentPlannerRejected
			}
			now := time.Now().UTC()
			processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: a, Planner: p, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) {
				events = append(events, "artifact")
				return "", errors.New("artifact boundary reached")
			}})
			if err != nil {
				t.Fatal(err)
			}
			err = processor.processClaim(ctx, securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", false, now), "lease-token-000000000001")
			want := []string{"prepare", "reserve", "plan", "settle"}
			if mode == "known" || mode == "rejected" {
				want = append(want, "artifact")
			}
			if mode == "reserve_stop" || mode == "reserve_error" {
				want = []string{"prepare", "reserve"}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("order=%v want=%v err=%v", events, want, err)
			}
			if mode == "reserve_stop" || mode == "unknown" || mode == "unavailable" {
				if !errors.Is(err, apiserver.ErrSecurityAgentBudgetStopped) {
					t.Fatalf("untyped stop: %v", err)
				}
			}
			if mode == "known" || mode == "rejected" || mode == "cancel_after_response" {
				if !a.usage.Known || a.usage.OutputDigest != p.result.OutputDigest || a.usage.TotalTokens != 0 || a.usage.ReservationID == "" {
					t.Fatalf("lost response accounting: %#v", a.usage)
				}
			}
		})
	}
}
