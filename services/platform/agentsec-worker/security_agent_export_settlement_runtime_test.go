package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"testing"
	"time"
)

type exportPollingAuthority struct {
	*securityAgentWorkerAuthorityStub
	available  bool
	probeErr   error
	settleErr  error
	claimHook  func(context.Context) error
	settleHook func(context.Context) error
	calls      [][3]string
}

func (a *exportPollingAuthority) SecurityAgentExportsAvailable(context.Context) (bool, error) {
	return a.available, a.probeErr
}
func (a *exportPollingAuthority) ClaimSecurityAgentExportSettlements(ctx context.Context, _ string, _ string, _ int, _ int) ([]apiserver.SecurityAgentExportSettlementClaim, error) {
	if a.claimHook != nil {
		if err := a.claimHook(ctx); err != nil {
			return nil, err
		}
	}
	return []apiserver.SecurityAgentExportSettlementClaim{{RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", ExportID: "pid_78000003-0000-4000-8000-000000000003", RunVersion: 3}}, nil
}
func (a *exportPollingAuthority) SettleSecurityAgentExport(ctx context.Context, c apiserver.SecurityAgentExportSettlementClaim, worker, token, audit, correlation string) (apiserver.SecurityAgentExportSettlementResult, error) {
	a.calls = append(a.calls, [3]string{token, audit, correlation})
	if a.settleHook != nil {
		if err := a.settleHook(ctx); err != nil {
			return apiserver.SecurityAgentExportSettlementResult{}, err
		}
	}
	if a.settleErr != nil {
		return apiserver.SecurityAgentExportSettlementResult{}, a.settleErr
	}
	if len(a.calls) == 1 {
		return apiserver.SecurityAgentExportSettlementResult{}, errors.New("committed reply lost")
	}
	return apiserver.SecurityAgentExportSettlementResult{RunID: c.RunID, StepID: c.StepID, ExportID: c.ExportID, RunVersion: 4, State: "needs_human", Reason: "export_available", Settled: true, Replayed: true}, nil
}

func TestSecurityAgentExportPollingInFlightCancellation(t *testing.T) {
	for _, mode := range []string{"claim_error", "claim_cancel", "settle_cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &exportPollingAuthority{securityAgentWorkerAuthorityStub: &securityAgentWorkerAuthorityStub{}, available: true}
			entered := false
			hook := func(work context.Context) error {
				entered = true
				deadline, ok := work.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) <= 0 {
					t.Error("I/O lacks bounded five-second deadline")
				}
				if mode == "claim_error" {
					return errors.New("claim failed")
				}
				cancel()
				select {
				case <-work.Done():
					return work.Err()
				case <-time.After(time.Second):
					t.Error("in-flight call did not receive cancellation")
					return errors.New("cancellation not propagated")
				}
			}
			if mode == "settle_cancel" {
				a.settleHook = hook
			} else {
				a.claimHook = hook
			}
			ids := 0
			p, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: a, Planner: successfulSecurityAgentPlanner(), WorkerID: "worker-1", LeaseSeconds: 60, BatchSize: 2, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return "lease-token-00000001", nil }, NewProductID: func() (string, error) {
				ids++
				if ids == 1 {
					return "pid_78000010-0000-4000-8000-000000000010", nil
				}
				return "pid_78000011-0000-4000-8000-000000000011", nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err = p.RunOnce(ctx)
			if err == nil || !entered || time.Since(started) > time.Second || a.claimCalls != 0 || a.scheduleCalls != 0 || a.expireCalls != 0 {
				t.Fatalf("failed/cancelled I/O did not stop tick: %v entered=%t", err, entered)
			}
			wantCalls := 0
			if mode == "settle_cancel" {
				wantCalls = 1
			}
			if len(a.calls) != wantCalls {
				t.Fatalf("cancel retried settlement: %d", len(a.calls))
			}
		})
	}
}

func TestSecurityAgentExportPollingFailureGates(t *testing.T) {
	for _, mode := range []string{"absent", "drift", "settlement_outage", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			a := &exportPollingAuthority{securityAgentWorkerAuthorityStub: &securityAgentWorkerAuthorityStub{}, available: mode != "absent"}
			if mode == "drift" {
				a.probeErr = errors.New("release drift")
			}
			if mode == "settlement_outage" {
				a.settleErr = errors.New("unavailable")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			ids := []string{"pid_78000010-0000-4000-8000-000000000010", "pid_78000011-0000-4000-8000-000000000011"}
			p, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: a, Planner: successfulSecurityAgentPlanner(), WorkerID: "worker-1", LeaseSeconds: 60, BatchSize: 2, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return "lease-token-00000001", nil }, NewProductID: func() (string, error) {
				if len(ids) == 0 {
					return "", errors.New("unexpected extra ID")
				}
				v := ids[0]
				ids = ids[1:]
				return v, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			err = p.RunOnce(ctx)
			if mode == "absent" {
				if err != nil || a.claimCalls != 1 || len(a.calls) != 0 {
					t.Fatalf("legacy polling changed: %v %d %v", err, a.claimCalls, a.calls)
				}
			} else if err == nil || a.claimCalls != 0 || a.scheduleCalls != 0 || a.expireCalls != 0 {
				t.Fatalf("failed settlement reached parent work: %v %d %d", err, a.claimCalls, a.scheduleCalls)
			}
			if mode == "settlement_outage" && (len(a.calls) != 2 || a.calls[0] != a.calls[1]) {
				t.Fatal("retry bound or identity lost")
			}
		})
	}
}
func TestSecurityAgentExportPollingPreservesRetryIdentity(t *testing.T) {
	authority := &exportPollingAuthority{securityAgentWorkerAuthorityStub: &securityAgentWorkerAuthorityStub{}, available: true}
	now := time.Now().UTC()
	ids := []string{"pid_78000010-0000-4000-8000-000000000010", "pid_78000011-0000-4000-8000-000000000011"}
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: authority, Planner: successfulSecurityAgentPlanner(), WorkerID: "worker-1", LeaseSeconds: 60, BatchSize: 2, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-00000001", nil }, NewProductID: func() (string, error) {
		if len(ids) == 0 {
			return "", errors.New("extra ID generation")
		}
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(authority.calls) != 2 || authority.calls[0] != authority.calls[1] || len(ids) != 0 || authority.claimCalls != 1 || len(authority.prepared) != 0 || len(authority.executed) != 0 {
		t.Fatalf("settlement did not preserve independent retry: calls=%v ids=%v parentClaims=%d", authority.calls, ids, authority.claimCalls)
	}
}
