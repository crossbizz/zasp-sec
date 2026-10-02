package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"time"
)

type securityAgentExportSettlementAuthority interface {
	SecurityAgentExportsAvailable(context.Context) (bool, error)
	ClaimSecurityAgentExportSettlements(context.Context, string, string, int, int) ([]apiserver.SecurityAgentExportSettlementClaim, error)
	SettleSecurityAgentExport(context.Context, apiserver.SecurityAgentExportSettlementClaim, string, string, string, string) (apiserver.SecurityAgentExportSettlementResult, error)
}

// Reconcile existing export facts with a dedicated link lease. This path has
// no planner, parent heartbeat or artifact writer authority.
func (p *securityAgentProcessor) reconcileExportSettlements(ctx context.Context) error {
	a, ok := p.config.Authority.(securityAgentExportSettlementAuthority)
	if !ok {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	available, err := a.SecurityAgentExportsAvailable(probe)
	probeErr := probe.Err()
	cancel()
	if err != nil || probeErr != nil {
		return errWorkerExecution
	}
	if !available {
		return nil
	}
	token, err := p.config.NewLeaseToken()
	if err != nil || len(token) < 16 || len(token) > 128 {
		return errWorkerExecution
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	claims, err := a.ClaimSecurityAgentExportSettlements(work, p.config.WorkerID, token, p.config.LeaseSeconds, p.config.BatchSize)
	claimErr := work.Err()
	cancel()
	if err != nil || claimErr != nil || len(claims) > p.config.BatchSize {
		return errWorkerExecution
	}
	for _, claim := range claims {
		if ctx.Err() != nil {
			return errWorkerExecution
		}
		ids, err := p.newProductIDs(2)
		if err != nil {
			return errWorkerExecution
		}
		succeeded := false
		for attempt := 0; attempt < 2; attempt++ {
			if ctx.Err() != nil {
				return errWorkerExecution
			}
			call, done := context.WithTimeout(ctx, 5*time.Second)
			result, err := a.SettleSecurityAgentExport(call, claim, p.config.WorkerID, token, ids[0], ids[1])
			callErr := call.Err()
			done()
			if err == nil && callErr == nil {
				if result.RunID != claim.RunID || result.StepID != claim.StepID || result.ExportID != claim.ExportID || result.RunVersion < claim.RunVersion || result.RunVersion > 1000000 {
					return errWorkerExecution
				}
				valid := result.State == "verifying" && result.Reason == "export_pending" && !result.Settled && !result.Replayed
				if result.Settled {
					switch result.Reason {
					case "export_available", "export_failed":
						valid = result.State == "needs_human" && result.RunVersion > claim.RunVersion
					case "export_cancelled":
						valid = result.State == "cancelled"
					case "export_parent_stopped":
						valid = result.State == "simulated" || result.State == "contained" || result.State == "remediated" || result.State == "needs_human" || result.State == "failed" || result.State == "inconclusive"
					}
				}
				if !valid {
					return errWorkerExecution
				}
				succeeded = true
				break
			}
		}
		if !succeeded {
			return errWorkerExecution
		}
	}
	return nil
}
