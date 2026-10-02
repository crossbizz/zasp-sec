package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type SecurityAgentExportSettlementClaim struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	RunID          string    `json:"run_id"`
	StepID         string    `json:"step_id"`
	ExportID       string    `json:"export_id"`
	RunVersion     int64     `json:"run_version"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}
type SecurityAgentExportSettlementResult struct {
	RunID      string `json:"run_id"`
	StepID     string `json:"step_id"`
	ExportID   string `json:"export_id"`
	RunVersion int64  `json:"run_version"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
	Settled    bool   `json:"settled"`
	Replayed   bool   `json:"replayed"`
}

func (r *SecurityAgentWorkerRepository) ClaimSecurityAgentExportSettlements(ctx context.Context, worker, token string, seconds, limit int) ([]SecurityAgentExportSettlementClaim, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || !validSecurityAgentWorkerLease(worker, token, seconds) || limit < 1 || limit > 25 {
		return nil, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_settlement_claim($1,$2,$3,$4,$5,$6)`, worker, token, seconds, limit, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var items []json.RawMessage
	if len(raw) > 65536 || json.Unmarshal(raw, &items) != nil || items == nil || len(items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	claims := make([]SecurityAgentExportSettlementClaim, len(items))
	seen := map[string]bool{}
	for i, item := range items {
		_, closedErr := auditExportClosedObject(item, 65536, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "export_id", "run_version", "lease_expires_at")
		if closedErr != nil || decodeStrictDiscovery(item, &claims[i]) != nil || !validExportSettlementClaim(claims[i]) {
			return nil, ErrRepositoryUnavailable
		}
		c := claims[i]
		key := c.OrganizationID + "/" + c.WorkspaceID + "/" + c.EnvironmentID + "/" + c.RunID
		if seen[key] {
			return nil, ErrRepositoryUnavailable
		}
		seen[key] = true
	}
	return claims, nil
}
func (r *SecurityAgentWorkerRepository) SettleSecurityAgentExport(ctx context.Context, claim SecurityAgentExportSettlementClaim, worker, token, audit, correlation string) (SecurityAgentExportSettlementResult, error) {
	var result SecurityAgentExportSettlementResult
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || !validExportSettlementClaim(claim) || !validSecurityAgentWorkerIdentity(worker, token) || !validProductID(audit) || !validProductID(correlation) {
		return result, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, worker, token, audit, correlation, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	if err != nil {
		return result, discoveryProviderError(err)
	}
	_, closedErr := auditExportClosedObject(raw, 8192, "run_id", "step_id", "export_id", "run_version", "state", "reason", "settled", "replayed")
	if closedErr != nil || decodeStrictDiscovery(raw, &result) != nil || result.RunID != claim.RunID || result.StepID != claim.StepID || result.ExportID != claim.ExportID || result.RunVersion < claim.RunVersion || result.RunVersion > 1000000 {
		return SecurityAgentExportSettlementResult{}, ErrRepositoryUnavailable
	}
	var flags struct {
		Settled  *bool `json:"settled"`
		Replayed *bool `json:"replayed"`
	}
	if json.Unmarshal(raw, &flags) != nil || flags.Settled == nil || flags.Replayed == nil {
		return SecurityAgentExportSettlementResult{}, ErrRepositoryUnavailable
	}
	valid := false
	switch result.Reason {
	case "export_pending":
		valid = result.State == "verifying" && !result.Settled && !result.Replayed
	case "export_available", "export_failed":
		valid = result.State == "needs_human" && result.Settled && result.RunVersion > claim.RunVersion
	case "export_cancelled":
		valid = result.State == "cancelled" && result.Settled
	case "export_parent_stopped":
		valid = stringIn(result.State, "simulated", "contained", "remediated", "needs_human", "failed", "inconclusive") && result.Settled
	}
	if !valid {
		return SecurityAgentExportSettlementResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// SQL owns expiry and exact lost-reply replay authorization. Checking wall time
// here would reject a committed result replay after its lease expired.
func validExportSettlementClaim(c SecurityAgentExportSettlementClaim) bool {
	_, offset := c.LeaseExpiresAt.Zone()
	return validProductID(c.OrganizationID) && validProductID(c.WorkspaceID) && validProductID(c.EnvironmentID) && validProductID(c.RunID) && validProductID(c.StepID) && validProductID(c.ExportID) && c.RunVersion >= 1 && c.RunVersion <= 1000000 && !c.LeaseExpiresAt.IsZero() && offset == 0
}
