package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This receipt proves durable export admission, not artifact availability or a
// security outcome. The parent lease is cleared by the committed admission.
type SecurityAgentExportDispatchResult struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	RunID          string `json:"run_id"`
	StepID         string `json:"step_id"`
	ExportID       string `json:"export_id"`
	RunVersion     int64  `json:"run_version"`
	State          string `json:"state"`
	Replayed       bool   `json:"replayed"`
}

func (r *SecurityAgentWorkerRepository) ExecuteSecurityAgentExport(ctx context.Context, claim SecurityAgentRunClaim, worker, lease, audit, correlation string) (SecurityAgentExportDispatchResult, error) {
	var result SecurityAgentExportDispatchResult
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || !validSecurityAgentRunClaim(claim) || !claim.Prepared || !validSecurityAgentWorkerIdentity(worker, lease) || !validProductID(audit) || !validProductID(correlation) {
		return result, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, worker, lease, audit, correlation, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	if err != nil {
		return result, discoveryProviderError(err)
	}
	// A committed admission clears its lease. Its in-flight heartbeat may cancel
	// this context after SQL returned the receipt; validate that receipt before
	// deciding whether the operation was confirmed, as other executors do.
	fields, err := auditExportClosedObject(raw, 8192, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "export_id", "run_version", "state", "replayed")
	if err != nil || decodeStrictDiscovery(raw, &result) != nil || result.OrganizationID != claim.OrganizationID || result.WorkspaceID != claim.WorkspaceID || result.EnvironmentID != claim.EnvironmentID || result.RunID != claim.RunID || !validProductID(result.StepID) || !validProductID(result.ExportID) || !validSecurityAgentResultVersion(result.RunVersion, claim.Version) || result.State != "pending" {
		return SecurityAgentExportDispatchResult{}, ErrRepositoryUnavailable
	}
	var replayed *bool
	if json.Unmarshal(fields["replayed"], &replayed) != nil || replayed == nil {
		return SecurityAgentExportDispatchResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (r *SecurityAgentWorkerRepository) tryExecuteSecurityAgentExport(ctx context.Context, claim SecurityAgentRunClaim, worker, lease, audit, correlation string) (SecurityAgentExecuteResult, bool, error) {
	available, err := r.SecurityAgentExportsAvailable(ctx)
	if err != nil || !available {
		return SecurityAgentExecuteResult{}, false, err
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_run_kind($1,$2,$3,$4,$5,$6)`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, worker, lease)
	if err != nil {
		return SecurityAgentExecuteResult{}, false, discoveryProviderError(err)
	}
	var kind struct {
		Export *bool `json:"export"`
	}
	if _, err := auditExportClosedObject(raw, 1024, "export"); err != nil || decodeStrictDiscovery(raw, &kind) != nil || kind.Export == nil || ctx.Err() != nil {
		return SecurityAgentExecuteResult{}, false, ErrRepositoryUnavailable
	}
	if !*kind.Export {
		return SecurityAgentExecuteResult{}, false, nil
	}
	receipt, err := r.ExecuteSecurityAgentExport(ctx, claim, worker, lease, audit, correlation)
	if err != nil {
		return SecurityAgentExecuteResult{}, true, err
	}
	return SecurityAgentExecuteResult{RunID: receipt.RunID, StepID: receipt.StepID, Version: receipt.RunVersion, State: "verifying", ExportDispatch: &receipt}, true, nil
}
