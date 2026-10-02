package apiserver

import (
	"context"
	"encoding/json"
)

const (
	postgresSecurityAgentExportPlannerContextSQL = `SELECT public.zasp_sa_export_planner_context($1,$2,$3,$4,$5,$6)`
	postgresSecurityAgentExportAcceptPlannerSQL  = `SELECT public.zasp_sa_export_accept_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	postgresSecurityAgentExportReservePlannerSQL = `SELECT public.zasp_sa_export_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	postgresSecurityAgentExportFailPlannerSQL    = `SELECT public.zasp_sa_export_fail_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
)

// Receipt-aware SQL wrappers perform family dispatch internally. Acceptance or
// failure may have cleared the lease before a lost reply, so a separate leased
// family read cannot precede those operations. The wrapper still validates the
// original request and predecessor receipt; this is not new replay authority.
func (r *SecurityAgentWorkerRepository) exportPlannerReceiptStatement(ctx context.Context, fallback, exportStatement string) (string, bool, error) {
	available, err := r.SecurityAgentExportsAvailable(ctx)
	if err != nil {
		return "", false, err
	}
	if !available {
		return fallback, false, nil
	}
	return exportStatement, true, nil
}

// Route using registered current-lease authority before consulting predecessor
// families. A failed capability or kind read must never fall back to older SQL.
func (r *SecurityAgentWorkerRepository) exportPlannerStatement(ctx context.Context, claim SecurityAgentRunClaim, worker, lease, fallback, exportStatement string) (string, bool, error) {
	available, err := r.SecurityAgentExportsAvailable(ctx)
	if err != nil {
		return "", false, err
	}
	if !available {
		return fallback, false, nil
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_run_kind($1,$2,$3,$4,$5,$6)`, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, worker, lease)
	if err != nil {
		return "", false, discoveryProviderError(err)
	}
	var kind struct {
		Export *bool `json:"export"`
	}
	if _, err := auditExportClosedObject(raw, 1024, "export"); err != nil || decodeStrictDiscovery(raw, &kind) != nil || kind.Export == nil || ctx.Err() != nil {
		return "", false, ErrRepositoryUnavailable
	}
	if !*kind.Export {
		return fallback, false, nil
	}
	return exportStatement, true, nil
}

func decodeSecurityAgentPlannerExportSelection(raw json.RawMessage) ([]SecurityAgentExportSelection, error) {
	if len(raw) > 32768 {
		return nil, ErrRepositoryUnavailable
	}
	var selection []SecurityAgentExportSelection
	if json.Unmarshal(raw, &selection) != nil || !validSecurityAgentExportSelection(selection) {
		return nil, ErrRepositoryUnavailable
	}
	var refs []json.RawMessage
	if json.Unmarshal(raw, &refs) != nil {
		return nil, ErrRepositoryUnavailable
	}
	for _, ref := range refs {
		if _, err := auditExportClosedObject(ref, 1024, "source_kind", "source_id", "source_version", "association_digest"); err != nil {
			return nil, ErrRepositoryUnavailable
		}
	}
	return selection, nil
}
