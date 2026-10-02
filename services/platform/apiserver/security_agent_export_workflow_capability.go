package apiserver

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *PostgresRepository) SecurityAgentExportDefinitionsAvailable(ctx context.Context) (bool, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || nilInterface(r.database) {
		return false, ErrRepositoryUnavailable
	}
	if !r.securityAgentExecution {
		return false, nil
	}
	probe, ok := r.database.(interface {
		SecurityAgentExportDefinitionsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.SecurityAgentExportDefinitionsAvailable(ctx)
}

func (r *PostgresRepository) SecurityAgentExportsWorkflowAvailable(ctx context.Context) (bool, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || nilInterface(r.database) {
		return false, ErrRepositoryUnavailable
	}
	if !r.securityAgentExecution {
		return false, nil
	}
	probe, ok := r.database.(interface {
		SecurityAgentExportsWorkflowAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.SecurityAgentExportsWorkflowAvailable(ctx)
}

// Export job settlement can be installed before public definition admission.
// Only the latter gate may allow the builder or activation path to proceed.
func (d *PostgresJSONDatabase) SecurityAgentExportDefinitionsAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var installed, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_sa_export_workflow_readiness(text,text)') IS NOT NULL`).Scan(&installed); err != nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	if !installed {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT public.zasp_sa_export_workflow_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
