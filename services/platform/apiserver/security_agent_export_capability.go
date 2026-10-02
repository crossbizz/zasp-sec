package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This capability admits settlement of existing links, not new workflow
// activation. Public admission also needs planner and deployed-runtime checks.
func (r *SecurityAgentWorkerRepository) SecurityAgentExportsAvailable(ctx context.Context) (bool, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || nilInterface(r.database) {
		return false, ErrRepositoryUnavailable
	}
	probe, ok := r.database.(interface {
		SecurityAgentExportsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.SecurityAgentExportsAvailable(ctx)
}

func (d *PostgresJSONDatabase) SecurityAgentExportsAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var installed, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_sa_export_readiness(text,text)') IS NOT NULL`).Scan(&installed); err != nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	if !installed {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT public.zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
