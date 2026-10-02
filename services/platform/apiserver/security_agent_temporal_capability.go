package apiserver

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *PostgresRepository) temporalAdmissionAvailable(ctx context.Context) (bool, error) {
	probe, ok := r.database.(interface {
		TemporalAdmissionAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.TemporalAdmissionAvailable(ctx)
}

// Absence allows the unchanged legacy58 route. Installed but unready66 never
// falls back to old admission, including an incomplete or malformed install.
func (d *PostgresJSONDatabase) TemporalAdmissionAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var installed, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal66') IS NOT NULL`).Scan(&installed); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !installed {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal66.ready($1,$2)`, migrations.ProductionTemporalOwnership().Checksum(), migrations.TemporalOwnershipFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
