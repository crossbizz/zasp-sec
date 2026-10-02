package apiserver

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Installation is optional; a present but invalid release never selects the
// historical mutation. SQL repeats this check in the mutation transaction.
func (d *PostgresJSONDatabase) RiskAutomaticSourcesAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var installed, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal77') IS NOT NULL`).Scan(&installed); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !installed {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal77.risk_api_ready($1,$2)`, migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
