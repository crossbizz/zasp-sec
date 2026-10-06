package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Absence preserves the prior installed path. Presence with bad registration,
// roles or catalog is a hard failure, never a fallback to an older count.
func (d *PostgresJSONDatabase) SecurityAgentCommonAdmissionAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var present, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal73') IS NOT NULL`).Scan(&present); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !present {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal73.client_ready($1,$2)`, migrations.TemporalAdmissionChecksum(), migrations.TemporalAdmissionFingerprint()).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
