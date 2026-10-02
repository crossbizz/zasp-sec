package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Exact installed presence is checked on every selection; invalid71 cannot
// select the historical55 client, including after an already-warm cutover.
func (d *PostgresJSONDatabase) LegacyTestsAvailable(ctx context.Context, role string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var present, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal71') IS NOT NULL`).Scan(&present); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !present {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal71.client_ready($1,$2,$3)`, migrations.ProductionTemporalLegacyTests().Checksum(), migrations.TemporalLegacyTestsFingerprint(), role).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
