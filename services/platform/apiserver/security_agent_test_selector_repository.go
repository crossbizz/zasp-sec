package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (d *PostgresJSONDatabase) SecurityAgentTestSelectorAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var present, ready bool
	if d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal75') IS NOT NULL`).Scan(&present) != nil {
		return false, ErrRepositoryUnavailable
	}
	if !present {
		return false, nil
	}
	if d.driver.QueryRow(ctx, `SELECT zasp_temporal75.ready($1,$2) AND zasp_security_agent_principal_ready('zasp_security_agent_worker')`, migrations.TemporalTestSelectorChecksum(), migrations.TemporalTestSelectorFingerprint()).Scan(&ready) != nil || !ready {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
