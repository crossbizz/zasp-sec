package apiserver

import (
	"context"
	"strings"
)

// Only the database adapter probes installation. A present but invalid72 is an
// error, never permission to select the retained authority.
func (d *PostgresJSONDatabase) TemporalDiscoveryAvailable(ctx context.Context, authority string) (bool, error) {
	return d.temporalDiscoveryCapability(ctx, authority, false)
}

func (d *PostgresJSONDatabase) TemporalDiscoveryRetainedAvailable(ctx context.Context, authority string) (bool, error) {
	return d.temporalDiscoveryCapability(ctx, authority, true)
}

func (d *PostgresJSONDatabase) temporalDiscoveryCapability(ctx context.Context, authority string, retained bool) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var installed, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal72') IS NOT NULL`).Scan(&installed); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !installed {
		return false, nil
	}
	query := `SELECT zasp_temporal72.principal_ready($1)`
	if retained {
		query = `SELECT zasp_temporal72.retained_principal_ready($1)`
	}
	if err := d.driver.QueryRow(ctx, query, authority).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}

func temporalDiscoveryAvailable(ctx context.Context, db JSONDatabase, authority string) (bool, error) {
	probe, ok := db.(interface {
		TemporalDiscoveryAvailable(context.Context, string) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return probe.TemporalDiscoveryAvailable(ctx, authority)
}

func (r *DiscoveryRepository) discoveryPublicSQL(legacy string) string {
	if !r.temporal {
		return legacy
	}
	return strings.Replace(legacy, "zasp_execution_", "zasp_temporal72.", 1)
}

func (r *DiscoveryRepository) validSync(value IntegrationSync, integrationID, syncID string) bool {
	if !r.temporal {
		return validPublicIntegrationSync(value, integrationID, syncID)
	}
	// A72-owned busy admission has not dispatched a provider page. Its immutable
	// wait receipt carries a not-before, but the public run attempt stays zero.
	if value.Attempt == 0 && value.Status == "queued" && value.LastErrorCode != nil {
		if *value.LastErrorCode != "retryable" || value.RetryAt == nil || !validPublicTime(*value.RetryAt) || value.RetryAt.Before(value.RequestedAt) || value.StartedAt != nil || value.CompletedAt != nil || value.SnapshotID != nil {
			return false
		}
		value.LastErrorCode, value.RetryAt = nil, nil
	}
	//72's SQL body checks ownership before admitting the pre-dispatch terminal
	// shape. No old job may acquire this exception through the compatibility read.
	if value.Attempt == 0 && stringIn(value.Status, "failed", "cancelled") {
		if value.StartedAt != nil || value.CompletedAt == nil || value.CompletedAt.Before(value.RequestedAt) || value.SnapshotID != nil || value.RetryAt != nil {
			return false
		}
		value.Attempt = 1 // Validate every remaining field with the unchanged decoder.
	}
	return validPublicIntegrationSync(value, integrationID, syncID)
}
