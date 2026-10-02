package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"time"
)

// Capability reads do not carry human authority. Actual GET/POST still require
// the exact current request attestation through the ordinary database facade.
func (d *PostgresJSONDatabase) SingleTestRecoveryAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	metadata := migrations.ProductionTemporalSingleRecoveryMetadata()
	if ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var present, valid, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal_single_recovery') IS NOT NULL`).Scan(&present); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !present {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, migrations.TemporalSingleRecoveryReadySourceSQL, metadata.ReadyBodyDigest).Scan(&valid); err != nil || !valid {
		return false, ErrRepositoryUnavailable
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.ready($1)`, metadata.Checksum).Scan(&ready); err != nil || !ready {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}

func NewSingleTestRecoveryWorkflowSurface(next, recovery http.Handler) (http.Handler, error) {
	if nilInterface(next) || nilInterface(recovery) {
		return nil, ErrRepositoryConfiguration
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := RoutedOperationFromRequest(r)
		if !ok {
			writeProductionError(w, r, ErrRepositoryAuthentication)
			return
		}
		if route.OperationID == "requestSingleTestCleanupRecovery" || route.OperationID == "getSingleTestCleanupRecovery" {
			recovery.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}
