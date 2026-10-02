package apiserver

import (
	"context"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAuthorizationRuntimeReadySQL = `SELECT zasp_authorization80.ready($1), zasp_authorization80_audit.production_ready($1,$2,$3,$4)`

var authorizationRuntimeChecksums = sync.OnceValues(func() (string, string) {
	return migrations.ProductionAuthorizationEnforcement().Checksum(), migrations.AuthorizationAuditProfileChecksum()
})

// CurrentAuthorizationRuntimeReady is fixed metadata, never a product-query
// escape. Both independent80 and the exact guarded composed endpoint must pass.
func (d *PostgresJSONDatabase) CurrentAuthorizationRuntimeReady(ctx context.Context, authority, keyVersion string) error {
	if d == nil || ctx == nil || ctx.Err() != nil || (authority != "zasp_discovery_api" && authority != "zasp_security_agent_api") || len(keyVersion) != 64 {
		return ErrRepositoryUnavailable
	}
	for _, c := range keyVersion {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrRepositoryUnavailable
		}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.currentAuthorization || d.closed || nilInterface(d.driver) {
		return ErrRepositoryUnavailable
	}
	checksum, audit := authorizationRuntimeChecksums()
	var independent, production bool
	if err := d.driver.QueryRow(ctx, postgresAuthorizationRuntimeReadySQL, checksum, audit, keyVersion, authority).Scan(&independent, &production); err != nil || !independent || !production || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}
