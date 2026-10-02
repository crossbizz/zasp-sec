package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *registeredReleaseMigrationRunner) UpProductionTemporalTestSelector(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal72.roles_ready()
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$2 AND authority_role='zasp_discovery_api')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$3 AND authority_role='zasp_discovery_worker')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$4 AND authority_role='zasp_outbox_worker')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$5 AND authority_role='zasp_discovery_scheduler')`, r.registration.migration, r.registration.api, r.registration.discovery, r.registration.outbox, r.registration.scheduler).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionTemporalTestSelector(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalTestSelector(ctx)
}
func configureTemporalTestSelector(ctx context.Context, q principalQueryer, raw string) error {
	if ctx == nil || q == nil || len(raw) == 0 || len(raw) > 4096 || !json.Valid([]byte(raw)) {
		return errInvalidMigrationCommand
	}
	var ready bool
	if q.QueryRow(ctx, `SELECT zasp_temporal75.ready($1,$2)`, migrations.ProductionTemporalTestSelector().Checksum(), migrations.TemporalTestSelectorFingerprint()).Scan(&ready) != nil || !ready {
		return errReleasePrincipalRegistration
	}
	var result []byte
	if q.QueryRow(ctx, `SELECT zasp_temporal75.configure($1::jsonb)`, raw).Scan(&result) != nil {
		return errInvalidMigrationCommand
	}
	return nil
}
