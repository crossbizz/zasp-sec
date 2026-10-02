package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationTemporalProfile(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$1 AND authority_role='zasp_discovery_authority')`, r.registration.migration).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationTemporalProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionAuthorizationTemporalProfile(ctx)
}
