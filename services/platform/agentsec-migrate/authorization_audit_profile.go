package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func authorizationProfileCommand(command string) bool {
	return command == "up-authorization-worker-profile" || command == "up-authorization-temporal-profile" || command == "up-authorization-audit-profile" || command == "up-authorization-temporal-audit-profile" || command == "up-authorization-identity-profile" || command == "up-authorization-temporal-identity-profile"
}
func (r *registeredReleaseMigrationRunner) auditProfilePrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$1 AND authority_role='zasp_discovery_authority')`, r.registration.migration).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	return nil
}
func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationAuditProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionAuthorizationAuditProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationTemporalAuditProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationTemporalAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionAuthorizationTemporalAuditProfile(ctx)
}
