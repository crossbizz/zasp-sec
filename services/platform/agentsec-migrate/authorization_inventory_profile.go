package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationInventoryProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	installer, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationInventoryProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return installer.UpProductionAuthorizationInventoryProfile(ctx)
}

func registerAuthorizationInventoryProfile(ctx context.Context, queryer principalQueryer, registration discoveryPrincipalRegistration) error {
	if ctx == nil || ctx.Err() != nil || queryer == nil {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator()`, registration.migration).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	// This compiled structural query pins both the catalog gate sources and the
	// profile checksum. API readiness separately requires its registered LOGIN.
	if err := queryer.QueryRow(ctx, migrations.AuthorizationInventoryInstallerReadySourceSQL()).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}
