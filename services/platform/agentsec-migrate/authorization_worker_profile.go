package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationWorkerProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationWorkerProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionAuthorizationWorkerProfile(ctx)
}
