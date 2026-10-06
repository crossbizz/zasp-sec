package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The composite command selects this exact audited recipe. Standalone worker
// dispatch continues to select the original profile. There is no mode fallback.
type authorizationRuntimeWorkerRunner struct {
	*registeredReleaseMigrationRunner
}

func (r authorizationRuntimeWorkerRunner) UpProductionAuthorizationWorkerProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationWorkerAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionAuthorizationWorkerAuditProfile(ctx)
}
