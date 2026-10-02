package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type registeredReleaseMigrationRunner struct {
	releaseMigrationRunner
	queryer      principalQueryer
	registration discoveryPrincipalRegistration
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalTestExecutor(ctx context.Context) error {
	if runner == nil || runner.releaseMigrationRunner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal72.roles_ready()
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$2 AND authority_role='zasp_discovery_api')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$3 AND authority_role='zasp_discovery_worker')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$4 AND authority_role='zasp_outbox_worker')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$5 AND authority_role='zasp_discovery_scheduler')`, runner.registration.migration, runner.registration.api, runner.registration.discovery, runner.registration.outbox, runner.registration.scheduler).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalTestExecutor(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalTestExecutor(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalAdmission(ctx context.Context) error {
	if runner == nil || runner.releaseMigrationRunner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND zasp_temporal72.roles_ready()
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$2 AND authority_role='zasp_discovery_api')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$3 AND authority_role='zasp_discovery_worker')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$4 AND authority_role='zasp_outbox_worker')
 AND EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=$5 AND authority_role='zasp_discovery_scheduler')`, runner.registration.migration, runner.registration.api, runner.registration.discovery, runner.registration.outbox, runner.registration.scheduler).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalAdmission(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalAdmission(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalDiscovery(ctx context.Context) error {
	if runner == nil || runner.releaseMigrationRunner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$2 AND authority_role='zasp_discovery_api')
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$3 AND authority_role='zasp_discovery_worker')
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$4 AND authority_role='zasp_outbox_worker')
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_execution_principals WHERE principal_name=$5 AND authority_role='zasp_discovery_scheduler')`, runner.registration.migration, runner.registration.api, runner.registration.discovery, runner.registration.outbox, runner.registration.scheduler).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalDiscovery(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalDiscovery(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalLegacyTests(ctx context.Context) error {
	if runner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')`, runner.registration.migration).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalLegacyTests(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalLegacyTests(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalCompatibility(ctx context.Context) error {
	if runner == nil || runner.releaseMigrationRunner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var owner bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')`, runner.registration.migration).Scan(&owner); err != nil || !owner {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalCompatibility(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalCompatibility(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalWorkflow(ctx context.Context) error {
	if runner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')`, runner.registration.migration).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalWorkflow(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalWorkflow(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalExecutor(ctx context.Context) error {
	if runner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')`, runner.registration.migration).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalExecutor(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalExecutor(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalDomain(ctx context.Context) error {
	if runner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	// Refuse configuration/principal mismatches before the atomic DDL begins.
	// The extension retains existing bindings; it never registers new logins.
	var bound bool
	if err := runner.queryer.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')`, runner.registration.migration).Scan(&bound); err != nil || !bound {
		return errReleasePrincipalRegistration
	}
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalDomain(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalDomain(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionTemporalOwnership(ctx context.Context) error {
	extension, ok := runner.releaseMigrationRunner.(interface{ UpProductionTemporalOwnership(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalOwnership(ctx)
}

// Install only the delivery extension. Exact legacy60 or ordered61/public62
// authority is checked by Runner; this command never changes execution family.
func (runner *registeredReleaseMigrationRunner) UpProductionTemporalOutbox(ctx context.Context) error {
	extension, ok := runner.releaseMigrationRunner.(interface {
		UpProductionTemporalOutbox(context.Context) error
	})
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalOutbox(ctx)
}

// Keep the production wrapper's release59 command surface explicit: embedding
// an older interface otherwise hides these methods from command dispatch.
func (runner *registeredReleaseMigrationRunner) UpProductionSecurityAgentWebhooks(ctx context.Context) error {
	return runner.releaseMigrationRunner.UpProductionSecurityAgentWebhooks(ctx)
}

func (runner *registeredReleaseMigrationRunner) DownProductionSecurityAgentWebhooks(ctx context.Context) error {
	return runner.releaseMigrationRunner.DownProductionSecurityAgentWebhooks(ctx)
}

func (runner *registeredReleaseMigrationRunner) UpProductionDiscoveryScheduleReplay(ctx context.Context) error {
	return runner.releaseMigrationRunner.UpProductionDiscoveryScheduleReplay(ctx)
}

func (runner *registeredReleaseMigrationRunner) DownProductionDiscoveryScheduleReplay(ctx context.Context) error {
	return runner.releaseMigrationRunner.DownProductionDiscoveryScheduleReplay(ctx)
}

// Audit exports snapshots privileges against the registered migration owner.
// Bootstrap that binding at the exact predecessor, after checking its compiled
// authority, and recheck readiness after registration before any schema52 DDL.
func (runner *registeredReleaseMigrationRunner) UpProductionAuditExports(ctx context.Context) error {
	if runner == nil || runner.releaseMigrationRunner == nil || runner.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := runner.queryer.QueryRow(ctx, `SELECT zasp_production_runtime_precision_readiness($1,$2)`, migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	if err := registerForwardRelease(ctx, runner.queryer, runner.registration, []string{"up-to-51"}); err != nil {
		return err
	}
	return runner.releaseMigrationRunner.UpProductionAuditExports(ctx)
}
