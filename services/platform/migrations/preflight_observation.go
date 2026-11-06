package migrations

import "context"

// PreflightProfileState describes observed schema state, never migration rights.
type PreflightProfileState struct {
	Installed        bool
	CanonicalVersion int64
	Code             string
}

// ObservePreflightProfile uses only fixed SELECTs and the existing complete
// canonical verifier. The caller must supply its already ReadOnly transaction.
// This does not install, lock, grant, repair or substitute a profile.
func ObservePreflightProfile(ctx context.Context, q Queryer, recipe string) (PreflightProfileState, error) {
	if ctx == nil || nilInterface(q) || (recipe != "worker-v1" && recipe != "audit-identity-worker-v1") {
		return PreflightProfileState{}, ErrInvalidState
	}
	if ctx.Err() != nil {
		return PreflightProfileState{}, ctx.Err()
	}
	present, e := tablePresent(ctx, q)
	if e != nil {
		return PreflightProfileState{}, e
	}
	if !present {
		var partial bool
		e = scanRow(ctx, q, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname IN('zasp_temporal78','zasp_authorization79','zasp_authorization80','zasp_authorization80_temporal','zasp_authorization80_worker','zasp_authorization80_runtime','zasp_authorization80_audit','zasp_authorization80_identity'))`, nil, &partial)
		if e != nil {
			return PreflightProfileState{}, fixedDatabaseError(ctx, e)
		}
		if partial {
			return PreflightProfileState{}, ErrInvalidState
		}
		return PreflightProfileState{Code: "not_installed"}, nil
	}
	if e = readProductionSecurityAgentMultistepState(ctx, q); e != nil {
		return PreflightProfileState{}, e
	}
	_, worker := authorizationWorkerProfileSource()
	auditMode, identityMode := "none", "none"
	if recipe == "audit-identity-worker-v1" {
		_, worker = authorizationWorkerAuditProfileSource()
		auditMode = AuthorizationAuditProfileName
		identityMode = AuthorizationIdentityProfileName
	}
	_, temporal := authorizationTemporalProfileSource()
	runtimePin := AuthorizationRuntimeProfileChecksum()
	var current bool
	e = scanRow(ctx, q, `SELECT COALESCE(
 EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum=$1)
 AND zasp_authorization80_worker.catalog_ready()
 AND EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE singleton AND checksum=$2)
 AND zasp_authorization80_temporal.ready()
 AND (SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode=$3 AND identity_mode=$4) FROM zasp_authorization80.runtime_profile)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=$5)
 AND zasp_authorization80_runtime.catalog_ready(),false)`, []any{worker, temporal, auditMode, identityMode, runtimePin}, &current)
	if e != nil {
		return PreflightProfileState{}, fixedDatabaseError(ctx, e)
	}
	if !current {
		return PreflightProfileState{}, ErrInvalidState
	}
	if recipe == "audit-identity-worker-v1" {
		var valid bool
		e = scanRow(ctx, q, `SELECT zasp_authorization80_audit.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum=$1) AND zasp_authorization80_identity.structural_ready($2)`, []any{AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()}, &valid)
		if e != nil {
			return PreflightProfileState{}, fixedDatabaseError(ctx, e)
		}
		if !valid {
			return PreflightProfileState{}, ErrInvalidState
		}
	}
	if ctx.Err() != nil {
		return PreflightProfileState{}, ctx.Err()
	}
	return PreflightProfileState{Installed: true, CanonicalVersion: 61, Code: "current"}, nil
}
