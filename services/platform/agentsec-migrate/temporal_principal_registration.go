package main

import "context"

type temporalPrincipalRegistration struct{ operator, executor, compensation string }

func loadTemporalPrincipalRegistration(args []string, getenv func(string) string) (*temporalPrincipalRegistration, error) {
	if len(args) != 1 || args[0] != "register-temporal-executor-principals" || getenv == nil {
		return nil, errInvalidMigrationCommand
	}
	r := &temporalPrincipalRegistration{getenv(migrationPrincipalEnvironment), getenv("ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL"), getenv("ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL")}
	if !databasePrincipalPattern.MatchString(r.operator) || !databasePrincipalPattern.MatchString(r.executor) || !databasePrincipalPattern.MatchString(r.compensation) || r.operator == r.executor || r.operator == r.compensation || r.executor == r.compensation {
		return nil, errInvalidMigrationCommand
	}
	return r, nil
}

func registerTemporalPrincipals(ctx context.Context, q principalQueryer, r *temporalPrincipalRegistration) error {
	if ctx == nil || ctx.Err() != nil || q == nil || r == nil {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$1 AND authority_role='zasp_discovery_authority') AND zasp_temporal68.current_ready()`, r.operator).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	if err := q.QueryRow(ctx, `SELECT true FROM zasp_temporal68.register_principals($1,$2)`, r.executor, r.compensation).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}
