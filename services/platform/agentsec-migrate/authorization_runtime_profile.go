package main

import (
	"context"
	"fmt"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var temporalProfileCommands = []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response"}

// Namespace inventory only chooses which exact native installer validates the
// current boundary. It never establishes readiness. Replaying an earlier
// installer over a later transformed catalog is deliberately avoided.
func authorizationRuntimeProfilePlan(version int64, namespaces []string) ([]string, error) {
	if version != 0 && version != 60 && version != 61 {
		return nil, migrations.ErrInvalidState
	}
	present := map[string]bool{}
	for _, name := range namespaces {
		if present[name] {
			return nil, migrations.ErrInvalidState
		}
		present[name] = true
	}
	if version != 61 && len(present) > 0 {
		return nil, migrations.ErrInvalidState
	}
	highest := -1
	for i := 0; i < len(temporalProfileCommands); i++ {
		name := fmt.Sprintf("zasp_temporal%d", 67+i)
		if present[name] {
			if highest != i-1 {
				return nil, migrations.ErrInvalidState
			}
			highest = i
			delete(present, name)
		}
	}
	// The 67 native cutover installs 65/66 source catalogs even on clean 60.
	// Require both retained catalogs and let the selected native readiness
	// validate their identities; namespace presence alone never admits them.
	if highest >= 0 {
		if !present["zasp_temporal65"] || !present["zasp_temporal66"] {
			return nil, migrations.ErrInvalidState
		}
		delete(present, "zasp_temporal65")
		delete(present, "zasp_temporal66")
	}
	authorization := []string{"zasp_authorization79", "zasp_authorization80", "zasp_authorization80_temporal", "zasp_authorization80_audit", "zasp_authorization80_identity"}
	projectionOnly := present["zasp_authorization79"] && !present["zasp_authorization80"] && !present["zasp_authorization80_temporal"] && !present["zasp_authorization80_audit"] && !present["zasp_authorization80_identity"]
	count := 0
	for _, name := range authorization {
		if present[name] {
			count++
			delete(present, name)
		}
	}
	worker := present["zasp_authorization80_worker"]
	delete(present, "zasp_authorization80_worker")
	if len(present) != 0 || count != 0 && (count != len(authorization) && !projectionOnly || highest != 11) || worker && count != len(authorization) {
		return nil, migrations.ErrInvalidState
	}
	end := []string{"up-authorization-temporal-identity-profile", "up-authorization-worker-profile"}
	if count != 0 {
		return end, nil
	}
	if highest >= 0 {
		return append(append([]string(nil), temporalProfileCommands[highest:]...), end...), nil
	}
	commands := append([]string(nil), temporalProfileCommands...)
	if version < 61 {
		commands = append([]string{"up-to-60"}, commands...)
	}
	return append(commands, end...), nil
}

func (r *registeredReleaseMigrationRunner) UpAuthorizationRuntimeProfile(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var principal bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1`, r.registration.migration).Scan(&principal); err != nil || !principal {
		return errReleasePrincipalRegistration
	}
	version, err := r.Version(ctx)
	if err != nil {
		return err
	}
	var namespaces []string
	if err = r.queryer.QueryRow(ctx, `SELECT COALESCE(array_agg(nspname::text ORDER BY nspname),ARRAY[]::text[]) FROM pg_namespace WHERE nspname ~ '^zasp_(temporal[0-9]+($|_)|authorization[0-9]+($|_))'`).Scan(&namespaces); err != nil {
		return errReleasePrincipalRegistration
	}
	commands, err := authorizationRuntimeProfilePlan(version, namespaces)
	if err != nil {
		return err
	}
	// Empty installation is already bound to the exact configured session.
	// Existing installations must prove their registered operator before DDL.
	if version != 0 {
		if err = r.auditProfilePrincipal(ctx); err != nil {
			return err
		}
	}
	for _, command := range commands {
		if err = runReleaseMigration(ctx, r, []string{command}); err != nil {
			return authorizationRuntimeProfileStepRefusal(command, "install", err)
		}
		if err = registerForwardRelease(ctx, r.queryer, r.registration, []string{command}); err != nil {
			return authorizationRuntimeProfileStepRefusal(command, "forward-readiness", err)
		}
	}
	return nil
}

func (r *registeredReleaseMigrationRunner) UpProductionTemporalAutomaticSources(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionTemporalAutomaticSources(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalAutomaticSources(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionTemporalFindingResponse(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionTemporalFindingResponse(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionTemporalFindingResponse(ctx)
}
