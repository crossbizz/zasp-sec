package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const environmentClassChecksumEnvironment = "ZASP_ENVIRONMENT_CLASS_PROFILE_CHECKSUM"

func environmentClassProfileCommand(command string) bool {
	return command == "up-environment-class-profile" || command == "up-environment-class-audit-profile"
}
func environmentClassCommandPin(command string) string {
	if command == "up-environment-class-profile" {
		return migrations.EnvironmentClassProfileChecksum()
	}
	if command == "up-environment-class-audit-profile" {
		return migrations.EnvironmentClassAuditProfileChecksum()
	}
	return ""
}
func validateEnvironmentClassCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !environmentClassProfileCommand(arguments[0]) || getenv(environmentClassChecksumEnvironment) != environmentClassCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeEnvironmentClassChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.EnvironmentClassProfileChecksum(), migrations.EnvironmentClassAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionEnvironmentClassProfile(ctx context.Context) error {
	if err := r.environmentClassPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionEnvironmentClassProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionEnvironmentClassProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionEnvironmentClassAuditProfile(ctx context.Context) error {
	if err := r.environmentClassPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionEnvironmentClassAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionEnvironmentClassAuditProfile(ctx)
}
func environmentClassPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !environmentClassProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_environment_class_v1.catalog_ready($2)`, principal, environmentClassCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) environmentClassPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
