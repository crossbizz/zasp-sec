package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const gatewayInstallationChecksumEnvironment = "ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM"

func gatewayInstallationProfileCommand(command string) bool {
	return command == "up-gateway-installation-profile" || command == "up-gateway-installation-audit-profile"
}
func gatewayInstallationCommandPin(command string) string {
	if command == "up-gateway-installation-profile" {
		return migrations.GatewayInstallationProfileChecksum()
	}
	if command == "up-gateway-installation-audit-profile" {
		return migrations.GatewayInstallationAuditProfileChecksum()
	}
	return ""
}
func validateGatewayInstallationCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !gatewayInstallationProfileCommand(arguments[0]) || getenv(gatewayInstallationChecksumEnvironment) != gatewayInstallationCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeGatewayInstallationChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.GatewayInstallationProfileChecksum(), migrations.GatewayInstallationAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionGatewayInstallationProfile(ctx context.Context) error {
	if err := r.gatewayInstallationPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionGatewayInstallationProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionGatewayInstallationProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionGatewayInstallationAuditProfile(ctx context.Context) error {
	if err := r.gatewayInstallationPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionGatewayInstallationAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionGatewayInstallationAuditProfile(ctx)
}
func gatewayInstallationPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !gatewayInstallationProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_gateway_installation_v1.raw_seal_ready() AND zasp_gateway_installation_v1.effective_ready() AND EXISTS(SELECT 1 FROM zasp_gateway_installation_v1.registration WHERE singleton AND checksum=$2)`, principal, gatewayInstallationCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) gatewayInstallationPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
