package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const gatewayBootstrapChecksumEnvironment = "ZASP_GATEWAY_BOOTSTRAP_PROFILE_CHECKSUM"

func gatewayBootstrapProfileCommand(command string) bool {
	return command == "up-gateway-bootstrap-profile" || command == "up-gateway-bootstrap-audit-profile"
}
func gatewayBootstrapCommandPin(command string) string {
	if command == "up-gateway-bootstrap-profile" {
		return migrations.GatewayBootstrapProfileChecksum()
	}
	if command == "up-gateway-bootstrap-audit-profile" {
		return migrations.GatewayBootstrapAuditProfileChecksum()
	}
	return ""
}
func validateGatewayBootstrapCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !gatewayBootstrapProfileCommand(arguments[0]) || getenv(gatewayBootstrapChecksumEnvironment) != gatewayBootstrapCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeGatewayBootstrapChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.GatewayBootstrapProfileChecksum(), migrations.GatewayBootstrapAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionGatewayBootstrapProfile(ctx context.Context) error {
	if err := r.gatewayBootstrapPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionGatewayBootstrapProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionGatewayBootstrapProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionGatewayBootstrapAuditProfile(ctx context.Context) error {
	if err := r.gatewayBootstrapPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionGatewayBootstrapAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionGatewayBootstrapAuditProfile(ctx)
}
func gatewayBootstrapPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !gatewayBootstrapProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_gateway_bootstrap_v1.raw_seal_ready() AND zasp_gateway_bootstrap_v1.effective_ready() AND EXISTS(SELECT 1 FROM zasp_gateway_bootstrap_v1.registration WHERE singleton AND checksum=$2)`, principal, gatewayBootstrapCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) gatewayBootstrapPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
