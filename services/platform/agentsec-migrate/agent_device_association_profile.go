package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const agentDeviceAssociationChecksumEnvironment = "ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM"

func agentDeviceAssociationProfileCommand(command string) bool {
	return command == "up-agent-device-association-profile" || command == "up-agent-device-association-audit-profile"
}
func agentDeviceAssociationCommandPin(command string) string {
	if command == "up-agent-device-association-profile" {
		return migrations.AgentDeviceAssociationProfileChecksum()
	}
	if command == "up-agent-device-association-audit-profile" {
		return migrations.AgentDeviceAssociationAuditProfileChecksum()
	}
	return ""
}
func validateAgentDeviceAssociationCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !agentDeviceAssociationProfileCommand(arguments[0]) || getenv(agentDeviceAssociationChecksumEnvironment) != agentDeviceAssociationCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeAgentDeviceAssociationChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.AgentDeviceAssociationProfileChecksum(), migrations.AgentDeviceAssociationAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentDeviceAssociationProfile(ctx context.Context) error {
	if err := r.agentDeviceAssociationPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentDeviceAssociationProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentDeviceAssociationProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentDeviceAssociationAuditProfile(ctx context.Context) error {
	if err := r.agentDeviceAssociationPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentDeviceAssociationAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentDeviceAssociationAuditProfile(ctx)
}
func agentDeviceAssociationPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !agentDeviceAssociationProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_agent_device_association_v1.raw_seal_ready() AND zasp_agent_device_association_v1.effective_ready() AND EXISTS(SELECT 1 FROM zasp_agent_device_association_v1.registration WHERE singleton AND checksum=$2)`, principal, agentDeviceAssociationCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) agentDeviceAssociationPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
