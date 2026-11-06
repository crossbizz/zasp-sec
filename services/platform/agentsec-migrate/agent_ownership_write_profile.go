package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const agentOwnershipWriteChecksumEnvironment = "ZASP_AGENT_OWNERSHIP_WRITE_PROFILE_CHECKSUM"

func agentOwnershipWriteProfileCommand(command string) bool {
	return command == "up-agent-ownership-write-profile" || command == "up-agent-ownership-write-audit-profile"
}
func agentOwnershipWriteCommandPin(command string) string {
	if command == "up-agent-ownership-write-profile" {
		return migrations.AgentOwnershipWriteProfileChecksum()
	}
	if command == "up-agent-ownership-write-audit-profile" {
		return migrations.AgentOwnershipWriteAuditProfileChecksum()
	}
	return ""
}
func validateAgentOwnershipWriteCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !agentOwnershipWriteProfileCommand(arguments[0]) || getenv(agentOwnershipWriteChecksumEnvironment) != agentOwnershipWriteCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeAgentOwnershipWriteChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.AgentOwnershipWriteProfileChecksum(), migrations.AgentOwnershipWriteAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentOwnershipWriteProfile(ctx context.Context) error {
	if err := r.agentOwnershipWritePrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentOwnershipWriteProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentOwnershipWriteProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentOwnershipWriteAuditProfile(ctx context.Context) error {
	if err := r.agentOwnershipWritePrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentOwnershipWriteAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentOwnershipWriteAuditProfile(ctx)
}
func agentOwnershipWritePostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !agentOwnershipWriteProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_agent_ownership_write_v1.catalog_ready($2)`, principal, agentOwnershipWriteCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) agentOwnershipWritePrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
