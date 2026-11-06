package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const agentOwnerFilterChecksumEnvironment = "ZASP_AGENT_OWNER_FILTER_PROFILE_CHECKSUM"

func agentOwnerFilterProfileCommand(command string) bool {
	return command == "up-agent-owner-filter-profile" || command == "up-agent-owner-filter-audit-profile"
}
func agentOwnerFilterCommandPin(command string) string {
	if command == "up-agent-owner-filter-profile" {
		return migrations.AgentOwnerFilterProfileChecksum()
	}
	if command == "up-agent-owner-filter-audit-profile" {
		return migrations.AgentOwnerFilterAuditProfileChecksum()
	}
	return ""
}
func validateAgentOwnerFilterCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !agentOwnerFilterProfileCommand(arguments[0]) || getenv(agentOwnerFilterChecksumEnvironment) != agentOwnerFilterCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeAgentOwnerFilterChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.AgentOwnerFilterProfileChecksum(), migrations.AgentOwnerFilterAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentOwnerFilterProfile(ctx context.Context) error {
	if err := r.agentOwnerFilterPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentOwnerFilterProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentOwnerFilterProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentOwnerFilterAuditProfile(ctx context.Context) error {
	if err := r.agentOwnerFilterPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentOwnerFilterAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentOwnerFilterAuditProfile(ctx)
}
func agentOwnerFilterPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !agentOwnerFilterProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_agent_owner_filter_v1.catalog_ready($2)`, principal, agentOwnerFilterCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) agentOwnerFilterPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
