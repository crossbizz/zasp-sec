package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const agentReadChecksumEnvironment = "ZASP_AGENT_READ_PROFILE_CHECKSUM"

func agentReadProfileCommand(command string) bool {
	return command == "up-agent-read-profile" || command == "up-agent-read-audit-profile"
}
func agentReadCommandPin(command string) string {
	if command == "up-agent-read-profile" {
		return migrations.AgentReadProfileChecksum()
	}
	if command == "up-agent-read-audit-profile" {
		return migrations.AgentReadAuditProfileChecksum()
	}
	return ""
}
func validateAgentReadCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !agentReadProfileCommand(arguments[0]) || getenv(agentReadChecksumEnvironment) != agentReadCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeAgentReadChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.AgentReadProfileChecksum(), migrations.AgentReadAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentReadProfile(ctx context.Context) error {
	if err := r.agentReadPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentReadProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentReadProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentReadAuditProfile(ctx context.Context) error {
	if err := r.agentReadPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentReadAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentReadAuditProfile(ctx)
}
func agentReadPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !agentReadProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_agent_read_v1.catalog_ready($2)`, principal, agentReadCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) agentReadPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
