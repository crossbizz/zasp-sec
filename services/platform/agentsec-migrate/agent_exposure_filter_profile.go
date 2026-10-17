package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const agentExposureFilterChecksumEnvironment = "ZASP_AGENT_EXPOSURE_FILTER_PROFILE_CHECKSUM"

func agentExposureFilterProfileCommand(command string) bool {
	return command == "up-agent-exposure-filter-profile" || command == "up-agent-exposure-filter-audit-profile"
}
func agentExposureFilterCommandPin(command string) string {
	if command == "up-agent-exposure-filter-profile" {
		return migrations.AgentExposureFilterProfileChecksum()
	}
	if command == "up-agent-exposure-filter-audit-profile" {
		return migrations.AgentExposureFilterAuditProfileChecksum()
	}
	return ""
}
func validateAgentExposureFilterCommand(arguments []string, getenv func(string) string) error {
	if len(arguments) != 1 || getenv == nil || !agentExposureFilterProfileCommand(arguments[0]) || getenv(agentExposureFilterChecksumEnvironment) != agentExposureFilterCommandPin(arguments[0]) {
		return errInvalidMigrationCommand
	}
	return nil
}
func writeAgentExposureFilterChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.AgentExposureFilterProfileChecksum(), migrations.AgentExposureFilterAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentExposureFilterProfile(ctx context.Context) error {
	if err := r.agentExposureFilterPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentExposureFilterProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentExposureFilterProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAgentExposureFilterAuditProfile(ctx context.Context) error {
	if err := r.agentExposureFilterPrincipal(ctx); err != nil {
		return err
	}
	e, ok := r.releaseMigrationRunner.(interface{ UpProductionAgentExposureFilterAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return e.UpProductionAgentExposureFilterAuditProfile(ctx)
}
func agentExposureFilterPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !agentExposureFilterProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_agent_exposure_filter_v1.catalog_ready($2)`, principal, agentExposureFilterCommandPin(command)).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Only public identity/membership facts are read before Runner legitimately
// selects the authority role. Private parent/profile gates run inside that role.
func (r *registeredReleaseMigrationRunner) agentExposureFilterPrincipal(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errReleasePrincipalRegistration
	}
	var ok bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&ok); err != nil || !ok {
		return errReleasePrincipalRegistration
	}
	return nil
}
