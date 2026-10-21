package apiserver

import (
	"context"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresAgentReadDetailSQL        = `SELECT zasp_agent_read_v1.detail($1,$2,$3,$4,$5)`
	postgresAgentReadCapabilitiesSQL  = `SELECT zasp_agent_read_v1.capabilities($1,$2,$3,$4,NULLIF($5,''),$6,$7)`
	postgresAgentReadRelationshipsSQL = `SELECT zasp_agent_read_v1.relationships($1,$2,$3,$4,NULLIF($5,''),$6,$7)`
	postgresAgentReadSessionsSQL      = `SELECT zasp_agent_read_v1.sessions($1,$2,$3,$4,NULLIF($5,''),$6,$7)`
)

func (r *PostgresRepository) RequireAgentReadProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsAgentReadProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentReadProfileChecksum = pin
	return nil
}
func (r *PostgresInventoryRepository) RequireAgentReadProfile(pin string) error {
	if r == nil || nilInterface(r.database) || !migrations.IsAgentReadProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentReadProfileChecksum = pin
	return nil
}

// Only an actual current request selects this profile. Missing configuration
// refuses before any query; it never falls back to the historical reader.
func (r *PostgresInventoryRepository) agentReadQuery(ctx context.Context, legacy, current string, args []any) (string, []any, error) {
	if _, ok := requestAuthorizationFromContext(ctx); !ok {
		return legacy, args, nil
	}
	if !migrations.IsAgentReadProfileChecksum(r.agentReadProfileChecksum) {
		return "", nil, ErrRepositoryUnavailable
	}
	return current, append(args, r.agentReadProfileChecksum), nil
}

func agentReadStatementAllowed(g RequestAuthorization, q string, args []any) (bool, bool) {
	operation := ""
	switch q {
	case postgresAgentReadDetailSQL:
		operation = "getAgent"
	case postgresAgentReadCapabilitiesSQL:
		operation = "getAgentCapabilities"
	case postgresAgentReadRelationshipsSQL:
		operation = "getAgentRelationships"
	case postgresAgentReadSessionsSQL:
		operation = "listAgentSessions"
	default:
		return false, false
	}
	count := 7
	if operation == "getAgent" {
		count = 5
	}
	if !validProductID(g.PathParameters["id"]) || len(args) != count || g.OperationID != operation || g.Collection || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) {
		return true, false
	}
	for n, want := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.PathParameters["id"]} {
		got, ok := args[n].(string)
		if !ok || got == "" || got != want {
			return true, false
		}
	}
	pin, ok := args[count-1].(string)
	if !ok || !migrations.IsAgentReadProfileChecksum(pin) || !authorizationNativeTargetAllowed(g, "agent", g.PathParameters["id"]) {
		return true, false
	}
	if operation != "getAgent" {
		after, aok := args[4].(string)
		limit, lok := args[5].(int)
		if !aok || !lok || limit < 1 || limit > 100 || !validAgentReadAfter(operation, after) {
			return true, false
		}
	}
	return true, true
}
func validAgentReadAfter(operation, after string) bool {
	if after == "" {
		return true
	}
	if operation != "getAgentCapabilities" {
		return validProductID(after)
	}
	parts := strings.Split(after, "~")
	return len(parts) == 3 && validProductID(parts[0]) && stringIn(parts[1], "data_read", "data_write", "action_execute", "identity_assume", "network_egress", "administration") && stringIn(parts[2], "read", "write", "execute", "assume", "connect", "administer")
}

func (d *PostgresJSONDatabase) AgentReadProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsAgentReadProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if err := d.driver.QueryRow(ctx, `SELECT zasp_agent_read_v1.caller_ready($1)`, pin).Scan(&ready); err != nil {
		return false, classifyPostgresError(err)
	}
	return ready, nil
}
