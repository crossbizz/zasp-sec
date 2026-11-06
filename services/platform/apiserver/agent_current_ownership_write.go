package apiserver

import (
	"context"
	"encoding/json"
	"slices"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAgentOwnershipWriteSQL = `SELECT zasp_agent_ownership_write_v1.update_agent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`

func (r *PostgresRepository) RequireAgentOwnershipWriteProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsAgentOwnershipWriteProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentOwnershipWriteProfileChecksum = pin
	return nil
}
func (r *PostgresInventoryRepository) RequireAgentOwnershipWriteProfile(pin string) error {
	if r == nil || nilInterface(r.database) || !migrations.IsAgentOwnershipWriteProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentOwnershipWriteProfileChecksum = pin
	return nil
}

// Historical standalone repositories retain their original contract. An actual
// current grant requires an explicitly installed profile before any SQL call.
// The production current database independently refuses requests without proof.
func (r *PostgresInventoryRepository) agentOwnershipWriteQuery(ctx context.Context, args []any) (string, []any, error) {
	if _, current := requestAuthorizationFromContext(ctx); !current {
		return postgresInventoryUpdateAgentSQL, args, nil
	}
	if !migrations.IsAgentOwnershipWriteProfileChecksum(r.agentOwnershipWriteProfileChecksum) {
		return "", nil, ErrRepositoryUnavailable
	}
	return postgresAgentOwnershipWriteSQL, append(args, r.agentOwnershipWriteProfileChecksum), nil
}

func agentOwnershipWriteStatementAllowed(g RequestAuthorization, q string, args []any) (bool, bool) {
	if q != postgresAgentOwnershipWriteSQL {
		return false, false
	}
	if g.OperationID != "updateAgent" || g.Collection || len(args) != 13 || !validRequestIdentity(g.Identity, false) || len(g.Targets) != 1 || len(g.Allowed) != 1 || len(g.PathParameters) != 1 || !validProductID(g.PathParameters["id"]) || g.Credential.Kind != g.Identity.CredentialKind || g.Credential.ID == "" || g.Credential.Digest == ([32]byte{}) {
		return true, false
	}
	if g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken {
		return true, false
	}
	if g.Identity.CredentialKind == CredentialBearerToken && !slices.Contains(g.Credential.PATCeiling, "manage_workflows") {
		return true, false
	}
	id := g.PathParameters["id"]
	for _, target := range []AuthorizationTarget{g.Targets[0], g.Allowed[0]} {
		if target.Scope != g.Identity.Scope || target.Kind != "agent" || target.ID != id || target.SourceID != "" && target.SourceID != id {
			return true, false
		}
	}
	if g.Targets[0] != g.Allowed[0] {
		return true, false
	}
	for n, want := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String(), id} {
		value, ok := args[n].(string)
		if !ok || value != want {
			return true, false
		}
	}
	key, kok := args[5].(string)
	v, vok := args[6].(int64)
	owner, ook := args[7].(string)
	team, tok := args[8].(string)
	tags, jok := args[9].(json.RawMessage)
	audit, aok := args[10].(string)
	correlation, cok := args[11].(string)
	pin, pok := args[12].(string)
	if !kok || len(key) < 16 || len(key) > 128 || !workflowKeyPattern.MatchString(key) || !vok || v < 1 || v >= 1000000 || !ook || !tok || !jok || len(tags) > 4096 || !utf8.Valid(tags) || !aok || !cok || !validProductID(audit) || !validProductID(correlation) || !pok || !migrations.IsAgentOwnershipWriteProfileChecksum(pin) {
		return true, false
	}
	var selected []string
	if decodeStrictInventory(tags, &selected) != nil || !validAgentOwnershipInput(AgentOwnershipInput{Owner: owner, Team: team, Tags: selected}) {
		return true, false
	}
	return true, true
}

func (d *PostgresJSONDatabase) AgentOwnershipWriteProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsAgentOwnershipWriteProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if err := d.driver.QueryRow(ctx, `SELECT zasp_agent_ownership_write_v1.caller_ready($1)`, pin).Scan(&ready); err != nil {
		return false, classifyPostgresError(err)
	}
	return ready, nil
}
