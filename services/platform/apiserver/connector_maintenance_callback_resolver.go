package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/url"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// ConnectorMaintenanceCallbackResolver resolves only a genuine, session-bound
// pending callback. It returns an integration candidate for the ORIGINAL live
// FGA decision; resolution itself grants no read, write or provider authority.
// Unselected runtimes retain the original resolver and target policy.
type ConnectorMaintenanceCallbackResolver struct {
	original AuthorizationTargetResolver
	database *PostgresJSONDatabase
	profile  string
}

func NewConnectorMaintenanceCallbackResolver(original AuthorizationTargetResolver, database *PostgresJSONDatabase, profile string) (*ConnectorMaintenanceCallbackResolver, error) {
	pin, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil || nilInterface(original) || database == nil || profile != pin {
		return nil, ErrRepositoryConfiguration
	}
	return &ConnectorMaintenanceCallbackResolver{original, database, profile}, nil
}
func (r *ConnectorMaintenanceCallbackResolver) ResolveAuthorization(ctx context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
	if r == nil || nilInterface(r.original) || ctx == nil || ctx.Err() != nil {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	if route.OperationID != "completeIntegrationOAuthCallback" {
		return r.original.ResolveAuthorization(ctx, identity, route)
	}
	if !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || identity.credentialBinding.Kind != CredentialBrowserSession || identity.credentialBinding.ID == "" || identity.credentialBinding.Digest == ([32]byte{}) || len(route.PathParameters) != 0 {
		return AuthorizationTargets{}, authorization.ErrInvalid
	}
	query, _ := ctx.Value(authorizationQueryContextKey{}).(url.Values)
	values, _, valid := exactConnectorCallbackQuery(query.Encode())
	if !valid {
		return AuthorizationTargets{}, authorization.ErrInvalid
	}
	state := sha256.Sum256([]byte(values.Get("state")))
	d := r.database
	d.mu.RLock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		d.mu.RUnlock()
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	var raw []byte
	err := d.driver.QueryRow(ctx, `SELECT zasp_connector_maintenance.callback_target($1,$2,$3,$4,$5,$6,$7,$8)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), identity.credentialBinding.ID, identity.credentialBinding.Digest[:], state[:], r.profile).Scan(&raw)
	d.mu.RUnlock()
	if err != nil {
		return AuthorizationTargets{}, classifyPostgresError(err)
	}
	var target struct {
		IntegrationID string `json:"integration_id"`
	}
	if decodeStrictDiscovery(json.RawMessage(raw), &target) != nil || !validProductID(target.IntegrationID) || ctx.Err() != nil {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	return resolveAuthorizationDatabase(ctx, d, identity, route, authorizationOperationTarget{Mode: "object", Kind: "integration"}, target.IntegrationID)
}
