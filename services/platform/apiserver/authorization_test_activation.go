package apiserver

import (
	"context"
	"encoding/json"
	"time"
)

const currentTestActivateSQL = `SELECT zasp_authorization80_worker.test74_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

func (d *PostgresJSONDatabase) ActivateCurrentTemporalTestDefinition(ctx context.Context, args ...any) (json.RawMessage, error) {
	if d == nil || !d.CurrentAuthorizationRequired() {
		return nil, ErrRepositoryUnavailable
	}
	return d.QueryJSON(ctx, currentTestActivateSQL, args...)
}

func test74ActivationStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	if q != currentTestActivateSQL {
		return false, false
	}
	if g.OperationID != "activateSecurityAgent" || g.Collection || len(args) != 12 || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated {
		return true, false
	}
	for n, want := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.PathParameters["id"], g.Identity.PrincipalID.String()} {
		value, ok := args[n].(string)
		if !ok || value == "" || value != want {
			return true, false
		}
	}
	k, ok := args[5].(string)
	v, versionOK := args[6].(int64)
	activation, activationOK := args[7].(string)
	fresh, freshOK := args[8].(time.Time)
	if !ok || !validPublicIdempotency(k) || !versionOK || v < 1 || v > 999999 || !activationOK || !stringIn(activation, "validated", "supervised", "autonomous") || !freshOK || fresh.IsZero() || fresh.Location() != time.UTC || fresh != g.Identity.FreshAuthExpiresAt {
		return true, false
	}
	ids := make(map[string]struct{}, 3)
	for _, arg := range args[9:] {
		value, ok := arg.(string)
		if !ok || !validProductID(value) {
			return true, false
		}
		ids[value] = struct{}{}
	}
	return true, len(ids) == 3 && authorizationNativeTargetAllowed(g, "security_agent", g.PathParameters["id"])
}
