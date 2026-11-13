package apiserver

// Discovery admits only these native72 API statements. Legacy writers and
// worker phases cannot borrow the human API decision.
func discovery72StatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	var operation string
	var count int
	switch q {
	case `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`:
		operation, count = "syncIntegration", 16
	case `SELECT zasp_temporal72.public_put_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`:
		operation, count = "putIntegrationSchedule", 12
	case `SELECT zasp_temporal72.public_delete_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`:
		operation, count = "deleteIntegrationSchedule", 10
	default:
		return discovery72ReadStatementAllowed(g, q, args)
	}
	if g.OperationID != operation || g.Collection || len(args) != count || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) {
		return true, false
	}
	for n, expected := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String(), g.PathParameters["id"]} {
		value, ok := args[n].(string)
		if !ok || value == "" || value != expected {
			return true, false
		}
	}
	return true, authorizationNativeTargetAllowed(g, "integration", g.PathParameters["id"])
}

// The integration read routes: one sync, the sync history, the schedule and
// the freshness of one integration. Each statement is bound
// to its operation, to the caller's scope and to the integration in the path;
// the integration (for one sync, the sync) must be among the objects the
// decision allows.
func discovery72ReadStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	var operation string
	var count int
	switch q {
	case `SELECT zasp_temporal72.sync_detail($1,$2,$3,$4,$5)`:
		operation, count = "getIntegrationSync", 5
	case `SELECT zasp_temporal72.sync_history($1,$2,$3,$4,$5,$6,$7)`:
		operation, count = "listIntegrationSyncs", 7
	case `SELECT zasp_temporal72.schedule_detail($1,$2,$3,$4)`:
		operation, count = "getIntegrationSchedule", 4
	case `SELECT zasp_temporal72.last_good_freshness($1,$2,$3,$4)`:
		operation, count = "getIntegrationFreshness", 4
	default:
		return false, false
	}
	if g.OperationID != operation || g.Collection || len(args) != count || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) {
		return true, false
	}
	for n, expected := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.PathParameters["id"]} {
		value, ok := args[n].(string)
		if !ok || value == "" || value != expected {
			return true, false
		}
	}
	if operation == "getIntegrationSync" {
		sync, ok := args[4].(string)
		return true, ok && sync != "" && sync == g.PathParameters["syncId"] && authorizationNativeTargetAllowed(g, "discovery_sync", sync)
	}
	return true, authorizationNativeTargetAllowed(g, "integration", g.PathParameters["id"])
}
