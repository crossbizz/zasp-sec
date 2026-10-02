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
		return false, false
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
