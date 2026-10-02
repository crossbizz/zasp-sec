package apiserver

// These names are the finite source7/8 writer contracts, not caller SQL.
const (
	currentPATPageSQL            = `SELECT zasp_authorization80_identity.pat_page($1,$2,$3,$4,$5)`
	currentRevealPageSQL         = `SELECT zasp_authorization80_identity.reveal_page($1,$2,$3,$4,$5,$6)`
	currentRevealPATSQL          = `SELECT zasp_authorization80_identity.reveal_pat($1,$2,$3,$4,$5)`
	currentMemberRoleSQL         = `SELECT zasp_authorization80_identity.member_role($1,$2,$3,$4,$5,$6,$7,$8)`
	currentGroupMappingSQL       = `SELECT zasp_authorization80_identity.group_mapping($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	currentCreatePatSQL          = `SELECT zasp_authorization80_identity.create_pat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	currentRotatePatSQL          = `SELECT zasp_authorization80_identity.rotate_pat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
	currentRevokePatSQL          = `SELECT zasp_authorization80_identity.revoke_pat($1,$2,$3,$4,$5,$6,$7)`
	currentAckRevealSQL          = `SELECT zasp_authorization80_identity.ack_reveal($1,$2,$3,$4,$5,$6)`
	currentRevokeInvestigatedSQL = `SELECT zasp_authorization80_identity.revoke_investigated($1,$2,$3,$4,$5,$6,$7,$8)`
)

func identityAdministrationStatement(q string) string {
	switch q {
	case postgresUpdateMemberRoleSQL:
		return currentMemberRoleSQL
	case postgresUpsertGroupMappingSQL:
		return currentGroupMappingSQL
	case postgresCreateAPITokenSQL:
		return currentCreatePatSQL
	case postgresRotateAPITokenSQL:
		return currentRotatePatSQL
	case postgresRevokeAPITokenSQL:
		return currentRevokePatSQL
	case postgresAcknowledgeAPITokenRevealSQL:
		return currentAckRevealSQL
	case postgresRevokeInvestigatedSessionSQL:
		return currentRevokeInvestigatedSQL
	}
	return q
}

func identityAdministrationStatementAllowed(g RequestAuthorization, q string, args []any) (bool, bool) {
	type rule struct {
		query, op, kind                   string
		count, w, e, actor, target, audit int
	}
	rules := []rule{
		{currentMemberRoleSQL, "updateMemberRole", "organization_identity", 8, 5, 6, 8, 2, 7},
		{currentGroupMappingSQL, "updateGroupMappings", "environment", 9, 4, 5, 8, 2, 7},
		{currentCreatePatSQL, "createAPIToken", "environment", 17, 7, 8, 2, 6, 12},
		{currentRotatePatSQL, "rotateAPIToken", "environment", 16, 10, 11, 2, 5, 9},
		{currentRevokePatSQL, "revokeAPIToken", "environment", 7, 2, 3, 7, 4, 6},
		{currentAckRevealSQL, "acknowledgeAPITokenRevealGrant", "environment", 6, 2, 3, 4, 5, 6},
		{currentRevokeInvestigatedSQL, "revokeSession", "product_session", 8, 2, 3, 7, 4, 6},
	}
	for _, r := range rules {
		if q != r.query {
			continue
		}
		if len(args) != r.count || g.OperationID != r.op || g.Collection || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated {
			return true, false
		}
		o, w, e, p := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
		if args[0] != o || args[r.w-1] != w || args[r.e-1] != e || args[r.actor-1] != p {
			return true, false
		}
		audit, ok := args[r.audit-1].(string)
		if !ok || !validProductID(audit) {
			return true, false
		}
		target, ok := args[r.target-1].(string)
		if !ok || (r.op != "createAPIToken" && target != g.PathParameters["id"]) {
			return true, false
		}
		key := e
		if r.kind == "organization_identity" {
			key = o
		}
		if r.kind == "product_session" {
			key = target
		}
		return true, authorizationNativeTargetAllowed(g, r.kind, key)
	}
	return false, false
}
