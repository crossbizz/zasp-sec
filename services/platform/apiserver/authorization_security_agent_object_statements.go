package apiserver

import (
	"encoding/json"
	"time"
)

// Authorized Security Agent run and approval statements added by
// migrations/baseline/completion.sql (section Y3). Each is one
// zasp_authorization80 function that binds the request to the attested proof
// and then calls the chain's reader or writer for the family that owns the
// object. The API sends exactly one of these per request; the family is
// chosen inside PostgreSQL, under the proof, never by an unauthorized probe.
const (
	currentSecurityAgentRunDetailSQL      = `SELECT zasp_authorization80.security_agent_run_detail($1,$2,$3,$4,$5)`
	currentSecurityAgentCancelRunSQL      = `SELECT zasp_authorization80.security_agent_cancel_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	currentSecurityAgentApprovalSQL       = `SELECT zasp_authorization80.security_agent_approval($1,$2,$3,$4,$5)`
	currentSecurityAgentDecideApprovalSQL = `SELECT zasp_authorization80.security_agent_decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	currentSecurityAgentSimulateSQL       = `SELECT zasp_authorization80.security_agent_simulate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)`
	currentSecurityAgentManualRunSQL      = `SELECT zasp_authorization80.security_agent_manual_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
)

// securityAgentObjectStatementAllowed admits the Security Agent run and
// approval contracts. It reports handled for every statement above, so none
// of them can reach the generic rule table with weaker preconditions.
// Operation, scope, actor, credential kind, fresh authentication, the path
// object and the allowed target are compared with the checked request here;
// PostgreSQL compares them again with the attested proof.
func securityAgentObjectStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	type rule struct {
		operation string
		arguments int
		kind      string
	}
	r, ok := map[string]rule{
		currentSecurityAgentRunDetailSQL:      {"getSecurityAgentRun", 5, "security_agent_run"},
		currentSecurityAgentCancelRunSQL:      {"cancelSecurityAgentRun", 10, "security_agent_run"},
		currentSecurityAgentApprovalSQL:       {"getSecurityAgentApproval", 5, "security_agent_approval"},
		currentSecurityAgentDecideApprovalSQL: {"decideSecurityAgentApproval", 12, "security_agent_approval"},
		currentSecurityAgentSimulateSQL:       {"simulateSecurityAgent", 14, "security_agent"},
		currentSecurityAgentManualRunSQL:      {"runSecurityAgent", 11, "security_agent"},
	}[q]
	if !ok {
		return false, false
	}
	if g.Collection || g.OperationID != r.operation || len(args) != r.arguments || !stringIn(string(g.Identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) {
		return true, false
	}
	o, w, e, actor := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	// Every statement starts with the scope, the path object and the actor.
	head, ok := securityAgentWriteStrings(args, 0, 1, 2, 3, 4)
	if !ok || head[0] != o || head[1] != w || head[2] != e || head[4] != actor ||
		!validProductID(head[3]) || head[3] != g.PathParameters["id"] || !authorizationNativeTargetAllowed(g, r.kind, head[3]) {
		return true, false
	}
	distinct := func(positions ...int) bool {
		values, ok := securityAgentWriteStrings(args, positions...)
		if !ok {
			return false
		}
		seen := map[string]struct{}{}
		for _, value := range values {
			if !validProductID(value) {
				return false
			}
			seen[value] = struct{}{}
		}
		return len(seen) == len(values)
	}
	mutation := func(key, version int, maximum int64) bool {
		values, ok := securityAgentWriteStrings(args, key)
		expected, versionOK := args[version].(int64)
		return ok && versionOK && validPublicIdempotency(values[0]) && expected >= 1 && expected <= maximum
	}
	switch q {
	case currentSecurityAgentRunDetailSQL, currentSecurityAgentApprovalSQL:
		return true, true
	case currentSecurityAgentCancelRunSQL:
		return true, mutation(5, 6, 1000000) && distinct(7, 8, 9)
	case currentSecurityAgentDecideApprovalSQL:
		// Browser session with fresh authentication. The time the statement
		// names is the session's own: the end of the fresh window the
		// request was admitted with, less the window.
		decision, ok := securityAgentWriteStrings(args, 7)
		fresh, freshOK := args[8].(time.Time)
		return true, g.Identity.CredentialKind == CredentialBrowserSession && g.Identity.FreshAuthenticated && !g.Identity.FreshAuthExpiresAt.IsZero() &&
			mutation(5, 6, 1000000) && ok && stringIn(decision[0], "approved", "rejected", "cancelled") &&
			freshOK && !fresh.IsZero() && fresh.Location() == time.UTC && fresh.Equal(g.Identity.FreshAuthExpiresAt.Add(-securityAgentFreshAuthenticationTTL)) && distinct(9, 10, 11)
	case currentSecurityAgentSimulateSQL:
		goal, ok := securityAgentWriteStrings(args, 8)
		evidence, evidenceOK := args[9].(json.RawMessage)
		expires, expiresOK := args[10].(time.Time)
		var ids []string
		return true, mutation(5, 6, 1000000) && ok && validSecurityAgentText(goal[0], 1024) && evidenceOK && len(evidence) <= 8192 && json.Unmarshal(evidence, &ids) == nil &&
			len(ids) >= 1 && len(ids) <= 100 && validUniqueProductIDs(ids) && expiresOK && !expires.IsZero() && expires.Location() == time.UTC && distinct(7, 11, 12, 13)
	case currentSecurityAgentManualRunSQL:
		return true, mutation(5, 6, 1000000) && distinct(7, 8, 9, 10)
	}
	return true, false
}
