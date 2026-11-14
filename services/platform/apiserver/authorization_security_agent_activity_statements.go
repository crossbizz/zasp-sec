package apiserver

import (
	"context"
	"slices"
	"time"
)

// Authorized Security Agent activity, audit record and export statements
// added by migrations/baseline/completion.sql (section W4). Each is one
// zasp_authorization80 function bound to the attested proof of a browser
// session. The related-runs page also carries the attestation of a second
// decision (listSecurityAgentRuns), which the statement verifies.
const (
	currentSecurityAgentRunActivitySQL  = `SELECT zasp_authorization80.security_agent_run_activity($1,$2,$3,$4,$5,$6,$7,$8)`
	currentSecurityAgentActivityRunsSQL = `SELECT zasp_authorization80.security_agent_activity_runs($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	currentSecurityAgentAuditEventSQL   = `SELECT zasp_authorization80.security_agent_audit_event($1,$2,$3,$4,$5)`
	currentSecurityAgentExportGetSQL    = `SELECT zasp_authorization80.security_agent_export_get($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	currentSecurityAgentExportGrantSQL  = `SELECT zasp_authorization80.security_agent_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
)

// securityAgentActivityTargetKind maps the kind of an activity record in a
// request path to the authorization object kind that record is decided as.
// An audit record is decided through the run it belongs to; a session by the
// kind of session its identifier names.
func securityAgentActivityTargetKind(kind, id string) (string, bool) {
	switch kind {
	case "finding", "attack_path":
		return kind, true
	case "session":
		if runtimeSessionTarget(id) {
			return "session", true
		}
		return "product_session", true
	case "audit":
		return "security_agent_audit", true
	default:
		return "", false
	}
}

// securityAgentActivityStatementAllowed admits the activity, audit record and
// export contracts. It reports handled for every statement above, so none of
// them can reach the generic rule table. Operation, browser session, scope,
// actor, the path object and the allowed target are compared with the
// checked request here; PostgreSQL compares them again with the proof.
func securityAgentActivityStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	if !stringIn(q, currentSecurityAgentRunActivitySQL, currentSecurityAgentActivityRunsSQL, currentSecurityAgentAuditEventSQL, currentSecurityAgentExportGetSQL, currentSecurityAgentExportGrantSQL) {
		return false, false
	}
	if g.Collection || g.Identity.CredentialKind != CredentialBrowserSession {
		return true, false
	}
	o, w, e, actor := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	scope := func() bool {
		head, ok := securityAgentWriteStrings(args, 0, 1, 2)
		return ok && head[0] == o && head[1] == w && head[2] == e
	}
	// A parent-decided object (an audit record) is allowed when the proof
	// allows at least one target of the request's own scope: the resolver
	// named the record's run as the only target of this request.
	parentAllowed := func() bool {
		if len(g.Targets) == 0 || len(g.Allowed) != len(g.Targets) {
			return false
		}
		for _, target := range g.Allowed {
			if target.Kind != "security_agent_run" || target.Scope != g.Identity.Scope {
				return false
			}
		}
		return true
	}
	switch q {
	case currentSecurityAgentRunActivitySQL:
		if g.OperationID != "listSecurityAgentRunActivity" || len(args) != 8 || !scope() {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4, 5)
		limit, limitOK := args[7].(int)
		after, afterOK := args[6].(string)
		return true, ok && validProductID(values[0]) && values[0] == g.PathParameters["id"] && values[1] == actor && stringIn(values[2], "finding", "attack_path", "session", "audit") && values[2] == g.PathParameters["kind"] &&
			authorizationNativeTargetAllowed(g, "security_agent_run", values[0]) && limitOK && limit >= 1 && limit <= 100 && (args[6] == nil || afterOK && validProductID(after))
	case currentSecurityAgentActivityRunsSQL:
		if g.OperationID != "listSecurityAgentActivityRuns" || len(args) != 10 || !scope() {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4, 5)
		if !ok || values[0] != actor || !validProductID(values[2]) || values[1] != g.PathParameters["kind"] || values[2] != g.PathParameters["id"] {
			return true, false
		}
		kind, known := securityAgentActivityTargetKind(values[1], values[2])
		limit, limitOK := args[8].(int)
		proof, proofOK := args[9].(string)
		before, beforeOK := args[6].(time.Time)
		beforeID, beforeIDOK := args[7].(string)
		cursor := args[6] == nil && args[7] == nil || beforeOK && beforeIDOK && !before.IsZero() && validProductID(beforeID)
		target := known && (kind == "security_agent_audit" && parentAllowed() || kind != "security_agent_audit" && authorizationNativeTargetAllowed(g, kind, values[2]))
		return true, target && limitOK && limit >= 1 && limit <= 100 && cursor && proofOK && len(proof) >= 2 && len(proof) <= 4*1024*1024
	case currentSecurityAgentAuditEventSQL:
		if g.OperationID != "getSecurityAgentAuditEvent" || len(args) != 5 || !scope() {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4)
		return true, ok && validProductID(values[0]) && values[0] == g.PathParameters["id"] && values[1] == actor && parentAllowed()
	case currentSecurityAgentExportGetSQL, currentSecurityAgentExportGrantSQL:
		arguments, operations := 10, []string{"getSecurityAgentExport"}
		if q == currentSecurityAgentExportGrantSQL {
			arguments, operations = 13, []string{"createSecurityAgentExportDownloadGrant", "downloadSecurityAgentExport"}
		}
		if !stringIn(g.OperationID, operations...) || len(args) != arguments || !scope() {
			return true, false
		}
		values, ok := securityAgentWriteStrings(args, 3, 4, 5)
		digest, digestOK := args[6].([]byte)
		if !ok || !validProductID(values[0]) || !validProductID(values[1]) || values[0] != g.PathParameters["id"] || values[1] != g.PathParameters["stepId"] || values[2] != actor ||
			!authorizationNativeTargetAllowed(g, "security_agent_run", values[0]) || !digestOK || len(digest) != 32 {
			return true, false
		}
		if q == currentSecurityAgentExportGrantSQL {
			// The grant statement is 'issue' for the grant operation and one
			// of the three download phases for the download operation.
			phase, phaseOK := securityAgentWriteStrings(args, 10)
			return true, phaseOK && (g.OperationID == "createSecurityAgentExportDownloadGrant" && phase[0] == "issue" || g.OperationID == "downloadSecurityAgentExport" && stringIn(phase[0], "read", "consume", "integrity_failure"))
		}
		return true, true
	}
	return true, false
}

// securityAgentActivityPermitted says whether a request may ask for activity
// of this kind. A request with a current proof carries the operation's own
// permission ('view') in that proof, and the statement itself requires
// investigate_sessions or view_audit of the actor for a session or audit
// kind. A request without one keeps the retained contract on the identity's
// own permissions.
func securityAgentActivityPermitted(ctx context.Context, identity RequestIdentity, kind string) bool {
	if _, checked := requestAuthorizationFromContext(ctx); checked {
		return currentRequestHasPermission(ctx, identity, "view")
	}
	return slices.Contains(identity.Permissions, "view") && (kind != "session" || slices.Contains(identity.Permissions, "investigate_sessions")) && (kind != "audit" || slices.Contains(identity.Permissions, "view_audit"))
}
