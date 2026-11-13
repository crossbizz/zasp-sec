package apiserver

import "encoding/json"

// Authorized reads added by migrations/baseline/completion.sql. Each is a
// zasp_authorization80 function that returns data only inside the fenced
// transaction of a checked request (see authorization_transaction.go) and is
// admitted by an explicit rule in authorization_statement.go.
const (
	currentSecurityAgentPageSQL              = `SELECT zasp_authorization80.security_agent_page($1,$2,$3,NULLIF($4,''),$5)`
	currentSecurityAgentExecutionControlsSQL = `SELECT zasp_authorization80.security_agent_execution_controls($1,$2,$3,$4)`
	currentSecurityAgentRunPageSQL           = `SELECT zasp_authorization80.security_agent_run_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8)`
	currentSecurityAgentApprovalPageSQL      = `SELECT zasp_authorization80.security_agent_approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8,$9)`
	currentTestPageSQL                       = `SELECT zasp_authorization80.test_page($1,$2,$3,NULLIF($4,''),$5)`
	currentTestRunPageSQL                    = `SELECT zasp_authorization80.test_run_page($1,$2,$3,$4,NULLIF($5,''),$6)`
	currentAttackLabRunPageSQL               = `SELECT zasp_authorization80.attack_lab_run_page($1,$2,$3,$4,NULLIF($5,''),$6)`
	currentOrganizationSQL                   = `SELECT zasp_authorization80.organization($1,$2,$3)`
	currentMemberPageSQL                     = `SELECT zasp_authorization80.member_page($1,$2,$3,$4,$5,$6)`
	currentGroupMappingPageSQL               = `SELECT zasp_authorization80.group_mapping_page($1,$2,$3,$4,$5,$6)`
	currentIdentityProviderOrganizationSQL   = `SELECT zasp_authorization80.identity_provider_organization($1,$2,$3,$4)`

	// Single sign-on and SCIM connection writes (completion.sql section J).
	currentIdentityProviderReserveSQL     = `SELECT zasp_authorization80.identity_provider_reserve($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14)`
	currentIdentityProviderMarkUnknownSQL = `SELECT zasp_authorization80.identity_provider_mark_unknown($1,$2,$3,$4,$5,$6,$7,$8)`
	currentIdentityProviderCompleteSQL    = `SELECT zasp_authorization80.identity_provider_complete($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14)`
	currentIdentityProviderRevealSQL      = `SELECT zasp_authorization80.identity_provider_reveal_secret($1,$2,$3,$4,$5)`

	// Capability readiness for the current catalog. The historical probes pin
	// a 60-release count the 61-release baseline can never satisfy.
	currentSecurityAgentAttackLabReadySQL = `SELECT zasp_authorization80.security_agent_attack_lab_ready($1,$2)`
	currentSecurityAgentExportReadySQL    = `SELECT zasp_authorization80.security_agent_export_ready($1,$2)`
	currentTestReleaseReadySQL            = `SELECT zasp_authorization80.test_release_ready($1,$2)`
)

// completionStatementAllowed admits the completion reads. It reports handled
// for every statement above, so none of them can reach the generic rule table
// with weaker preconditions. Scope, actor and target arguments are compared
// with the checked request; PostgreSQL compares them again with the attested
// proof.
func completionStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	type rule struct {
		operations     []string
		arguments      int
		collection     bool // The request must be a collection read.
		browserOnly    bool
		actor          int // One-based position of the principal argument, zero when absent.
		targetKind     string
		targetArgument int // One-based position of the scope target argument.
	}
	rules := map[string]rule{
		currentSecurityAgentPageSQL:              {operations: []string{"listSecurityAgents"}, arguments: 5, collection: true},
		currentSecurityAgentExecutionControlsSQL: {operations: []string{"getSecurityAgentExecutionControls"}, arguments: 4, browserOnly: true, actor: 4, targetKind: "environment", targetArgument: 3},
		currentSecurityAgentRunPageSQL:           {operations: []string{"listSecurityAgentRuns"}, arguments: 8, collection: true},
		currentSecurityAgentApprovalPageSQL:      {operations: []string{"listSecurityAgentApprovals"}, arguments: 9, collection: true, actor: 9},
		currentTestPageSQL:                       {operations: []string{"listTests"}, arguments: 5, collection: true},
		currentTestRunPageSQL:                    {operations: []string{"listTestRuns"}, arguments: 6, collection: true},
		currentAttackLabRunPageSQL:               {operations: []string{"listAttackLabRuns"}, arguments: 6, collection: true},
		currentOrganizationSQL:                   {operations: []string{"getOrganization"}, arguments: 3, browserOnly: true, targetKind: "organization", targetArgument: 1},
		currentMemberPageSQL:                     {operations: []string{"listMembers"}, arguments: 6, browserOnly: true, actor: 4, targetKind: "organization_identity", targetArgument: 1},
		currentGroupMappingPageSQL:               {operations: []string{"listGroupMappings"}, arguments: 6, browserOnly: true, actor: 4, targetKind: "environment", targetArgument: 3},
		currentIdentityProviderOrganizationSQL:   {operations: []string{"listSSOConnections", "listSCIMConnections"}, arguments: 4, browserOnly: true, actor: 4, targetKind: "organization_identity", targetArgument: 1},
	}
	if handled, allowed := identityProviderStatementAllowed(g, q, args); handled {
		return true, allowed
	}
	r, ok := rules[q]
	if !ok {
		return false, false
	}
	if len(args) != r.arguments || !stringIn(g.OperationID, r.operations...) || g.Collection != r.collection {
		return true, false
	}
	if r.browserOnly && g.Identity.CredentialKind != CredentialBrowserSession {
		return true, false
	}
	for n, expected := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()} {
		if value, isString := args[n].(string); !isString || value != expected {
			return true, false
		}
	}
	if r.actor > 0 {
		if value, isString := args[r.actor-1].(string); !isString || value != g.Identity.PrincipalID.String() {
			return true, false
		}
	}
	if r.targetKind != "" {
		value, isString := args[r.targetArgument-1].(string)
		if !isString || !authorizationNativeTargetAllowed(g, r.targetKind, value) {
			return true, false
		}
	}
	return true, true
}

// identityProviderStatementAllowed admits the connection writes: a browser
// session with fresh authentication, the request's own operation, scope and
// principal, and the Organization's identity as the checked target. A
// reservation of a delete or a test must name the connection of the path.
func identityProviderStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	count := map[string]int{currentIdentityProviderReserveSQL: 14, currentIdentityProviderMarkUnknownSQL: 8, currentIdentityProviderCompleteSQL: 14, currentIdentityProviderRevealSQL: 5}[q]
	if count == 0 {
		return false, false
	}
	o, w, e := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()
	if len(args) != count || g.Collection || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated || args[0] != o || args[1] != w || args[2] != e || args[3] != g.Identity.PrincipalID.String() || !authorizationNativeTargetAllowed(g, "organization_identity", o) {
		return true, false
	}
	if q == currentIdentityProviderRevealSQL {
		grant, ok := args[4].(string)
		return true, ok && validProductID(grant) && g.OperationID == "createSCIMConnection"
	}
	operation, operationOK := args[4].(string)
	key, keyOK := args[5].(string)
	mutation, mutationOK := args[6].(string)
	if !operationOK || !keyOK || !mutationOK || operation != g.OperationID || !stringIn(operation, "createSSOConnection", "deleteSSOConnection", "testSSOConnection", "createSCIMConnection", "deleteSCIMConnection") || !validAdministrationIdempotencyKey(key) || !validProductID(mutation) {
		return true, false
	}
	if q != currentIdentityProviderReserveSQL {
		owner, ok := args[7].([]byte)
		return true, ok && len(owner) == 32
	}
	intent, intentOK := args[8].(json.RawMessage)
	owner, ownerOK := args[12].([]byte)
	if !intentOK || !ownerOK || len(owner) != 32 || len(intent) > 4096 {
		return true, false
	}
	if stringIn(operation, "createSSOConnection", "createSCIMConnection") {
		return true, g.PathParameters["id"] == ""
	}
	var named struct {
		Reference string `json:"reference"`
	}
	return true, json.Unmarshal(intent, &named) == nil && named.Reference != "" && named.Reference == g.PathParameters["id"]
}
