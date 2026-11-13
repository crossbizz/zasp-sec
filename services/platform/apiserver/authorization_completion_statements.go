package apiserver

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
