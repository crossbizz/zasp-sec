package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Browser authorization of an OAuth connector (GitHub, Okta, a Nango
// connector such as Slack) under current authorization.
//
// The connector chain's functions (zasp_connector_start_oauth and the others
// in connector_repository.go) take no request authorization, and the API
// login holds no EXECUTE on them. Until completion.sql section
// ws10_connector_oauth every statement of authorizeIntegration,
// completeIntegrationOAuthCallback and remediateIntegrationAuthorization was
// therefore refused twice: by the statement allow-list of the API server and
// by PostgreSQL.
//
// The statements below are that section's functions. Each one works only
// inside the fenced transaction of a checked request, for the proof's own
// scope, principal and browser session, and only for the operations it
// belongs to:
//
//   - authorizeIntegration and remediateIntegrationAuthorization: a freshly
//     authenticated session, and the integration of the request path as an
//     allowed object;
//   - completeIntegrationOAuthCallback: the provider's redirect names no
//     object. The request is checked against its Environment, and every
//     statement is bound in PostgreSQL to an authorization attempt that this
//     person started from this browser session.
//
// Each takes the scope first and the principal fourth, then the arguments of
// the chain function it guards. The background reconciler has no request and
// keeps its lease-bound statements (connector_maintenance_authorization.go).
const (
	currentConnectorIntegrationSQL         = `SELECT zasp_authorization80.connector_integration($1,$2,$3,$4,$5)`
	currentConnectorStagePKCECleanupSQL    = `SELECT zasp_authorization80.connector_stage_pkce_cleanup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	currentConnectorActivatePKCECleanupSQL = `SELECT zasp_authorization80.connector_activate_pkce_cleanup($1,$2,$3,$4,$5)`
	currentConnectorStartOAuthSQL          = `SELECT zasp_authorization80.connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17)`
	currentConnectorConsumeOAuthSQL        = `SELECT zasp_authorization80.connector_consume_oauth($1,$2,$3,$4,$5,$6)`
	currentConnectorCompletePKCECleanupSQL = `SELECT zasp_authorization80.connector_complete_pkce_cleanup($1,$2,$3,$4,$5)`
	currentConnectorResolveEffectSQL       = `SELECT zasp_authorization80.connector_resolve_effect($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`
	currentConnectorCompleteOAuthSQL       = `SELECT zasp_authorization80.connector_complete_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`
	currentConnectorCompleteCleanupSQL     = `SELECT zasp_authorization80.connector_complete_cleanup($1,$2,$3,$4,$5)`
	currentConnectorQuarantineSQL          = `SELECT zasp_authorization80.connector_quarantine($1,$2,$3,$4,$5)`
	currentConnectorQuarantineReplaySQL    = `SELECT zasp_authorization80.connector_quarantine_replay($1,$2,$3,$4,$5,$6::jsonb)`
	currentConnectorRemediateQuarantineSQL = `SELECT zasp_authorization80.connector_remediate_quarantine($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`

	connectorAuthorizeOperation = "authorizeIntegration"
	connectorCallbackOperation  = "completeIntegrationOAuthCallback"
	connectorRemediateOperation = "remediateIntegrationAuthorization"
)

// connectorCheckedActor reports the principal of a checked connector request.
// It is false for a context without a request authorization (the reconciler,
// or a deployment before current authorization), which keeps the chain's
// statements.
func connectorCheckedActor(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	grant, checked := requestAuthorizationFromContext(ctx)
	if !checked || !stringIn(grant.OperationID, connectorAuthorizeOperation, connectorCallbackOperation, connectorRemediateOperation) {
		return "", false
	}
	return grant.Identity.PrincipalID.String(), true
}

// connectorCheckedStatement returns the authorized statement and its
// arguments for a checked connector request: the scope, the principal, then
// rest. Without one it returns the chain statement and its own arguments.
func connectorCheckedStatement(ctx context.Context, chain string, chainArguments []any, current string, scope [3]string, rest ...any) (string, []any) {
	actor, checked := connectorCheckedActor(ctx)
	if !checked {
		return chain, chainArguments
	}
	return current, append([]any{scope[0], scope[1], scope[2], actor}, rest...)
}

func connectorScopeArguments(scope domain.Scope) [3]string {
	return [3]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
}

// connectorScopedStatement is connectorCheckedStatement for a chain statement
// whose arguments are the scope followed by rest.
func connectorScopedStatement(ctx context.Context, scope domain.Scope, chain, current string, rest ...any) (string, []any) {
	values := connectorScopeArguments(scope)
	return connectorCheckedStatement(ctx, chain, append([]any{values[0], values[1], values[2]}, rest...), current, values, rest...)
}

// connectorRequestAllowed is what every statement above requires of its
// request. integration is the statement's integration argument, or nil when
// it has none.
func connectorRequestAllowed(g RequestAuthorization, integration any) bool {
	if g.OperationID == connectorCallbackOperation {
		// The callback's path names no object; PostgreSQL binds the statement
		// to the attempt of this person and session.
		return g.PathParameters["id"] == "" && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}
	id := g.PathParameters["id"]
	if !g.Identity.FreshAuthenticated || !validProductID(id) || !authorizationNativeTargetAllowed(g, "integration", id) {
		return false
	}
	if integration == nil {
		return true
	}
	value, isString := integration.(string)
	return isString && value == id
}

// connectorIntegrationStatementAllowed returns a check for a statement whose
// argument at the zero-based position is its integration.
func connectorIntegrationStatementAllowed(position int) func(RequestAuthorization, []any) bool {
	return func(g RequestAuthorization, args []any) bool {
		if g.OperationID == connectorCallbackOperation {
			// The callback reads the integration of the attempt it consumed.
			value, isString := args[position].(string)
			return isString && validProductID(value) && connectorRequestAllowed(g, nil)
		}
		return connectorRequestAllowed(g, args[position])
	}
}

func connectorObjectStatementAllowed(g RequestAuthorization, _ []any) bool {
	return connectorRequestAllowed(g, nil)
}

// connectorSessionStatementAllowed returns a check for a statement that
// carries the digest of the browser session at the zero-based position: it is
// the digest of the request's own credential.
func connectorSessionStatementAllowed(session, integration int) func(RequestAuthorization, []any) bool {
	return func(g RequestAuthorization, args []any) bool {
		if !authorizationDigestArgument(g, args[session]) {
			return false
		}
		if integration < 0 {
			return connectorRequestAllowed(g, nil)
		}
		return connectorRequestAllowed(g, args[integration])
	}
}

// A remediation replay names the integration of the request path in its intent.
func connectorQuarantineReplayAllowed(g RequestAuthorization, args []any) bool {
	key, keyOK := args[4].(string)
	raw, rawOK := args[5].(json.RawMessage)
	var intent struct {
		ResourceID string `json:"resource_id"`
	}
	if !keyOK || !rawOK || len(key) < 16 || len(key) > 128 || !workflowKeyPattern.MatchString(key) || len(raw) > 65536 || json.Unmarshal(raw, &intent) != nil {
		return false
	}
	return connectorRequestAllowed(g, intent.ResourceID)
}

// connectorStatementRules joins productStatementRules (authorization_product_
// statements.go). Every rule is browser-only and binds the scope at the first
// three positions and the principal at the fourth.
var connectorStatementRules = map[string]productStatementRule{
	currentConnectorIntegrationSQL:         {operations: []string{connectorAuthorizeOperation, connectorCallbackOperation, connectorRemediateOperation}, arguments: 5, scope: 1, actor: 4, browserOnly: true, check: connectorIntegrationStatementAllowed(4)},
	currentConnectorStagePKCECleanupSQL:    {operations: []string{connectorAuthorizeOperation}, arguments: 12, scope: 1, actor: 4, browserOnly: true, fresh: true, check: connectorIntegrationStatementAllowed(5)},
	currentConnectorActivatePKCECleanupSQL: {operations: []string{connectorAuthorizeOperation, connectorCallbackOperation}, arguments: 5, scope: 1, actor: 4, browserOnly: true, check: connectorObjectStatementAllowed},
	currentConnectorStartOAuthSQL:          {operations: []string{connectorAuthorizeOperation}, arguments: 17, scope: 1, actor: 4, browserOnly: true, fresh: true, check: connectorSessionStatementAllowed(7, 5)},
	currentConnectorConsumeOAuthSQL:        {operations: []string{connectorCallbackOperation}, arguments: 6, scope: 1, actor: 4, browserOnly: true, check: connectorSessionStatementAllowed(5, -1)},
	currentConnectorCompletePKCECleanupSQL: {operations: []string{connectorCallbackOperation}, arguments: 5, scope: 1, actor: 4, browserOnly: true, check: connectorObjectStatementAllowed},
	currentConnectorResolveEffectSQL:       {operations: []string{connectorCallbackOperation}, arguments: 9, scope: 1, actor: 4, browserOnly: true, check: connectorObjectStatementAllowed},
	currentConnectorCompleteOAuthSQL:       {operations: []string{connectorCallbackOperation}, arguments: 13, scope: 1, actor: 4, browserOnly: true, check: connectorObjectStatementAllowed},
	currentConnectorCompleteCleanupSQL:     {operations: []string{connectorCallbackOperation}, arguments: 5, scope: 1, actor: 4, browserOnly: true, check: connectorObjectStatementAllowed},
	currentConnectorQuarantineSQL:          {operations: []string{connectorRemediateOperation}, arguments: 5, scope: 1, actor: 4, browserOnly: true, fresh: true, check: connectorIntegrationStatementAllowed(4)},
	currentConnectorQuarantineReplaySQL:    {operations: []string{connectorRemediateOperation}, arguments: 6, scope: 1, actor: 4, browserOnly: true, fresh: true, check: connectorQuarantineReplayAllowed},
	currentConnectorRemediateQuarantineSQL: {operations: []string{connectorRemediateOperation}, arguments: 14, scope: 1, actor: 4, browserOnly: true, fresh: true, check: connectorIntegrationStatementAllowed(5)},
}

func init() {
	for statement, rule := range connectorStatementRules {
		productStatementRules[statement] = rule
	}
}
