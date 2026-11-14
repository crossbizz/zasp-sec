package apiserver

import "encoding/json"

// Authorized statements of the product routes that migrations/baseline/
// completion.sql sections Z2 to Z7 moved off the chain's direct functions:
// receipt acknowledgement, policies, inventory detail, integration deletion
// and delivery status, the Workspace and Environment of a path, and finding
// status changes. Each is one zasp_authorization80 function that works only
// inside the fenced transaction of a checked request.
const (
	currentReceiptAcknowledgeSQL = `SELECT zasp_authorization80.receipt_acknowledge($1,$2,$3,$4,$5)`

	currentPolicyValueSQL     = `SELECT zasp_authorization80.policy_value($1,$2,$3,$4)`
	currentWorkflowReplaySQL  = `SELECT zasp_authorization80.workflow_replay($1,$2,$3,$4,$5,$6,$7::jsonb)`
	currentPolicyMutateSQL    = `SELECT zasp_authorization80.policy_mutate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15)`
	currentPolicyDecisionsSQL = `SELECT zasp_authorization80.policy_decisions($1,$2,$3,$4,$5)`

	currentInventoryDetailSQL      = `SELECT zasp_authorization80.inventory_detail($1,$2,$3,$4,$5)`
	currentInventoryAgentPageSQL   = `SELECT zasp_authorization80.inventory_agent_page($1,$2,$3,$4,$5,NULLIF($6,''),$7)`
	currentInventoryUpdateAgentSQL = `SELECT zasp_authorization80.inventory_update_agent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)`

	currentIntegrationDeleteSQL          = `SELECT zasp_authorization80.integration_delete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15)`
	currentIntegrationWebhookStatusSQL   = `SELECT zasp_authorization80.integration_webhook_status($1,$2,$3,$4)`
	currentIntegrationWebhookReserveSQL  = `SELECT zasp_authorization80.integration_webhook_test_reserve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	currentIntegrationWebhookCompleteSQL = `SELECT zasp_authorization80.integration_webhook_test_complete($1,$2,$3,$4,$5,$6,$7)`

	currentHierarchyValueSQL  = `SELECT zasp_authorization80.hierarchy_value($1,$2,$3,$4,$5)`
	currentHierarchyRenameSQL = `SELECT zasp_authorization80.hierarchy_rename($1,$2,$3,$4,$5,$6,$7,$8,$9)`

	currentFindingMutateSQL = `SELECT zasp_authorization80.finding_mutate($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),NULLIF($10,''),$11,$12,NULLIF($13,''))`
)

// productStatementRule is the closed contract of one statement above. The
// positions are one-based SQL argument positions; zero means absent.
type productStatementRule struct {
	operations  []string
	arguments   int
	scope       int    // Position of the Organization; Workspace and Environment follow it.
	actor       int    // Position of the principal.
	object      int    // Position of the object named by the request path.
	kind        string // The object's kind among the allowed targets; empty when PostgreSQL resolves the parent.
	parameter   string // Path parameter holding the object; "id" when empty.
	browserOnly bool
	fresh       bool // The session must be freshly authenticated.
	check       func(RequestAuthorization, []any) bool
}

// The writer's action and the checked object of each workflow operation the
// current replay and writers accept (completion.sql, workflow_operation).
var productWorkflowOperations = map[string]struct{ kind, action string }{
	"createPolicy":      {"policy", "create"},
	"updatePolicy":      {"policy", "update"},
	"rolloutPolicy":     {"policy", "update"},
	"disablePolicy":     {"policy", "update"},
	"deletePolicy":      {"policy", "delete"},
	"deleteIntegration": {"integration", "delete"},
}

var productStatementRules = map[string]productStatementRule{
	currentReceiptAcknowledgeSQL: {operations: []string{"acknowledgeWorkflowMutationReceipt"}, arguments: 5, scope: 1, actor: 4, object: 5, browserOnly: true},
	currentPolicyValueSQL:        {operations: []string{"getPolicy", "listPolicyDecisions", "rolloutPolicy", "disablePolicy", "simulatePolicy"}, arguments: 4, scope: 1, object: 4, kind: "policy"},
	currentWorkflowReplaySQL:     {operations: []string{"createPolicy", "updatePolicy", "rolloutPolicy", "disablePolicy", "deletePolicy", "deleteIntegration"}, arguments: 7, scope: 1, actor: 4, check: productWorkflowReplayAllowed},
	currentPolicyMutateSQL:       {operations: []string{"createPolicy", "updatePolicy", "rolloutPolicy", "disablePolicy", "deletePolicy"}, arguments: 15, scope: 4, actor: 7, check: productWorkflowMutationAllowed},
	currentPolicyDecisionsSQL:    {operations: []string{"listPolicyDecisions"}, arguments: 5, scope: 1, object: 4, kind: "policy"},

	currentInventoryDetailSQL:      {operations: []string{"getAgent", "getTool", "getIdentity", "getRuntime", "getAsset"}, arguments: 5, scope: 1, object: 4, check: productInventoryDetailAllowed},
	currentInventoryAgentPageSQL:   {operations: []string{"getAgentCapabilities", "getAgentRelationships", "listAgentSessions"}, arguments: 7, scope: 1, object: 4, kind: "agent", check: productInventoryAgentPageAllowed},
	currentInventoryUpdateAgentSQL: {operations: []string{"updateAgent"}, arguments: 12, scope: 1, actor: 4, object: 5, kind: "agent"},

	currentIntegrationDeleteSQL:          {operations: []string{"deleteIntegration"}, arguments: 15, scope: 4, actor: 7, check: productWorkflowMutationAllowed},
	currentIntegrationWebhookStatusSQL:   {operations: []string{"getIntegrationWebhookStatus"}, arguments: 4, scope: 1, object: 4, kind: "integration"},
	currentIntegrationWebhookReserveSQL:  {operations: []string{"testIntegrationWebhook"}, arguments: 12, scope: 1, actor: 4, object: 5, kind: "integration"},
	currentIntegrationWebhookCompleteSQL: {operations: []string{"testIntegrationWebhook"}, arguments: 7, scope: 1, check: productIntegrationPathAllowed},

	currentHierarchyValueSQL:  {operations: []string{"getWorkspace", "getEnvironment"}, arguments: 5, scope: 1, browserOnly: true, check: productHierarchyValueAllowed},
	currentHierarchyRenameSQL: {operations: []string{"updateWorkspace", "updateEnvironment"}, arguments: 9, scope: 1, actor: 4, browserOnly: true, fresh: true, check: productHierarchyRenameAllowed},

	// Sign-in to a SaaS platform (saas_sign_in.go, completion.sql section
	// ws6_saas_sign_in). The first two belong to the authorize request of the
	// integration in the path; the last two to the provider's callback, which
	// names no object: PostgreSQL finds the sign-in by the state's digest
	// and binds it to the person and the browser session that started it.
	postgresSaaSSignInIntegrationSQL: {operations: []string{"authorizeIntegration"}, arguments: 5, scope: 1, actor: 4, object: 5, kind: "integration", browserOnly: true, fresh: true},
	postgresSaaSSignInStartSQL:       {operations: []string{"authorizeIntegration"}, arguments: 10, scope: 1, actor: 4, object: 5, kind: "integration", browserOnly: true, fresh: true},
	postgresSaaSSignInConsumeSQL:     {operations: []string{"completeIntegrationOAuthCallback"}, arguments: 6, scope: 1, actor: 4, browserOnly: true},
	postgresSaaSSignInFinishSQL:      {operations: []string{"completeIntegrationOAuthCallback"}, arguments: 7, scope: 1, actor: 4, browserOnly: true},

	currentFindingMutateSQL: {operations: []string{"updateFinding", "acceptFindingRisk"}, arguments: 13, scope: 3, actor: 6, object: 2, kind: "finding", check: productFindingMutationAllowed},
}

// productStatementAllowed admits the statements above. It reports handled for
// each of them, so none can reach the generic rule table. Every comparison is
// repeated by PostgreSQL against the attested proof.
func productStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	r, ok := productStatementRules[q]
	if !ok {
		return false, false
	}
	if len(args) != r.arguments || g.Collection || !stringIn(g.OperationID, r.operations...) {
		return true, false
	}
	if r.browserOnly && g.Identity.CredentialKind != CredentialBrowserSession {
		return true, false
	}
	if r.fresh && !g.Identity.FreshAuthenticated {
		return true, false
	}
	for n, expected := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()} {
		if value, isString := args[r.scope-1+n].(string); !isString || value != expected {
			return true, false
		}
	}
	if r.actor > 0 {
		if value, isString := args[r.actor-1].(string); !isString || value != g.Identity.PrincipalID.String() {
			return true, false
		}
	}
	if r.object > 0 {
		parameter := r.parameter
		if parameter == "" {
			parameter = "id"
		}
		value, isString := args[r.object-1].(string)
		if !isString || value == "" || value != g.PathParameters[parameter] {
			return true, false
		}
		if r.kind != "" && !authorizationNativeTargetAllowed(g, r.kind, value) {
			return true, false
		}
	}
	return true, r.check == nil || r.check(g, args)
}

// A replay names the request's own operation, and its intent names the
// object of the request path (nothing, for a creation).
func productWorkflowReplayAllowed(g RequestAuthorization, args []any) bool {
	operation, operationOK := args[4].(string)
	key, keyOK := args[5].(string)
	intent, intentOK := args[6].(json.RawMessage)
	if !operationOK || !keyOK || !intentOK || operation != g.OperationID || !workflowKeyPattern.MatchString(key) || len(key) < 16 || len(key) > 128 {
		return false
	}
	return productWorkflowIntentAllowed(g, intent, nil)
}

// A write carries the chain's fifteen arguments: action, kind, identifier,
// scope, actor, operation, key, expected version, intent, body, audit,
// correlation and receipt identifiers.
func productWorkflowMutationAllowed(g RequestAuthorization, args []any) bool {
	rule := productWorkflowOperations[g.OperationID]
	action, actionOK := args[0].(string)
	kind, kindOK := args[1].(string)
	id, idOK := args[2].(string)
	operation, operationOK := args[7].(string)
	key, keyOK := args[8].(string)
	version, versionOK := args[9].(int64)
	intent, intentOK := args[10].(json.RawMessage)
	_, bodyOK := args[11].(json.RawMessage)
	if !actionOK || !kindOK || !idOK || !operationOK || !keyOK || !versionOK || !intentOK || !bodyOK {
		return false
	}
	if operation != g.OperationID || rule.kind == "" || kind != rule.kind || action != rule.action || !workflowKeyPattern.MatchString(key) || len(key) < 16 || len(key) > 128 {
		return false
	}
	if action == "create" {
		if version != 0 || !validWorkflowID(kind, id) {
			return false
		}
	} else if version < 1 || id != g.PathParameters["id"] {
		return false
	}
	return productWorkflowIntentAllowed(g, intent, &version)
}

func productWorkflowIntentAllowed(g RequestAuthorization, raw json.RawMessage, version *int64) bool {
	rule := productWorkflowOperations[g.OperationID]
	var intent struct {
		ResourceID      *string `json:"resource_id"`
		ExpectedVersion *int64  `json:"expected_version"`
	}
	if rule.kind == "" || len(raw) > 65536 || json.Unmarshal(raw, &intent) != nil || intent.ResourceID == nil || intent.ExpectedVersion == nil {
		return false
	}
	if version != nil && *intent.ExpectedVersion != *version {
		return false
	}
	if rule.action == "create" {
		return *intent.ResourceID == "" && g.PathParameters["id"] == "" && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}
	return *intent.ResourceID != "" && *intent.ResourceID == g.PathParameters["id"] && authorizationNativeTargetAllowed(g, rule.kind, *intent.ResourceID)
}

// A statement without an object argument still belongs to the integration of
// the request path, which must be an allowed target.
func productIntegrationPathAllowed(g RequestAuthorization, _ []any) bool {
	id := g.PathParameters["id"]
	return id != "" && authorizationNativeTargetAllowed(g, "integration", id)
}

// The inventory kind is the one the operation reads, and the entity of the
// path is an allowed target of that kind.
func productInventoryDetailAllowed(g RequestAuthorization, args []any) bool {
	kind := map[string]string{"getAgent": "agent", "getTool": "tool", "getIdentity": "identity", "getRuntime": "runtime", "getAsset": "asset"}[g.OperationID]
	var actual string
	switch value := args[4].(type) {
	case InventoryKind:
		actual = string(value)
	case string:
		actual = value
	}
	id, _ := args[3].(string)
	return kind != "" && actual == kind && authorizationNativeTargetAllowed(g, kind, id)
}

func productInventoryAgentPageAllowed(g RequestAuthorization, args []any) bool {
	section, sectionOK := args[4].(string)
	_, afterOK := args[5].(string)
	limit, limitOK := args[6].(int)
	return sectionOK && afterOK && limitOK && limit >= 1 && limit <= 100 &&
		section == map[string]string{"getAgentCapabilities": "capabilities", "getAgentRelationships": "relationships", "listAgentSessions": "sessions"}[g.OperationID]
}

// The Workspace or the Environment of the request path, as an allowed target
// of that kind. A Workspace target carries the Workspace's identifier and is
// checked in the session's own scope.
func productHierarchyValueAllowed(g RequestAuthorization, args []any) bool {
	kind, kindOK := args[3].(string)
	id, idOK := args[4].(string)
	if !kindOK || !idOK || id == "" || id != g.PathParameters["id"] || kind != map[string]string{"getWorkspace": "workspace", "getEnvironment": "environment"}[g.OperationID] {
		return false
	}
	return authorizationNativeTargetAllowed(g, kind, id)
}

func productHierarchyRenameAllowed(g RequestAuthorization, args []any) bool {
	kind, kindOK := args[4].(string)
	id, idOK := args[5].(string)
	version, versionOK := args[7].(int64)
	audit, auditOK := args[8].(string)
	if !kindOK || !idOK || !versionOK || !auditOK || version < 1 || !validProductID(audit) || id == "" || id != g.PathParameters["id"] || kind != map[string]string{"updateWorkspace": "workspace", "updateEnvironment": "environment"}[g.OperationID] {
		return false
	}
	return authorizationNativeTargetAllowed(g, kind, id)
}

// A finding status change names the request's own operation.
func productFindingMutationAllowed(g RequestAuthorization, args []any) bool {
	operation, operationOK := args[0].(string)
	key, keyOK := args[6].(string)
	version, versionOK := args[7].(int64)
	return operationOK && keyOK && versionOK && operation == g.OperationID && version >= 1 && len(key) >= 16 && len(key) <= 128
}
