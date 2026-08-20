package apiserver

import (
	"errors"
	"net/http"
	"reflect"
)

var ErrInvalidComposition = errors.New("invalid API composition")

type Dependencies struct {
	Session   http.Handler
	Identity  http.Handler
	Inventory http.Handler
	Risk      http.Handler
	Workflow  http.Handler
	Connector http.Handler
}

type OperationDefinition struct {
	Method      string
	Pattern     string
	OperationID string
	Permission  string
	Security    []string
}

type dependencyKind uint8

const (
	sessionDependency dependencyKind = iota + 1
	identityDependency
	inventoryDependency
	riskDependency
	workflowDependency
	connectorDependency
)

type coreOperation struct {
	OperationDefinition
	dependency dependencyKind
}

var coreOperations = withBrowserExpectedScope([]coreOperation{
	{OperationDefinition{"GET", "/api/v1/session/start", "startSession", "", []string{}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/session/bootstrap", "bootstrapSession", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/callback", "completeSessionCallback", "", []string{}}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/sign-out", "signOutSession", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/session/scopes", "listSessionScopes", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"PUT", "/api/v1/session/scope", "switchSessionScope", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/me", "getCurrentPrincipal", "", []string{"BrowserSession", "ProductAPIToken"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/organization", "getOrganization", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/workspaces", "listWorkspaces", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/workspaces", "createWorkspace", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/workspaces/{id}", "getWorkspace", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/workspaces/{id}", "updateWorkspace", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/environments", "listEnvironments", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/environments", "createEnvironment", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/environments/{id}", "getEnvironment", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/environments/{id}", "updateEnvironment", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/members", "listMembers", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/roles", "listBuiltInRoles", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/admin/members/{id}", "updateMemberRole", "manage_identity", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/api-tokens", "listAPITokens", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/api-tokens", "createAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/api-tokens/{id}/rotate", "rotateAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/api-tokens/{id}", "revokeAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/admin/api-token-reveal-grants", "listAPITokenRevealGrants", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"POST", "/api/v1/admin/api-token-reveal-grants/{id}/reveal", "revealAPIToken", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/admin/api-token-reveal-grants/{id}", "acknowledgeAPITokenRevealGrant", "manage_api_tokens", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/audit-events", "listAuditEvents", "view_audit", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions", "listSessions", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions/{id}", "getSession", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/sessions/{id}/events", "listSessionEvents", "investigate_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"DELETE", "/api/v1/sessions/{id}", "revokeSession", "revoke_sessions", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/compliance/controls", "listComplianceControls", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/compliance/evidence", "listComplianceEvidence", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/settings/data-controls", "getDataControls", "view_compliance", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"PATCH", "/api/v1/settings/data-controls", "updateDataControls", "manage_data_controls", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/settings/external-data-flows", "getExternalDataFlows", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/system/status", "getSystemStatus", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/system/components", "listSystemComponents", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/system/version", "getSystemVersion", "view", []string{"BrowserSession"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/home/summary", "getHomeSummary", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/findings", "listFindings", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/findings/{id}", "getFinding", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"PATCH", "/api/v1/findings/{id}", "updateFinding", "manage_findings", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"POST", "/api/v1/findings/{id}/accept-risk", "acceptFindingRisk", "manage_findings", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths", "listAttackPaths", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths/{id}", "getAttackPath", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths/{id}/break-options", "getAttackPathBreakOptions", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/agents", "listAgents", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}", "getAgent", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/capabilities", "getAgentCapabilities", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/relationships", "getAgentRelationships", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/sessions", "listAgentSessions", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/tools", "listTools", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/tools/{id}", "getTool", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/identities", "listIdentities", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/identities/{id}", "getIdentity", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/runtimes", "listRuntimes", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/runtimes/{id}", "getRuntime", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/assets/{id}", "getAsset", "view", []string{"BrowserSession", "ProductAPIToken"}}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/workflow-mutation-receipts", "listWorkflowMutationReceipts", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/workflow-mutation-receipts/{id}/acknowledge", "acknowledgeWorkflowMutationReceipt", "view", []string{"BrowserSession"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies", "listPolicies", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies", "createPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies/{id}", "getPolicy", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/policies/{id}", "updatePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/policies/{id}", "deletePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/rollout", "rolloutPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/disable", "disablePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integration-catalog", "listIntegrationCatalog", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations", "listIntegrations", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations", "createIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}", "getIntegration", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/integrations/{id}", "updateIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/integrations/{id}", "deleteIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/sync", "syncIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/syncs", "listIntegrationSyncs", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/syncs/{syncId}", "getIntegrationSync", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/schedule", "getIntegrationSchedule", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PUT", "/api/v1/integrations/{id}/schedule", "putIntegrationSchedule", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/integrations/{id}/schedule", "deleteIntegrationSchedule", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}/freshness", "getIntegrationFreshness", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/authorize", "authorizeIntegration", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/reference-authorization", "authorizeIntegrationReference", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"POST", "/api/v1/integrations/{id}/authorization-remediation", "remediateIntegrationAuthorization", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/oauth/callback", "completeIntegrationOAuthCallback", "manage_workflows", []string{"BrowserSession"}}, connectorDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-templates", "listSecurityAgentTemplates", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents", "listSecurityAgents", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents", "createSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/{id}", "getSecurityAgent", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/security-agents/{id}", "updateSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/security-agents/{id}", "deleteSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
})

func withBrowserExpectedScope(operations []coreOperation) []coreOperation {
	for index := range operations {
		definition := &operations[index].OperationDefinition
		switch definition.OperationID {
		case "", "startSession", "bootstrapSession", "completeSessionCallback", "completeIntegrationOAuthCallback", "signOutSession":
			continue
		}
		for schemeIndex, scheme := range definition.Security {
			if scheme != "BrowserSession" {
				continue
			}
			definition.Security = append(definition.Security, "")
			copy(definition.Security[schemeIndex+1:], definition.Security[schemeIndex:])
			definition.Security[schemeIndex] = "BrowserExpectedScope"
			break
		}
	}
	return operations
}

func CoreOperations() []OperationDefinition {
	result := make([]OperationDefinition, len(coreOperations))
	for index, operation := range coreOperations {
		result[index] = operation.OperationDefinition
	}
	return result
}

func NewComposition(dependencies Dependencies) (http.Handler, error) {
	handlers := []http.Handler{dependencies.Session, dependencies.Identity, dependencies.Inventory, dependencies.Risk, dependencies.Workflow, dependencies.Connector}
	seenHandlers := make(map[uintptr]struct{}, len(handlers))
	for _, handler := range handlers {
		identity, valid := handlerIdentity(handler)
		if !valid {
			return nil, ErrInvalidComposition
		}
		if _, duplicate := seenHandlers[identity]; duplicate {
			return nil, ErrInvalidComposition
		}
		seenHandlers[identity] = struct{}{}
	}

	operations := make([]Operation, 0, len(coreOperations))
	for _, definition := range coreOperations {
		handler := dependencyHandler(dependencies, definition.dependency)
		security := make([]CredentialKind, 0, len(definition.Security))
		for _, scheme := range definition.Security {
			switch scheme {
			case "BrowserSession":
				security = append(security, CredentialBrowserSession)
			case "BrowserExpectedScope":
				// The exact header is a request precondition, not a credential.
			case "ProductAPIToken":
				security = append(security, CredentialBearerToken)
			}
		}
		requireCSRF := definition.OperationID == "signOutSession" || definition.OperationID == "switchSessionScope" || isMutation(definition.Method) && len(security) > 0
		operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Permission: definition.Permission, Security: security, RequireCSRF: requireCSRF, RequireFreshAuth: requiresFreshAuthentication(definition.OperationID), Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		return nil, errors.Join(ErrInvalidComposition, err)
	}
	return router, nil
}

func requiresFreshAuthentication(operationID string) bool {
	switch operationID {
	case "createWorkspace", "updateWorkspace", "createEnvironment", "updateEnvironment",
		"updateMemberRole", "createAPIToken", "rotateAPIToken", "revokeAPIToken", "revealAPIToken", "acknowledgeAPITokenRevealGrant",
		"revokeSession", "updateDataControls", "authorizeIntegration", "authorizeIntegrationReference", "remediateIntegrationAuthorization":
		return true
	default:
		return false
	}
}

func handlerIdentity(handler http.Handler) (uintptr, bool) {
	if handler == nil {
		return 0, false
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return 0, false
		}
		identity := value.Pointer()
		return identity, identity != 0
	default:
		return 0, false
	}
}

func dependencyHandler(dependencies Dependencies, kind dependencyKind) http.Handler {
	switch kind {
	case sessionDependency:
		return dependencies.Session
	case identityDependency:
		return dependencies.Identity
	case inventoryDependency:
		return dependencies.Inventory
	case riskDependency:
		return dependencies.Risk
	case workflowDependency:
		return dependencies.Workflow
	case connectorDependency:
		return dependencies.Connector
	default:
		return nil
	}
}
