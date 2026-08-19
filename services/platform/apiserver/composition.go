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
)

type coreOperation struct {
	OperationDefinition
	dependency dependencyKind
}

var coreOperations = []coreOperation{
	{OperationDefinition{"GET", "/api/v1/session/start", "startSession", "", []string{}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/session/bootstrap", "bootstrapSession", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/callback", "completeSessionCallback", "", []string{}}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/sign-out", "signOutSession", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/session/scopes", "listSessionScopes", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"PUT", "/api/v1/session/scope", "switchSessionScope", "", []string{"BrowserSession"}}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/me", "getCurrentPrincipal", "", []string{"BrowserSession", "ProductAPIToken"}}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/home/summary", "getHomeSummary", "view", []string{"BrowserSession", "ProductAPIToken"}}, riskDependency},
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
	{OperationDefinition{"GET", "/api/v1/policies", "listPolicies", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies", "createPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies/{id}", "getPolicy", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/policies/{id}", "updatePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/policies/{id}", "deletePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/simulate", "simulatePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/rollout", "rolloutPolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/policies/{id}/disable", "disablePolicy", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/policies/{id}/decisions", "listPolicyDecisions", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integration-catalog", "listIntegrationCatalog", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations", "listIntegrations", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/integrations", "createIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/integrations/{id}", "getIntegration", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/integrations/{id}", "updateIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/integrations/{id}", "deleteIntegration", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agent-templates", "listSecurityAgentTemplates", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents", "listSecurityAgents", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"POST", "/api/v1/security-agents", "createSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"GET", "/api/v1/security-agents/{id}", "getSecurityAgent", "view", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"PATCH", "/api/v1/security-agents/{id}", "updateSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
	{OperationDefinition{"DELETE", "/api/v1/security-agents/{id}", "deleteSecurityAgent", "manage_workflows", []string{"BrowserSession", "ProductAPIToken"}}, workflowDependency},
}

func CoreOperations() []OperationDefinition {
	result := make([]OperationDefinition, len(coreOperations))
	for index, operation := range coreOperations {
		result[index] = operation.OperationDefinition
	}
	return result
}

func NewComposition(dependencies Dependencies) (http.Handler, error) {
	handlers := []http.Handler{dependencies.Session, dependencies.Identity, dependencies.Inventory, dependencies.Risk, dependencies.Workflow}
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
			case "ProductAPIToken":
				security = append(security, CredentialBearerToken)
			}
		}
		requireCSRF := definition.OperationID == "signOutSession" || definition.OperationID == "switchSessionScope" || isMutation(definition.Method) && len(security) > 0
		operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Permission: definition.Permission, Security: security, RequireCSRF: requireCSRF, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		return nil, errors.Join(ErrInvalidComposition, err)
	}
	return router, nil
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
	default:
		return nil
	}
}
