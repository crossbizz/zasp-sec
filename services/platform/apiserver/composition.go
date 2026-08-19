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
}

func CoreOperations() []OperationDefinition {
	result := make([]OperationDefinition, len(coreOperations))
	for index, operation := range coreOperations {
		result[index] = operation.OperationDefinition
	}
	return result
}

func NewComposition(dependencies Dependencies) (http.Handler, error) {
	handlers := []http.Handler{dependencies.Session, dependencies.Identity, dependencies.Inventory, dependencies.Risk}
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
		operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, OperationID: definition.OperationID, Permission: definition.Permission, Security: security, RequireCSRF: definition.OperationID == "signOutSession" || definition.OperationID == "switchSessionScope", Handler: handler})
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
	default:
		return nil
	}
}
