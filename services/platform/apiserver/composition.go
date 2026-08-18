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
	Method  string
	Pattern string
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
	{OperationDefinition{"GET", "/api/v1/session/bootstrap"}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/callback"}, sessionDependency},
	{OperationDefinition{"POST", "/api/v1/session/sign-out"}, sessionDependency},
	{OperationDefinition{"GET", "/api/v1/me"}, identityDependency},
	{OperationDefinition{"GET", "/api/v1/home/summary"}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/search"}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/agents"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}"}, inventoryDependency},
	{OperationDefinition{"PATCH", "/api/v1/agents/{id}"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/capabilities"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/relationships"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/agents/{id}/sessions"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/tools"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/tools/{id}"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/identities"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/identities/{id}"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/runtimes"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/runtimes/{id}"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/assets/{id}"}, inventoryDependency},
	{OperationDefinition{"GET", "/api/v1/findings"}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/findings/{id}"}, riskDependency},
	{OperationDefinition{"PATCH", "/api/v1/findings/{id}"}, riskDependency},
	{OperationDefinition{"POST", "/api/v1/findings/{id}/accept-risk"}, riskDependency},
	{OperationDefinition{"POST", "/api/v1/findings/{id}/ticket"}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths"}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths/{id}"}, riskDependency},
	{OperationDefinition{"GET", "/api/v1/attack-paths/{id}/break-options"}, riskDependency},
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
		operations = append(operations, Operation{Method: definition.Method, Pattern: definition.Pattern, Handler: handler})
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
