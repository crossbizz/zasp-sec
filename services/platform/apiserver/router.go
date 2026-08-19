package apiserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const fallbackCorrelationID = "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"

var (
	ErrInvalidOperation   = errors.New("invalid API operation")
	ErrDuplicateOperation = errors.New("duplicate API operation")
)

type Operation struct {
	Method      string
	Pattern     string
	OperationID string
	Permission  string
	Security    []CredentialKind
	RequireCSRF bool
	Handler     http.Handler
}

type operationRouter struct {
	operations []registeredOperation
}

type registeredOperation struct {
	method      string
	pattern     string
	operationID string
	permission  string
	security    []CredentialKind
	requireCSRF bool
	segments    []routeSegment
	handler     http.Handler
}

type routeSegment struct {
	literal   string
	parameter bool
	name      string
}

type RoutedOperation struct {
	OperationID    string
	PathParameters map[string]string
}

type routedOperationContextKey struct{}

func NewRouter(operations []Operation) (http.Handler, error) {
	if len(operations) == 0 {
		return nil, ErrInvalidOperation
	}
	registered := make([]registeredOperation, 0, len(operations))
	seen := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		segments, err := parsePattern(operation.Pattern)
		if err != nil || !validMethod(operation.Method) || operation.Handler == nil {
			return nil, ErrInvalidOperation
		}
		key := operation.Method + " " + operation.Pattern
		if _, exists := seen[key]; exists {
			return nil, ErrDuplicateOperation
		}
		seen[key] = struct{}{}
		for _, existing := range registered {
			if existing.method == operation.Method && overlappingRouteShape(existing.segments, segments) {
				return nil, ErrDuplicateOperation
			}
		}
		registered = append(registered, registeredOperation{
			method: operation.Method, pattern: operation.Pattern, operationID: operation.OperationID, permission: operation.Permission, security: append([]CredentialKind(nil), operation.Security...), requireCSRF: operation.RequireCSRF, segments: segments, handler: operation.Handler,
		})
	}
	return &operationRouter{operations: registered}, nil
}

func (router *operationRouter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.URL == nil || request.URL.Path == "" ||
		request.URL.EscapedPath() != request.URL.Path || strings.HasSuffix(request.URL.Path, "/") {
		writeRouterError(writer, request, http.StatusNotFound, "not_found", "Product route not found")
		return
	}
	pathSegments := splitPath(request.URL.Path)
	pathMatched := false
	for _, operation := range router.operations {
		parameters, matched := matchSegments(operation.segments, pathSegments)
		if !matched || !validRouteParameters(operation.operationID, parameters) {
			continue
		}
		pathMatched = true
		if operation.method == request.Method {
			if len(operation.security) > 0 && !requestHasCredentialKind(request, operation.security) {
				writeRouterError(writer, request, http.StatusUnauthorized, "authentication_required", "Authentication required")
				return
			}
			if operation.requireCSRF && !requestHasValidCSRF(request) {
				writeRouterError(writer, request, http.StatusForbidden, "request_forbidden", "Request forbidden")
				return
			}
			if operation.permission != "" && !requestHasPermission(request, operation.permission) {
				writeRouterError(writer, request, http.StatusForbidden, "request_forbidden", "Request forbidden")
				return
			}
			routed := RoutedOperation{OperationID: operation.operationID, PathParameters: parameters}
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, routed))
			operation.handler.ServeHTTP(writer, request)
			return
		}
	}
	if pathMatched {
		writeRouterError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	writeRouterError(writer, request, http.StatusNotFound, "not_found", "Product route not found")
}

func requestHasCredentialKind(request *http.Request, allowed []CredentialKind) bool {
	identity, ok := IdentityFromRequest(request)
	if !ok {
		return false
	}
	for _, kind := range allowed {
		if identity.CredentialKind == kind {
			return true
		}
	}
	return false
}

func requestHasValidCSRF(request *http.Request) bool {
	identity, ok := IdentityFromRequest(request)
	if ok && identity.CredentialKind == CredentialBearerToken {
		return true
	}
	security, securityOK := request.Context().Value(browserSecurityContextKey{}).(browserSecurityContext)
	if !ok || !securityOK || identity.CredentialKind != CredentialBrowserSession {
		return false
	}
	csrf := request.Header.Get("X-CSRF-Token")
	return request.Header.Get("Origin") == security.publicOrigin && len(csrf) == len(identity.CSRFToken) && subtle.ConstantTimeCompare([]byte(csrf), []byte(identity.CSRFToken)) == 1
}

func parsePattern(pattern string) ([]routeSegment, error) {
	if pattern == "" || !strings.HasPrefix(pattern, "/") || pattern == "/" || strings.HasSuffix(pattern, "/") || strings.Contains(pattern, "//") {
		return nil, ErrInvalidOperation
	}
	parts := splitPath(pattern)
	segments := make([]routeSegment, len(parts))
	parameters := make(map[string]struct{})
	for index, part := range parts {
		if strings.HasPrefix(part, "{") || strings.HasSuffix(part, "}") {
			if len(part) < 3 || part[0] != '{' || part[len(part)-1] != '}' {
				return nil, ErrInvalidOperation
			}
			name := part[1 : len(part)-1]
			if !validParameterName(name) {
				return nil, ErrInvalidOperation
			}
			if _, exists := parameters[name]; exists {
				return nil, ErrInvalidOperation
			}
			parameters[name] = struct{}{}
			segments[index] = routeSegment{parameter: true, name: name}
			continue
		}
		if strings.ContainsAny(part, "{}") {
			return nil, ErrInvalidOperation
		}
		segments[index] = routeSegment{literal: part}
	}
	return segments, nil
}

func splitPath(path string) []string {
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

func matchSegments(pattern []routeSegment, path []string) (map[string]string, bool) {
	if len(pattern) != len(path) {
		return nil, false
	}
	parameters := make(map[string]string)
	for index, segment := range pattern {
		if path[index] == "" || (!segment.parameter && segment.literal != path[index]) {
			return nil, false
		}
		if segment.parameter {
			parameters[segment.name] = path[index]
		}
	}
	return parameters, true
}

func validRouteParameters(operationID string, parameters map[string]string) bool {
	for name, value := range parameters {
		if name == "id" && strings.Contains(operationID, "Policy") {
			if !policyIDPattern.MatchString(value) {
				return false
			}
			continue
		}
		if name == "id" || name == "syncId" {
			if _, err := domain.ParseProductID(value); err != nil {
				return false
			}
		}
	}
	return true
}

func overlappingRouteShape(left, right []routeSegment) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !left[index].parameter && !right[index].parameter && left[index].literal != right[index].literal {
			return false
		}
	}
	return true
}

func requestHasPermission(request *http.Request, permission string) bool {
	identity, ok := IdentityFromRequest(request)
	if !ok {
		return false
	}
	for _, granted := range identity.Permissions {
		if granted == permission {
			return true
		}
	}
	return false
}

func RoutedOperationFromRequest(request *http.Request) (RoutedOperation, bool) {
	if request == nil {
		return RoutedOperation{}, false
	}
	routed, ok := request.Context().Value(routedOperationContextKey{}).(RoutedOperation)
	if !ok || routed.PathParameters == nil {
		return RoutedOperation{}, false
	}
	copyParameters := make(map[string]string, len(routed.PathParameters))
	for name, value := range routed.PathParameters {
		copyParameters[name] = value
	}
	routed.PathParameters = copyParameters
	return routed, true
}

func validMethod(method string) bool {
	if method == "" {
		return false
	}
	for _, character := range method {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func validParameterName(name string) bool {
	for index, character := range name {
		if (character >= 'a' && character <= 'z') || (index > 0 && character >= '0' && character <= '9') || (index > 0 && character == '_') {
			continue
		}
		return false
	}
	return name != ""
}

func writeRouterError(writer http.ResponseWriter, request *http.Request, status int, code string, message string) {
	correlationID := fallbackCorrelationID
	if request != nil {
		correlationID = correlationIDFromContext(request.Context())
	}
	writeProductError(writer, status, code, message, correlationID)
}
