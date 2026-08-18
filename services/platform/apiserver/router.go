package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const fallbackCorrelationID = "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"

var (
	ErrInvalidOperation   = errors.New("invalid API operation")
	ErrDuplicateOperation = errors.New("duplicate API operation")
)

type Operation struct {
	Method  string
	Pattern string
	Handler http.Handler
}

type operationRouter struct {
	operations []registeredOperation
}

type registeredOperation struct {
	method   string
	pattern  string
	segments []routeSegment
	handler  http.Handler
}

type routeSegment struct {
	literal   string
	parameter bool
}

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
		registered = append(registered, registeredOperation{
			method: operation.Method, pattern: operation.Pattern, segments: segments, handler: operation.Handler,
		})
	}
	return &operationRouter{operations: registered}, nil
}

func (router *operationRouter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.URL == nil || request.URL.Path == "" ||
		request.URL.EscapedPath() != request.URL.Path || strings.HasSuffix(request.URL.Path, "/") {
		writeRouterError(writer, http.StatusNotFound, "not_found", "Product route not found")
		return
	}
	pathSegments := splitPath(request.URL.Path)
	pathMatched := false
	for _, operation := range router.operations {
		if !matchSegments(operation.segments, pathSegments) {
			continue
		}
		pathMatched = true
		if operation.method == request.Method {
			operation.handler.ServeHTTP(writer, request)
			return
		}
	}
	if pathMatched {
		writeRouterError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	writeRouterError(writer, http.StatusNotFound, "not_found", "Product route not found")
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
			segments[index] = routeSegment{parameter: true}
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

func matchSegments(pattern []routeSegment, path []string) bool {
	if len(pattern) != len(path) {
		return false
	}
	for index, segment := range pattern {
		if path[index] == "" || (!segment.parameter && segment.literal != path[index]) {
			return false
		}
	}
	return true
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

func writeRouterError(writer http.ResponseWriter, status int, code string, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code": code, "message": message, "correlation_id": fallbackCorrelationID, "retryable": false,
	})
}
