package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const (
	gatewayHTTPProxyPath = "/v1/proxy/http"
	gatewayMCPProxyPath  = "/v1/proxy/mcp"
)

type gatewayProxyConfig struct {
	Runtime      *gatewayRuntime
	Client       *http.Client
	Upstream     *url.URL
	ClientToken  []byte
	MaximumBytes int64
	Ready        func(context.Context) error
}

type gatewayProxyHandler struct {
	runtime      *gatewayRuntime
	client       *http.Client
	upstream     *url.URL
	clientToken  []byte
	maximumBytes int64
	ready        func(context.Context) error
	closeOnce    sync.Once
}

func newGatewayProxyHandler(config gatewayProxyConfig) (*gatewayProxyHandler, error) {
	if config.Runtime == nil || config.Client == nil || config.Upstream == nil ||
		config.Upstream.Scheme != "https" || config.Upstream.Hostname() == "" || config.Upstream.User != nil ||
		config.Upstream.RawQuery != "" || config.Upstream.Fragment != "" || config.Upstream.String() == "" ||
		len(config.ClientToken) < 32 || len(config.ClientToken) > 4096 || config.MaximumBytes < 1024 || config.MaximumBytes > 64*1024 {
		return nil, errGatewayRuntime
	}
	token := bytes.Clone(config.ClientToken)
	upstream := *config.Upstream
	return &gatewayProxyHandler{runtime: config.Runtime, client: config.Client, upstream: &upstream, clientToken: token, maximumBytes: config.MaximumBytes, ready: config.Ready}, nil
}

func (handler *gatewayProxyHandler) Ready(ctx context.Context) error {
	if handler == nil || ctx == nil || ctx.Err() != nil || handler.runtime == nil || handler.client == nil || handler.upstream == nil {
		return errGatewayRuntime
	}
	if handler.ready != nil && handler.ready(ctx) != nil {
		return errGatewayRuntime
	}
	return nil
}

func (handler *gatewayProxyHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.closeOnce.Do(func() {
		clear(handler.clientToken)
		handler.clientToken = nil
		handler.client = nil
		handler.runtime = nil
		handler.upstream = nil
		handler.ready = nil
	})
	return nil
}

func (handler *gatewayProxyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.runtime == nil || handler.client == nil || handler.upstream == nil || request == nil || request.URL == nil {
		gatewayJSONError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if request.URL.Path != gatewayHTTPProxyPath && request.URL.Path != gatewayMCPProxyPath {
		gatewayJSONError(response, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		gatewayJSONError(response, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.URL.RawQuery != "" {
		gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !handler.authorized(request.Header.Get("X-Zasp-Gateway-Token")) {
		gatewayJSONError(response, http.StatusUnauthorized, "unauthorized")
		return
	}
	if request.URL.Path == gatewayMCPProxyPath && request.Header.Get("Content-Type") != "application/json" {
		gatewayJSONError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	forwardHeaders, headersOK := gatewayProxyRequestHeaders(request.Header)
	if !headersOK {
		gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	body, ok := gatewayProxyBody(response, request, handler.maximumBytes)
	if !ok {
		return
	}
	evaluation, ok := handler.evaluation(request, body)
	if !ok {
		gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := handler.runtime.Evaluate(request.Context(), evaluation)
	if err != nil {
		gatewayJSONError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	response.Header().Set("X-Zasp-Correlation-ID", evaluation.EventID)
	if result.Decision == "block" {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(response).Encode(struct {
			Code          string   `json:"code"`
			CorrelationID string   `json:"correlation_id"`
			PolicyIDs     []string `json:"policy_ids"`
		}{Code: "policy_blocked", CorrelationID: evaluation.EventID, PolicyIDs: append([]string(nil), result.MatchedPolicyIDs...)})
		return
	}
	handler.forward(response, request, forwardHeaders, body, evaluation.EventID)
}

func (handler *gatewayProxyHandler) authorized(candidate string) bool {
	if len(candidate) != len(handler.clientToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), handler.clientToken) == 1
}

func gatewayProxyBody(response http.ResponseWriter, request *http.Request, maximum int64) ([]byte, bool) {
	request.Body = http.MaxBytesReader(response, request.Body, maximum)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			gatewayJSONError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		} else {
			gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		}
		return nil, false
	}
	if len(body) == 0 {
		gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

func (handler *gatewayProxyHandler) evaluation(request *http.Request, body []byte) (gatewayEvaluationRequest, bool) {
	eventID := request.Header.Get("X-Zasp-Event-ID")
	principalID := request.Header.Get("X-Zasp-Principal-ID")
	agentID := request.Header.Get("X-Zasp-Agent-ID")
	sessionID := request.Header.Get("X-Zasp-Session-ID")
	routeClass := request.Header.Get("X-Zasp-Route-Class")
	resourceClass := request.Header.Get("X-Zasp-Resource-Class")
	action := request.Header.Get("X-Zasp-Action")
	resource := request.Header.Get("X-Zasp-Resource")
	if !validGatewayProductID(eventID) || !validGatewayProductID(principalID) || !validGatewayProductID(agentID) || !validGatewayProductID(sessionID) ||
		!gatewayClassificationValuePattern.MatchString(routeClass) || !gatewayClassificationValuePattern.MatchString(resourceClass) || !boundedGatewayText(action, 64) || !boundedGatewayText(resource, 256) {
		return gatewayEvaluationRequest{}, false
	}
	actionKind := "http"
	contextValue := policy.ActionContext{
		PrincipalID: principalID, AgentID: agentID, SessionID: sessionID, Action: action, Resource: resource,
		EnvironmentID: handler.runtime.authority.EnvironmentID,
		Metadata:      map[string]string{"http.method": request.Method, "http.route_class": routeClass},
	}
	attributes := map[string]string{}
	if request.URL.Path == gatewayMCPProxyPath {
		actionKind = "mcp"
		parsed, err := policy.ParseMCPAction(body, principalID, agentID, sessionID, handler.runtime.authority.EnvironmentID)
		if err != nil || parsed.Resource != resource {
			return gatewayEvaluationRequest{}, false
		}
		parsed.Action = action
		contextValue = parsed
		attributes["tool.name"] = parsed.Metadata["tool.name"]
		attributes["mcp.method"] = parsed.Metadata["mcp.method"]
	} else {
		attributes["http.method"] = request.Method
		attributes["http.route_class"] = routeClass
	}
	normalized, err := policy.NormalizeActionContext(contextValue)
	if err != nil {
		return gatewayEvaluationRequest{}, false
	}
	attributes["action"] = normalized.Action
	attributes["resource"] = normalized.Resource
	attributes["principal_id"] = normalized.PrincipalID
	attributes["agent_id"] = normalized.AgentID
	attributes["session_id"] = normalized.SessionID
	attributes["environment_id"] = normalized.EnvironmentID
	classification := map[string]string{"category": "runtime", "route_class": routeClass, "resource_class": resourceClass, "outcome": "requested", "session_id": sessionID}
	capabilityValues := []struct{ header, key string }{
		{"X-Zasp-Capability-Agent-ID", "agent_id"},
		{"X-Zasp-Capability-Target-ID", "target_id"},
		{"X-Zasp-Capability-Category", "capability_category"},
		{"X-Zasp-Capability-Outcome", "capability_outcome"},
	}
	present := 0
	for _, value := range capabilityValues {
		candidate := request.Header.Get(value.header)
		if candidate != "" {
			classification[value.key] = candidate
			present++
		}
	}
	if present != 0 && present != len(capabilityValues) {
		return gatewayEvaluationRequest{}, false
	}
	evaluation := gatewayEvaluationRequest{EventID: eventID, ActionKind: actionKind, Attributes: attributes, Classification: classification}
	if !validGatewayEvaluationRequest(evaluation) {
		return gatewayEvaluationRequest{}, false
	}
	return evaluation, true
}

func (handler *gatewayProxyHandler) forward(response http.ResponseWriter, source *http.Request, headers http.Header, body []byte, correlationID string) {
	request, err := http.NewRequestWithContext(source.Context(), http.MethodPost, handler.upstream.String(), bytes.NewReader(body))
	if err != nil {
		gatewayJSONError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	request.Header = headers.Clone()
	upstream, err := handler.client.Do(request)
	if upstream != nil && upstream.StatusCode >= http.StatusMultipleChoices && upstream.StatusCode < http.StatusBadRequest {
		if upstream.Body != nil {
			_ = upstream.Body.Close()
		}
		gatewayJSONError(response, http.StatusBadGateway, "upstream_rejected")
		return
	}
	if err != nil || upstream == nil || upstream.Body == nil {
		if upstream != nil && upstream.Body != nil {
			_ = upstream.Body.Close()
		}
		gatewayJSONError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	defer upstream.Body.Close()
	upstreamBody, err := io.ReadAll(io.LimitReader(upstream.Body, handler.maximumBytes+1))
	if err != nil || int64(len(upstreamBody)) > handler.maximumBytes || upstream.StatusCode < http.StatusOK || upstream.StatusCode > 599 {
		gatewayJSONError(response, http.StatusBadGateway, "upstream_rejected")
		return
	}
	for name, values := range gatewayProxyResponseHeaders(upstream.Header) {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Zasp-Correlation-ID", correlationID)
	response.WriteHeader(upstream.StatusCode)
	_, _ = response.Write(upstreamBody)
}

func gatewayProxyRequestHeaders(source http.Header) (http.Header, bool) {
	allowed := map[string]int{
		"Accept":          4096,
		"Content-Type":    256,
		"Idempotency-Key": 256,
		"Traceparent":     256,
		"Tracestate":      1024,
		"X-Request-Id":    256,
	}
	result := make(http.Header)
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		if gatewayHopHeader(canonical) {
			return nil, false
		}
		maximum, approved := allowed[canonical]
		if strings.HasPrefix(canonical, "X-Zasp-") || !approved {
			continue
		}
		if len(values) < 1 || len(values) > 4 {
			return nil, false
		}
		for _, value := range values {
			if !boundedGatewayText(value, maximum) {
				return nil, false
			}
			result.Add(canonical, value)
		}
	}
	return result, true
}

func gatewayProxyResponseHeaders(source http.Header) http.Header {
	allowed := map[string]int{"Content-Type": 256, "Etag": 256, "Retry-After": 256, "X-Request-Id": 256}
	result := make(http.Header)
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		maximum, approved := allowed[canonical]
		if !approved || len(values) < 1 || len(values) > 4 {
			continue
		}
		for _, value := range values {
			if boundedGatewayText(value, maximum) {
				result.Add(canonical, value)
			}
		}
	}
	return result
}

func gatewayHopHeader(name string) bool {
	switch name {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}
