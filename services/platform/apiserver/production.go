package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type CallbackProvider interface {
	Complete(context.Context, string, string) (SessionGrant, error)
	Ready(context.Context) error
}
type CallbackProviderFunc func(context.Context, string, string) (SessionGrant, error)

func (function CallbackProviderFunc) Complete(ctx context.Context, code, state string) (SessionGrant, error) {
	return function(ctx, code, state)
}

func (function CallbackProviderFunc) Ready(context.Context) error { return nil }

type SessionGrant struct {
	PrincipalID domain.ProductID
	Scope       domain.Scope
	Permissions []string
	ExpiresAt   time.Time
	ReturnTo    string
}

type CookiePolicy struct {
	Secure             bool
	WorkflowSigningKey []byte
	Clock              func() time.Time
}

type sessionRepository interface {
	Authenticate(context.Context, Credential) (RequestIdentity, error)
	Bootstrap(context.Context, RequestIdentity) (json.RawMessage, error)
	CreateSession(context.Context, SessionGrant) (string, error)
	Revoke(context.Context, RequestIdentity, string) error
	ListScopes(context.Context, RequestIdentity) (json.RawMessage, error)
	SwitchScope(context.Context, RequestIdentity, string, domain.Scope) (RequestIdentity, error)
}

type coreRepository interface {
	Read(context.Context, domain.Scope, string) (json.RawMessage, error)
}

func NewProductionHandlers(repository *PostgresRepository, provider CallbackProvider, cookie CookiePolicy) (Dependencies, Authenticator, error) {
	if repository == nil || nilInterface(repository.database) || nilInterface(provider) {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	workflow, err := newWorkflowHTTPHandler(repository, cookie.WorkflowSigningKey, cookie.Clock)
	if err != nil {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	session := &sessionHTTPHandler{repository: repository, provider: provider, cookie: cookie}
	return Dependencies{
		Session:   session,
		Identity:  &identityHTTPHandler{repository: repository},
		Inventory: &coreHTTPHandler{repository: repository, boundary: inventoryDependency},
		Risk:      &coreHTTPHandler{repository: repository, boundary: riskDependency},
		Workflow:  workflow,
	}, repository.Authenticate, nil
}

type sessionHTTPHandler struct {
	repository sessionRepository
	provider   CallbackProvider
	cookie     CookiePolicy
}

func (handler *sessionHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/api/v1/session/start":
		starter, ok := handler.provider.(IdentityStarter)
		returnTo := request.URL.Query().Get("return_to")
		if !ok || !validReturnPath(returnTo) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		target, err := starter.Start(request.Context(), returnTo)
		if err != nil {
			writeProductionError(writer, request, err)
			return
		}
		http.Redirect(writer, request, target, http.StatusFound)
	case "/api/v1/session/bootstrap":
		identity, ok := IdentityFromRequest(request)
		if !ok || identity.CredentialKind != CredentialBrowserSession || !validRequestIdentity(identity, true) {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		payload, err := handler.repository.Bootstrap(request.Context(), identity)
		if err == nil {
			payload, err = authorizedBootstrap(payload, identity)
		}
		writeProductionResponse(writer, request, http.StatusOK, payload, err)
	case "/api/v1/session/callback":
		var input struct {
			ProviderToken string `json:"provider_token"`
			State         string `json:"state"`
		}
		if decodeProductionJSON(request, &input) != nil || input.ProviderToken == "" || len(input.ProviderToken) > 4096 || len(input.State) < 32 || len(input.State) > 512 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		grant, err := handler.provider.Complete(request.Context(), input.ProviderToken, input.State)
		if err != nil {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		if !validReturnPath(grant.ReturnTo) {
			grant.ReturnTo = "/"
		}
		token, err := handler.repository.CreateSession(request.Context(), grant)
		if err != nil || token == "" {
			writeProductionError(writer, request, err)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: browserSessionCookie, Value: token, Path: "/", Secure: handler.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		payload, marshalErr := json.Marshal(map[string]string{"return_to": grant.ReturnTo})
		if marshalErr != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(writer, request, http.StatusOK, payload, nil)
	case "/api/v1/session/sign-out":
		identity, ok := IdentityFromRequest(request)
		cookie, cookieErr := request.Cookie(browserSessionCookie)
		if !ok || cookieErr != nil || handler.repository.Revoke(request.Context(), identity, cookie.Value) != nil {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: browserSessionCookie, Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), Secure: handler.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		writer.WriteHeader(http.StatusNoContent)
	case "/api/v1/session/scopes":
		identity, ok := IdentityFromRequest(request)
		if !ok {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		payload, err := handler.repository.ListScopes(request.Context(), identity)
		writeProductionResponse(writer, request, http.StatusOK, payload, err)
	case "/api/v1/session/scope":
		identity, ok := IdentityFromRequest(request)
		cookie, cookieErr := request.Cookie(browserSessionCookie)
		var input struct {
			WorkspaceID   string `json:"workspace_id"`
			EnvironmentID string `json:"environment_id"`
		}
		if !ok || cookieErr != nil || decodeProductionJSON(request, &input) != nil {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		workspace, workspaceErr := domain.ParseProductID(input.WorkspaceID)
		environment, environmentErr := domain.ParseProductID(input.EnvironmentID)
		scope, scopeErr := domain.NewScope(identity.Scope.OrganizationID(), workspace, environment)
		if workspaceErr != nil || environmentErr != nil || scopeErr != nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		if _, err := handler.repository.SwitchScope(request.Context(), identity, cookie.Value, scope); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func authorizedBootstrap(payload json.RawMessage, identity RequestIdentity) (json.RawMessage, error) {
	var value map[string]json.RawMessage
	if json.Unmarshal(payload, &value) != nil {
		return nil, ErrRepositoryUnavailable
	}
	capabilities := capabilitiesForPermissions(identity.Permissions)
	replacements := map[string]any{
		"organization_id": identity.Scope.OrganizationID().String(),
		"workspace_id":    identity.Scope.WorkspaceID().String(),
		"environment_id":  identity.Scope.EnvironmentID().String(),
		"permissions":     identity.Permissions,
		"capabilities":    capabilities,
		"csrf_token":      identity.CSRFToken,
	}
	for name, replacement := range replacements {
		encoded, err := json.Marshal(replacement)
		if err != nil {
			return nil, ErrRepositoryUnavailable
		}
		value[name] = encoded
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return result, nil
}

func capabilitiesForPermissions(permissions []string) []string {
	capabilities := []string{}
	for _, permission := range permissions {
		switch permission {
		case "view":
			capabilities = append(capabilities, "inventory.read", "scope.switch", "policies.read", "integrations.read", "sensors.read", "security-agents.read")
		case "manage_workflows":
			capabilities = append(capabilities, "policies.write", "integrations.write", "sensors.write", "security-agents.write", "security-agents.run", "security-agents.approve")
		}
	}
	return capabilities
}

type identityHTTPHandler struct{ repository sessionRepository }

func (handler *identityHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	payload, err := handler.repository.Bootstrap(request.Context(), identity)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	var bootstrap struct {
		Principal json.RawMessage `json:"principal"`
	}
	if json.Unmarshal(payload, &bootstrap) != nil || !json.Valid(bootstrap.Principal) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	writeProductionResponse(writer, request, http.StatusOK, bootstrap.Principal, nil)
}

type coreHTTPHandler struct {
	repository coreRepository
	boundary   dependencyKind
}

func (handler *coreHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	operation, _, status, err := productionOperation(request, handler.boundary)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	payload, err := handler.repository.Read(request.Context(), identity.Scope, operation)
	writeProductionResponse(writer, request, status, payload, err)
}

func productionOperation(request *http.Request, boundary dependencyKind) (string, bool, int, error) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		return "", false, 0, ErrRepositoryNotFound
	}
	id := routed.PathParameters["id"]
	if boundary == inventoryDependency {
		switch routed.OperationID {
		case "listAgents":
			return "agents", false, http.StatusOK, nil
		case "getAgent":
			return "agent:" + id, false, http.StatusOK, nil
		case "getAgentCapabilities":
			return "agent_capabilities:" + id, false, http.StatusOK, nil
		case "getAgentRelationships":
			return "agent_relationships:" + id, false, http.StatusOK, nil
		case "listAgentSessions":
			return "agent_sessions:" + id, false, http.StatusOK, nil
		case "listTools":
			return "tools", false, http.StatusOK, nil
		case "getTool":
			return "tool:" + id, false, http.StatusOK, nil
		case "listIdentities":
			return "identities", false, http.StatusOK, nil
		case "getIdentity":
			return "identity:" + id, false, http.StatusOK, nil
		case "listRuntimes":
			return "runtimes", false, http.StatusOK, nil
		case "getRuntime":
			return "runtime:" + id, false, http.StatusOK, nil
		case "getAsset":
			return "asset:" + id, false, http.StatusOK, nil
		}
	}
	if boundary == riskDependency && routed.OperationID == "getHomeSummary" {
		return "home", false, http.StatusOK, nil
	}
	return "", false, 0, ErrRepositoryNotFound
}

func decodeProductionJSON(request *http.Request, target any) error {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		return ErrRepositoryOperation
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 16*1024+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrRepositoryOperation
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrRepositoryOperation
	}
	return nil
}

func writeProductionResponse(writer http.ResponseWriter, request *http.Request, status int, payload json.RawMessage, err error) {
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
	_, _ = writer.Write([]byte("\n"))
}

func writeProductionError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message, retryable := http.StatusServiceUnavailable, "provider_unavailable", "Provider unavailable", true
	if errors.Is(err, ErrRepositoryAuthentication) {
		status, code, message, retryable = http.StatusUnauthorized, "authentication_required", "Authentication required", false
	}
	if errors.Is(err, ErrRepositoryNotFound) {
		status, code, message, retryable = http.StatusNotFound, "not_found", "Resource not found", false
	}
	if errors.Is(err, ErrRepositoryOperation) {
		status, code, message, retryable = http.StatusBadRequest, "invalid_request", "Request rejected", false
	}
	if errors.Is(err, ErrRepositoryConflict) {
		status, code, message, retryable = http.StatusConflict, "operation_conflict", "Operation conflicted", false
	}
	correlation := fallbackCorrelationID
	if request != nil {
		correlation = correlationIDFromContext(request.Context())
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": message, "correlation_id": correlation, "retryable": retryable})
}
