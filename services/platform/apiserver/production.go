package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type CallbackProvider interface {
	Complete(context.Context, string, string) (string, error)
}
type CallbackProviderFunc func(context.Context, string, string) (string, error)

func (function CallbackProviderFunc) Complete(ctx context.Context, code, state string) (string, error) {
	return function(ctx, code, state)
}

type CookiePolicy struct{ Secure bool }

type sessionRepository interface {
	Authenticate(context.Context, Credential) (RequestIdentity, error)
	Bootstrap(context.Context, RequestIdentity) (json.RawMessage, error)
	Revoke(context.Context, RequestIdentity, string) error
}

type coreRepository interface {
	Read(context.Context, domain.Scope, string) (json.RawMessage, error)
	Write(context.Context, domain.Scope, string, json.RawMessage) (json.RawMessage, error)
}

func NewProductionHandlers(repository *PostgresRepository, provider CallbackProvider, cookie CookiePolicy) (Dependencies, Authenticator, error) {
	if repository == nil || nilInterface(repository.database) || nilInterface(provider) {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	session := &sessionHTTPHandler{repository: repository, provider: provider, cookie: cookie}
	return Dependencies{
		Session:   session,
		Identity:  &identityHTTPHandler{repository: repository},
		Inventory: &coreHTTPHandler{repository: repository, boundary: inventoryDependency},
		Risk:      &coreHTTPHandler{repository: repository, boundary: riskDependency},
	}, repository.Authenticate, nil
}

type sessionHTTPHandler struct {
	repository sessionRepository
	provider   CallbackProvider
	cookie     CookiePolicy
}

func (handler *sessionHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/api/v1/session/bootstrap":
		identity, ok := IdentityFromRequest(request)
		if !ok {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		payload, err := handler.repository.Bootstrap(request.Context(), identity)
		writeProductionResponse(writer, request, http.StatusOK, payload, err)
	case "/api/v1/session/callback":
		var input struct {
			AuthorizationCode string `json:"authorization_code"`
			State             string `json:"state"`
		}
		if decodeProductionJSON(request, &input) != nil || input.AuthorizationCode == "" || len(input.AuthorizationCode) > 4096 || len(input.State) < 32 || len(input.State) > 512 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		token, err := handler.provider.Complete(request.Context(), input.AuthorizationCode, input.State)
		if err != nil || token == "" {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: browserSessionCookie, Value: token, Path: "/", Secure: handler.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		writer.WriteHeader(http.StatusNoContent)
	case "/api/v1/session/sign-out":
		identity, ok := IdentityFromRequest(request)
		cookie, cookieErr := request.Cookie(browserSessionCookie)
		if !ok || cookieErr != nil || handler.repository.Revoke(request.Context(), identity, cookie.Value) != nil {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: browserSessionCookie, Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), Secure: handler.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
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
	operation, mutation, status, err := productionOperation(request, handler.boundary)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	var payload json.RawMessage
	if mutation {
		input, readErr := io.ReadAll(io.LimitReader(request.Body, 16*1024+1))
		if readErr != nil || len(input) > 16*1024 || !json.Valid(input) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		payload, err = handler.repository.Write(request.Context(), identity.Scope, operation, input)
	} else {
		payload, err = handler.repository.Read(request.Context(), identity.Scope, operation)
	}
	writeProductionResponse(writer, request, status, payload, err)
}

func productionOperation(request *http.Request, boundary dependencyKind) (string, bool, int, error) {
	path := request.URL.Path
	if boundary == inventoryDependency {
		collections := map[string]string{"/api/v1/agents": "agents", "/api/v1/tools": "tools", "/api/v1/identities": "identities", "/api/v1/runtimes": "runtimes"}
		if value := collections[path]; value != "" {
			return value, false, http.StatusOK, nil
		}
		for prefix, name := range map[string]string{"/api/v1/agents/": "agent:", "/api/v1/tools/": "tool:", "/api/v1/identities/": "identity:", "/api/v1/runtimes/": "runtime:", "/api/v1/assets/": "asset:"} {
			if strings.HasPrefix(path, prefix) {
				tail := strings.TrimPrefix(path, prefix)
				if prefix == "/api/v1/agents/" && strings.Contains(tail, "/") {
					parts := strings.SplitN(tail, "/", 2)
					return "agent_" + parts[1] + ":" + parts[0], false, http.StatusOK, nil
				}
				if request.Method == http.MethodPatch && prefix == "/api/v1/agents/" {
					return name + tail, true, http.StatusOK, nil
				}
				return name + tail, false, http.StatusOK, nil
			}
		}
	}
	if boundary == riskDependency {
		switch path {
		case "/api/v1/home/summary":
			return "home", false, http.StatusOK, nil
		case "/api/v1/search":
			return "search:" + request.URL.RawQuery, false, http.StatusOK, nil
		case "/api/v1/findings":
			return "findings", false, http.StatusOK, nil
		case "/api/v1/attack-paths":
			return "attack_paths", false, http.StatusOK, nil
		}
		if strings.HasPrefix(path, "/api/v1/findings/") {
			tail := strings.TrimPrefix(path, "/api/v1/findings/")
			if strings.HasSuffix(tail, "/accept-risk") {
				return "finding_accept:" + strings.TrimSuffix(tail, "/accept-risk"), true, http.StatusOK, nil
			}
			if strings.HasSuffix(tail, "/ticket") {
				return "finding_ticket:" + strings.TrimSuffix(tail, "/ticket"), true, http.StatusCreated, nil
			}
			return "finding:" + tail, request.Method == http.MethodPatch, http.StatusOK, nil
		}
		if strings.HasPrefix(path, "/api/v1/attack-paths/") {
			tail := strings.TrimPrefix(path, "/api/v1/attack-paths/")
			if strings.HasSuffix(tail, "/break-options") {
				return "attack_path_break_options:" + strings.TrimSuffix(tail, "/break-options"), false, http.StatusOK, nil
			}
			return "attack_path:" + tail, false, http.StatusOK, nil
		}
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
	correlation := fallbackCorrelationID
	if request != nil {
		correlation = correlationIDFromContext(request.Context())
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": message, "correlation_id": correlation, "retryable": retryable})
}
