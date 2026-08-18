package policy

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Authorizer func(*http.Request) bool

type HTTPHandler struct {
	store        *MemoryStore
	decisions    *DecisionStore
	capabilities Capabilities
	authorize    Authorizer
}

func NewHTTPHandler(store *MemoryStore, capabilities Capabilities, authorize Authorizer) (*HTTPHandler, error) {
	if store == nil || authorize == nil || len(capabilities.Triggers) == 0 || len(capabilities.Fields) == 0 {
		return nil, ErrRejected
	}
	return &HTTPHandler{store: store, decisions: NewDecisionStore(), capabilities: capabilities, authorize: authorize}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || request == nil || request.URL == nil || !handler.authorize(request) || request.URL.RawQuery != "" || strings.HasSuffix(request.URL.Path, "/") || request.URL.EscapedPath() != request.URL.Path {
		writeError(writer, http.StatusForbidden)
		return
	}
	status, value, err := handler.dispatch(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if status == http.StatusNoContent {
		return
	}
	_ = json.NewEncoder(writer).Encode(value)
}

func (handler *HTTPHandler) dispatch(request *http.Request) (int, any, error) {
	if request.URL.Path == "/api/v1/policies" {
		switch request.Method {
		case http.MethodGet:
			values, err := handler.store.List(request.Context())
			return http.StatusOK, map[string]any{"items": values}, err
		case http.MethodPost:
			var value Policy
			if decode(request, &value) != nil {
				return 0, nil, ErrRejected
			}
			return http.StatusCreated, value, handler.store.Create(request.Context(), value, handler.capabilities)
		}
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/policies/") && request.Method == http.MethodGet {
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/api/v1/policies/"), "/")
		if len(parts) == 1 {
			value, err := handler.store.Get(request.Context(), parts[0])
			return http.StatusOK, value, err
		}
		if len(parts) == 2 && parts[1] == "decisions" {
			if _, err := handler.store.Get(request.Context(), parts[0]); err != nil {
				return 0, nil, ErrRejected
			}
			return http.StatusOK, map[string]any{"items": handler.decisions.List(parts[0])}, nil
		}
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/policies/") {
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/api/v1/policies/"), "/")
		if len(parts) == 1 && request.Method == http.MethodPatch {
			var value Policy
			if decode(request, &value) != nil || value.ID != parts[0] {
				return 0, nil, ErrRejected
			}
			return http.StatusOK, value, handler.store.Update(request.Context(), value, handler.capabilities)
		}
		if len(parts) == 1 && request.Method == http.MethodDelete {
			return http.StatusNoContent, nil, handler.store.Delete(request.Context(), parts[0])
		}
		if len(parts) == 2 && request.Method == http.MethodPost {
			switch parts[1] {
			case "simulate":
				var input struct {
					Events []ActionContext `json:"events"`
				}
				if decode(request, &input) != nil {
					return 0, nil, ErrRejected
				}
				value, err := handler.store.Simulate(request.Context(), parts[0], input.Events)
				return http.StatusOK, value, err
			case "rollout":
				var input struct {
					State    RolloutState `json:"state"`
					TargetID string       `json:"target_id"`
				}
				if decode(request, &input) != nil {
					return 0, nil, ErrRejected
				}
				value, err := handler.store.Rollout(request.Context(), parts[0], input.State, input.TargetID)
				return http.StatusOK, value, err
			case "disable":
				var input struct{}
				if decode(request, &input) != nil {
					return 0, nil, ErrRejected
				}
				value, err := handler.store.Disable(request.Context(), parts[0])
				return http.StatusOK, value, err
			}
		}
	}
	return 0, nil, ErrRejected
}

func decode(request *http.Request, target any) error {
	if request.Header.Get("Content-Type") != "application/json" || request.ContentLength < 0 || request.ContentLength > 16*1024 {
		return ErrRejected
	}
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrRejected
	}
	var extra any
	if decoder.Decode(&extra) == nil {
		return ErrRejected
	}
	return nil
}

func writeError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte("{\"code\":\"policy_rejected\",\"message\":\"Policy operation rejected\",\"retryable\":false}\n"))
}
