package redteam

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Authorizer func(*http.Request) bool

type HTTPHandler struct {
	store     *MemoryStore
	authorize Authorizer
}

func NewHTTPHandler(store *MemoryStore, authorize Authorizer) (*HTTPHandler, error) {
	if store == nil || authorize == nil {
		return nil, ErrRejected
	}
	return &HTTPHandler{store: store, authorize: authorize}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.store == nil || request == nil || request.URL == nil || !handler.authorize(request) {
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
	_ = json.NewEncoder(writer).Encode(value)
}

func (handler *HTTPHandler) dispatch(request *http.Request) (int, any, error) {
	if request.URL.RawQuery != "" || strings.HasSuffix(request.URL.Path, "/") || request.URL.EscapedPath() != request.URL.Path {
		return 0, nil, ErrRejected
	}
	switch request.URL.Path {
	case "/api/v1/tests":
		switch request.Method {
		case http.MethodGet:
			values, err := handler.store.ListDefinitions(request.Context())
			return http.StatusOK, map[string]any{"items": values}, err
		case http.MethodPost:
			var value TestDefinition
			if decode(request, &value) != nil {
				return 0, nil, ErrRejected
			}
			return http.StatusCreated, value, handler.store.CreateDefinition(request.Context(), value)
		}
	case "/api/v1/test-runs":
		if request.Method == http.MethodGet {
			values, err := handler.store.ListRuns(request.Context())
			return http.StatusOK, map[string]any{"items": values}, err
		}
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/tests/") {
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/api/v1/tests/"), "/")
		if len(parts) == 1 {
			switch request.Method {
			case http.MethodGet:
				value, err := handler.store.GetDefinition(request.Context(), parts[0])
				return http.StatusOK, value, err
			case http.MethodPatch:
				var value TestDefinition
				if decode(request, &value) != nil || value.ID != parts[0] {
					return 0, nil, ErrRejected
				}
				return http.StatusOK, value, handler.store.UpdateDefinition(request.Context(), value)
			}
		}
		if len(parts) == 2 && parts[1] == "runs" && request.Method == http.MethodPost {
			var input struct {
				RunID string `json:"run_id"`
			}
			if decode(request, &input) != nil {
				return 0, nil, ErrRejected
			}
			value, err := handler.store.CreateRun(request.Context(), input.RunID, parts[0])
			return http.StatusCreated, value, err
		}
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/test-runs/") {
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/api/v1/test-runs/"), "/")
		if len(parts) == 1 && request.Method == http.MethodGet {
			value, err := handler.store.GetRun(request.Context(), parts[0])
			return http.StatusOK, value, err
		}
		if len(parts) == 2 && parts[1] == "cancel" && request.Method == http.MethodPost {
			var input struct{}
			if decode(request, &input) != nil {
				return 0, nil, ErrRejected
			}
			value, err := handler.store.CancelRun(request.Context(), parts[0])
			return http.StatusOK, value, err
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
	_, _ = writer.Write([]byte("{\"code\":\"red_team_rejected\",\"message\":\"Red team operation rejected\",\"retryable\":false}\n"))
}
