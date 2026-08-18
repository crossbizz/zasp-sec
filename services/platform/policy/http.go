package policy

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Authorizer func(*http.Request) bool

type HTTPHandler struct {
	store        *MemoryStore
	capabilities Capabilities
	authorize    Authorizer
}

func NewHTTPHandler(store *MemoryStore, capabilities Capabilities, authorize Authorizer) (*HTTPHandler, error) {
	if store == nil || authorize == nil || len(capabilities.Triggers) == 0 || len(capabilities.Fields) == 0 {
		return nil, ErrRejected
	}
	return &HTTPHandler{store: store, capabilities: capabilities, authorize: authorize}, nil
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
		id := strings.TrimPrefix(request.URL.Path, "/api/v1/policies/")
		value, err := handler.store.Get(request.Context(), id)
		return http.StatusOK, value, err
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
