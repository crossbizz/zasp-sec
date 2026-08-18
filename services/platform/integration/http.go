package integration

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumRequestBytes = 16 * 1024
const fallbackCorrelationID = "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"

type Authorizer func(*http.Request) (domain.Scope, error)

type HTTPHandler struct {
	service   *Service
	authorize Authorizer
}

func NewHTTPHandler(service *Service, authorize Authorizer) (*HTTPHandler, error) {
	if service == nil || service.store == nil || service.catalog == nil || authorize == nil {
		return nil, ErrConfiguration
	}
	return &HTTPHandler{service: service, authorize: authorize}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.service == nil || request == nil || request.URL == nil {
		writeHTTPError(writer, ErrConfiguration)
		return
	}
	scope, err := authorizeRequest(handler.authorize, request)
	if err != nil || scope.Validate() != nil {
		writeHTTPError(writer, ErrForbidden)
		return
	}
	status, payload, err := handler.dispatch(request, scope)
	if err != nil {
		writeHTTPError(writer, err)
		return
	}
	if status == http.StatusNoContent {
		writer.WriteHeader(status)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func (handler *HTTPHandler) dispatch(request *http.Request, scope domain.Scope) (int, any, error) {
	path := request.URL.EscapedPath()
	if path != request.URL.Path || strings.HasSuffix(path, "/") {
		return 0, nil, ErrNotFound
	}
	switch {
	case path == "/api/v1/integration-catalog" && request.Method == http.MethodGet:
		if !exactQuery(request, "q", "category", "data_type", "action", "auth_mode") {
			return 0, nil, ErrInvalid
		}
		query := request.URL.Query()
		items, err := handler.service.Catalog(request.Context(), CatalogFilter{Query: query.Get("q"), Category: query.Get("category"), DataType: query.Get("data_type"), Action: query.Get("action"), AuthMode: query.Get("auth_mode")})
		return http.StatusOK, map[string]any{"items": items}, err
	case path == "/api/v1/integrations":
		return handler.integrationCollection(request, scope)
	case strings.HasPrefix(path, "/api/v1/integrations/"):
		return handler.integrationResource(request, scope, strings.TrimPrefix(path, "/api/v1/integrations/"))
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) integrationCollection(request *http.Request, scope domain.Scope) (int, any, error) {
	if !exactQuery(request) {
		return 0, nil, ErrInvalid
	}
	switch request.Method {
	case http.MethodGet:
		values, err := handler.service.List(request.Context(), scope)
		return http.StatusOK, map[string]any{"items": integrationResponses(values)}, err
	case http.MethodPost:
		var input integrationInputJSON
		if err := decodeRequest(request, &input); err != nil {
			return 0, nil, err
		}
		value, err := handler.service.Create(request.Context(), scope, IntegrationInput{ConnectorKey: input.ConnectorKey, Name: input.Name, Configuration: input.Configuration})
		return http.StatusCreated, integrationResponse(value), err
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) integrationResource(request *http.Request, scope domain.Scope, tail string) (int, any, error) {
	if !exactQuery(request) {
		return 0, nil, ErrInvalid
	}
	parts := strings.Split(tail, "/")
	if len(parts) == 0 || len(parts) > 3 {
		return 0, nil, ErrNotFound
	}
	id, err := domain.ParseProductID(parts[0])
	if err != nil {
		return 0, nil, ErrInvalid
	}
	if len(parts) == 1 {
		switch request.Method {
		case http.MethodGet:
			value, err := handler.service.Get(request.Context(), scope, id)
			return http.StatusOK, integrationResponse(value), err
		case http.MethodPatch:
			var input integrationUpdateJSON
			if err := decodeRequest(request, &input); err != nil {
				return 0, nil, err
			}
			value, err := handler.service.Update(request.Context(), scope, id, IntegrationUpdate{Name: input.Name, Configuration: input.Configuration})
			return http.StatusOK, integrationResponse(value), err
		case http.MethodDelete:
			return http.StatusNoContent, nil, handler.service.Delete(request.Context(), scope, id)
		default:
			return 0, nil, ErrNotFound
		}
	}
	if len(parts) == 2 && parts[1] == "authorize" && request.Method == http.MethodPost {
		if err := decodeEmptyRequest(request); err != nil {
			return 0, nil, err
		}
		value, err := handler.service.Authorize(request.Context(), scope, id)
		return http.StatusOK, integrationResponse(value), err
	}
	if len(parts) == 2 && parts[1] == "sync" && request.Method == http.MethodPost {
		var input syncInputJSON
		if err := decodeRequest(request, &input); err != nil {
			return 0, nil, err
		}
		value, _, err := handler.service.Sync(request.Context(), scope, id, input.JobID)
		return http.StatusAccepted, syncResponse(value), err
	}
	if len(parts) == 2 && parts[1] == "syncs" && request.Method == http.MethodGet {
		values, err := handler.service.ListSyncs(request.Context(), scope, id)
		return http.StatusOK, map[string]any{"items": syncResponses(values)}, err
	}
	if len(parts) == 3 && parts[1] == "syncs" && request.Method == http.MethodGet {
		syncID, err := domain.ParseProductID(parts[2])
		if err != nil {
			return 0, nil, ErrInvalid
		}
		value, err := handler.service.GetSync(request.Context(), scope, id, syncID)
		return http.StatusOK, syncResponse(value), err
	}
	return 0, nil, ErrNotFound
}

type integrationInputJSON struct {
	ConnectorKey  string            `json:"connector_key"`
	Name          string            `json:"name"`
	Configuration map[string]string `json:"configuration"`
}
type integrationUpdateJSON struct {
	Name          string            `json:"name"`
	Configuration map[string]string `json:"configuration"`
}
type syncInputJSON struct {
	JobID string `json:"job_id"`
}

type integrationJSON struct {
	ID            string            `json:"id"`
	ConnectorKey  string            `json:"connector_key"`
	Name          string            `json:"name"`
	Configuration map[string]string `json:"configuration"`
	Status        IntegrationStatus `json:"status"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}
type syncJSON struct {
	ID            string     `json:"id"`
	IntegrationID string     `json:"integration_id"`
	JobID         string     `json:"job_id"`
	Status        SyncStatus `json:"status"`
	CreatedAt     string     `json:"created_at"`
	UpdatedAt     string     `json:"updated_at"`
}

func integrationResponse(value Integration) integrationJSON {
	return integrationJSON{ID: value.id.String(), ConnectorKey: value.connectorKey, Name: value.name, Configuration: cloneConfiguration(value.configuration), Status: value.status, CreatedAt: value.createdAt.Format(timeFormat), UpdatedAt: value.updatedAt.Format(timeFormat)}
}
func integrationResponses(values []Integration) []integrationJSON {
	result := make([]integrationJSON, len(values))
	for i, v := range values {
		result[i] = integrationResponse(v)
	}
	return result
}
func syncResponse(value IntegrationSync) syncJSON {
	return syncJSON{ID: value.id.String(), IntegrationID: value.integrationID.String(), JobID: value.jobID, Status: value.status, CreatedAt: value.createdAt.Format(timeFormat), UpdatedAt: value.updatedAt.Format(timeFormat)}
}
func syncResponses(values []IntegrationSync) []syncJSON {
	result := make([]syncJSON, len(values))
	for i, v := range values {
		result[i] = syncResponse(v)
	}
	return result
}

const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

func decodeRequest(request *http.Request, target any) error {
	if request.Header.Get("Content-Type") != "application/json" || request.Body == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maximumRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func decodeEmptyRequest(request *http.Request) error {
	var empty struct{}
	return decodeRequest(request, &empty)
}
func exactQuery(request *http.Request, allowed ...string) bool {
	set := map[string]bool{}
	for _, v := range allowed {
		set[v] = true
	}
	for key, values := range request.URL.Query() {
		if !set[key] || len(values) != 1 {
			return false
		}
	}
	return true
}
func authorizeRequest(authorize Authorizer, request *http.Request) (scope domain.Scope, err error) {
	defer func() {
		if recover() != nil {
			scope = domain.Scope{}
			err = ErrForbidden
		}
	}()
	return authorize(request)
}

func writeHTTPError(writer http.ResponseWriter, err error) {
	status, code, message := http.StatusInternalServerError, "operation_rejected", "Operation rejected"
	switch {
	case errors.Is(err, ErrForbidden):
		status, code, message = http.StatusForbidden, "authorization_rejected", "Authorization rejected"
	case errors.Is(err, ErrNotFound):
		status, code, message = http.StatusNotFound, "not_found", "Integration not found"
	case errors.Is(err, ErrInvalid):
		status, code, message = http.StatusBadRequest, "invalid_request", "Request rejected"
	case errors.Is(err, ErrConflict), errors.Is(err, ErrTransition):
		status, code, message = http.StatusConflict, "conflict", "Integration conflict"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": message, "correlation_id": fallbackCorrelationID, "retryable": false})
}
