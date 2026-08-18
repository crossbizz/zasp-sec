package sensor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumBodyBytes = 16 * 1024

type Authorizer func(*http.Request) (domain.Scope, error)
type HTTPHandler struct {
	store     *MemoryStore
	authorize Authorizer
}
type HeartbeatHandler struct {
	store     *MemoryStore
	authorize Authorizer
}

func NewHTTPHandler(store *MemoryStore, authorize Authorizer) (*HTTPHandler, error) {
	if store == nil || !store.usable() || authorize == nil {
		return nil, ErrInvalid
	}
	return &HTTPHandler{store: store, authorize: authorize}, nil
}
func NewHeartbeatHandler(store *MemoryStore, authorize Authorizer) (*HeartbeatHandler, error) {
	if store == nil || !store.usable() || authorize == nil {
		return nil, ErrInvalid
	}
	return &HeartbeatHandler{store: store, authorize: authorize}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.store == nil || request == nil || request.URL == nil {
		writeError(writer, ErrInvalid)
		return
	}
	scope, err := safeAuthorize(handler.authorize, request)
	if err != nil || scope.Validate() != nil {
		writeError(writer, ErrForbidden)
		return
	}
	if request.URL.RawQuery != "" || request.URL.EscapedPath() != request.URL.Path || strings.HasSuffix(request.URL.Path, "/") {
		writeError(writer, ErrInvalid)
		return
	}
	status, payload, err := handler.dispatch(request, scope)
	if err != nil {
		writeError(writer, err)
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
	path := request.URL.Path
	if path == "/api/v1/sensors" {
		switch request.Method {
		case http.MethodGet:
			values, err := handler.store.List(request.Context(), scope)
			return http.StatusOK, map[string]any{"items": sensorResponses(values)}, err
		case http.MethodPost:
			var input Input
			if decodeBody(request, &input) != nil {
				return 0, nil, ErrInvalid
			}
			value, err := handler.store.Create(request.Context(), scope, input)
			return http.StatusCreated, enrollmentResponse(value), err
		default:
			return 0, nil, ErrNotFound
		}
	}
	const prefix = "/api/v1/sensors/"
	if !strings.HasPrefix(path, prefix) {
		return 0, nil, ErrNotFound
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 0 || len(parts) > 2 {
		return 0, nil, ErrNotFound
	}
	id, err := domain.ParseProductID(parts[0])
	if err != nil {
		return 0, nil, ErrInvalid
	}
	if len(parts) == 1 {
		switch request.Method {
		case http.MethodGet:
			value, err := handler.store.Get(request.Context(), scope, id)
			return http.StatusOK, sensorResponse(value), err
		case http.MethodPatch:
			var input Input
			if decodeBody(request, &input) != nil {
				return 0, nil, ErrInvalid
			}
			value, err := handler.store.Update(request.Context(), scope, id, input)
			return http.StatusOK, sensorResponse(value), err
		case http.MethodDelete:
			return http.StatusNoContent, nil, handler.store.Delete(request.Context(), scope, id)
		default:
			return 0, nil, ErrNotFound
		}
	}
	if parts[1] == "rotate-token" && request.Method == http.MethodPost {
		if decodeEmpty(request) != nil {
			return 0, nil, ErrInvalid
		}
		value, err := handler.store.Rotate(request.Context(), scope, id)
		return http.StatusOK, enrollmentResponse(value), err
	}
	if parts[1] == "coverage" && request.Method == http.MethodGet {
		value, err := handler.store.Coverage(request.Context(), scope, id)
		return http.StatusOK, coverageResponse(value), err
	}
	return 0, nil, ErrNotFound
}

func (handler *HeartbeatHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.store == nil || request == nil || request.URL == nil {
		writeError(writer, ErrInvalid)
		return
	}
	scope, err := safeAuthorize(handler.authorize, request)
	if err != nil || scope.Validate() != nil {
		writeError(writer, ErrForbidden)
		return
	}
	const prefix = "/internal/v1/sensors/"
	path := request.URL.Path
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.EscapedPath() != path || !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, "/heartbeat") {
		writeError(writer, ErrNotFound)
		return
	}
	idText := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/heartbeat")
	if strings.Contains(idText, "/") {
		writeError(writer, ErrNotFound)
		return
	}
	id, err := domain.ParseProductID(idText)
	if err != nil {
		writeError(writer, ErrInvalid)
		return
	}
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 {
		writeError(writer, ErrForbidden)
		return
	}
	var heartbeat Heartbeat
	if decodeBody(request, &heartbeat) != nil {
		writeError(writer, ErrInvalid)
		return
	}
	value, err := handler.store.Heartbeat(request.Context(), scope, id, strings.TrimPrefix(authorization, "Bearer "), heartbeat)
	if err != nil {
		writeError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(sensorResponse(value))
}

func sensorResponse(value Sensor) map[string]any {
	result := map[string]any{"id": value.ID.String(), "name": value.Name, "mode": value.Mode, "capabilities": append([]string{}, value.Capabilities...), "created_at": value.CreatedAt.Format("2006-01-02T15:04:05.000Z"), "updated_at": value.UpdatedAt.Format("2006-01-02T15:04:05.000Z")}
	if !value.LastHeartbeat.IsZero() {
		result["last_heartbeat"] = value.LastHeartbeat.Format("2006-01-02T15:04:05.000Z")
	}
	return result
}
func sensorResponses(values []Sensor) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, sensorResponse(value))
	}
	return result
}
func enrollmentResponse(value Enrollment) map[string]any {
	result := sensorResponse(value.Sensor)
	result["token"] = value.Token
	return result
}
func coverageResponse(value Coverage) map[string]any {
	result := map[string]any{"sensor_id": value.SensorID.String(), "supported": value.Supported, "status": value.Status, "kernel": value.Kernel, "btf": value.BTF, "capabilities": append([]string{}, value.Capabilities...), "event_rate": value.EventRate, "drops": value.Drops}
	if !value.LastHeartbeat.IsZero() {
		result["last_heartbeat"] = value.LastHeartbeat.Format("2006-01-02T15:04:05.000Z")
	}
	return result
}

func decodeBody(request *http.Request, destination any) error {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		return ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumBodyBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumBodyBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func decodeEmpty(request *http.Request) error {
	if request.Body == nil {
		return nil
	}
	var value map[string]any
	if decodeBody(request, &value) != nil || len(value) != 0 {
		return ErrInvalid
	}
	return nil
}
func safeAuthorize(authorize Authorizer, request *http.Request) (scope domain.Scope, err error) {
	defer func() {
		if recover() != nil {
			scope = domain.Scope{}
			err = ErrForbidden
		}
	}()
	if authorize == nil {
		return domain.Scope{}, ErrForbidden
	}
	return authorize(request)
}
func writeError(writer http.ResponseWriter, err error) {
	status, code := http.StatusBadRequest, "invalid_request"
	switch {
	case errors.Is(err, ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, ErrConflict):
		status, code = http.StatusConflict, "conflict"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": "Request rejected", "correlation_id": "pid_ffffffff-ffff-4fff-8fff-ffffffffffff", "retryable": false})
}
