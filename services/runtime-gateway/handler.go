package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const gatewayEvaluatePath = "/v1/evaluate"

type gatewayHTTPHandler struct {
	runtime      *gatewayRuntime
	maximumBytes int64
}

func newGatewayHandler(runtime *gatewayRuntime, maximumBytes int64) (http.Handler, error) {
	if runtime == nil || maximumBytes < 1024 || maximumBytes > 64*1024 {
		return nil, errGatewayRuntime
	}
	handler := &gatewayHTTPHandler{runtime: runtime, maximumBytes: maximumBytes}
	mux := http.NewServeMux()
	mux.Handle(gatewayEvaluatePath, handler)
	mux.Handle("/", http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		gatewayJSONError(response, http.StatusNotFound, "not_found")
	}))
	return mux, nil
}

func (handler *gatewayHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.runtime == nil || request == nil {
		gatewayJSONError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		gatewayJSONError(response, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.Header.Get("Content-Type") != "application/json" {
		gatewayJSONError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.maximumBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var evaluation gatewayEvaluationRequest
	if err := decoder.Decode(&evaluation); err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			gatewayJSONError(response, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validGatewayEvaluationRequest(evaluation) {
		gatewayJSONError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := handler.runtime.Evaluate(request.Context(), evaluation)
	if err != nil {
		gatewayJSONError(response, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(result)
}

func gatewayJSONError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code})
}
