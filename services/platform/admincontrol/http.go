package admincontrol

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type HTTPHandler struct {
	flows     *ExternalFlowStore
	probes    *SystemProbes
	authorize func(*http.Request) bool
	clock     func() time.Time
}

func NewHTTPHandler(flows *ExternalFlowStore, probes *SystemProbes, authorize func(*http.Request) bool) (*HTTPHandler, error) {
	if flows == nil || !flows.requiredReady() || probes == nil || authorize == nil {
		return nil, ErrRejected
	}
	return &HTTPHandler{flows: flows, probes: probes, authorize: authorize, clock: func() time.Time { return time.Now().UTC() }}, nil
}
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || !h.authorize(r) || r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path || strings.HasSuffix(r.URL.Path, "/") {
		writeError(w, http.StatusForbidden)
		return
	}
	status, value, err := h.dispatch(r)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (h *HTTPHandler) dispatch(r *http.Request) (int, any, error) {
	switch r.URL.Path {
	case "/api/v1/settings/external-data-flows":
		if r.Method == http.MethodGet {
			values, err := h.flows.List(r.Context())
			return http.StatusOK, map[string]any{"items": values}, err
		}
		if r.Method == http.MethodPatch {
			var value ExternalFlow
			if decode(r, &value) != nil {
				return 0, nil, ErrRejected
			}
			return http.StatusOK, value, h.flows.Update(r.Context(), value)
		}
	case "/api/v1/system/status":
		if r.Method == http.MethodGet {
			value, err := h.probes.Status(r.Context(), h.clock())
			return http.StatusOK, value, err
		}
	case "/api/v1/system/components":
		if r.Method == http.MethodGet {
			values, err := h.probes.Components(r.Context(), h.clock())
			return http.StatusOK, map[string]any{"items": values}, err
		}
	case "/api/v1/system/version":
		if r.Method == http.MethodGet {
			value, err := h.probes.Version(r.Context())
			return http.StatusOK, map[string]string{"version": value}, err
		}
	}
	return 0, nil, ErrRejected
}
func decode(r *http.Request, target any) error {
	if r.Header.Get("Content-Type") != "application/json" || r.ContentLength < 0 || r.ContentLength > 16*1024 {
		return ErrRejected
	}
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16*1024))
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
func writeError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("{\"code\":\"admin_control_rejected\",\"message\":\"Admin control operation rejected\",\"retryable\":false}\n"))
}
