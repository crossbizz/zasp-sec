package sessioncontrol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type HTTPHandler struct {
	mu        sync.RWMutex
	projector *Projector
	controls  []ComplianceControl
	evidence  []EvidenceRecord
	exports   map[string]ComplianceExport
	data      *DataControlStore
	authorize func(*http.Request) bool
	clock     func() time.Time
}

func NewHTTPHandler(projector *Projector, controls []ComplianceControl, evidence []EvidenceRecord, data *DataControlStore, authorize func(*http.Request) bool) (*HTTPHandler, error) {
	if projector == nil || len(controls) == 0 || data == nil || authorize == nil {
		return nil, ErrRejected
	}
	clonedControls := make([]ComplianceControl, len(controls))
	for index, control := range controls {
		clonedControls[index] = cloneControl(control)
	}
	return &HTTPHandler{projector: projector, controls: clonedControls, evidence: append([]EvidenceRecord(nil), evidence...), exports: map[string]ComplianceExport{}, data: data, authorize: authorize, clock: func() time.Time { return time.Now().UTC() }}, nil
}
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || !h.authorize(r) || r.URL.EscapedPath() != r.URL.Path || strings.HasSuffix(r.URL.Path, "/") {
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
	if status != http.StatusNoContent {
		_ = json.NewEncoder(w).Encode(value)
	}
}
func (h *HTTPHandler) dispatch(r *http.Request) (int, any, error) {
	if r.URL.Path == "/api/v1/sessions" && r.Method == http.MethodGet {
		if _, err := filterFromQuery(r.URL.Query()); err != nil {
			return 0, nil, err
		}
		values, err := h.projector.List(r.Context())
		return http.StatusOK, map[string]any{"items": values}, err
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/sessions/") && r.Method == http.MethodGet {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/"), "/")
		if len(parts) == 1 {
			value, err := h.projector.Get(r.Context(), parts[0])
			return http.StatusOK, value, err
		}
		if len(parts) == 2 && parts[1] == "events" {
			value, err := h.projector.Get(r.Context(), parts[0])
			return http.StatusOK, map[string]any{"items": value.Events}, err
		}
	}
	if r.URL.Path == "/api/v1/compliance/controls" && r.Method == http.MethodGet {
		return http.StatusOK, map[string]any{"items": h.controls}, nil
	}
	if r.URL.Path == "/api/v1/compliance/evidence" && r.Method == http.MethodGet {
		value, err := AssembleComplianceEvidence(h.controls, h.evidence, h.clock())
		return http.StatusOK, map[string]any{"items": value}, err
	}
	if r.URL.Path == "/api/v1/compliance/exports" && r.Method == http.MethodPost {
		var input struct {
			ID string `json:"id"`
		}
		if decode(r, &input) != nil {
			return 0, nil, ErrRejected
		}
		assembled, err := AssembleComplianceEvidence(h.controls, h.evidence, h.clock())
		if err != nil {
			return 0, nil, err
		}
		value, err := BuildComplianceExport(input.ID, assembled)
		if err == nil {
			h.mu.Lock()
			h.exports[input.ID] = value
			h.mu.Unlock()
		}
		return http.StatusCreated, value, err
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/compliance/exports/") && r.Method == http.MethodGet {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/compliance/exports/")
		h.mu.RLock()
		value, ok := h.exports[id]
		h.mu.RUnlock()
		if !ok {
			return 0, nil, ErrRejected
		}
		return http.StatusOK, value, nil
	}
	if r.URL.Path == "/api/v1/settings/data-controls" {
		if r.Method == http.MethodGet {
			value, err := h.data.Get(r.Context(), "environment-1")
			return http.StatusOK, value, err
		}
		if r.Method == http.MethodPatch {
			var value DataControls
			if decode(r, &value) != nil {
				return 0, nil, ErrRejected
			}
			return http.StatusOK, value, h.data.Update(r.Context(), value)
		}
	}
	return 0, nil, ErrRejected
}

func filterFromQuery(query url.Values) (map[string]string, error) {
	allowed := map[string]bool{"agent_id": true, "principal_id": true, "tool": true, "process": true, "file": true, "domain": true, "credential": true, "resource": true, "decision": true, "from": true, "to": true}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return nil, ErrRejected
		}
	}
	parseTime := func(key string) (time.Time, error) {
		raw := query.Get(key)
		if raw == "" {
			return time.Time{}, nil
		}
		value, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || value.Location() != time.UTC {
			return time.Time{}, ErrRejected
		}
		return value, nil
	}
	from, err := parseTime("from")
	if err != nil {
		return nil, err
	}
	to, err := parseTime("to")
	if err != nil {
		return nil, err
	}
	return BuildSessionFilter(SessionFilter{AgentID: query.Get("agent_id"), PrincipalID: query.Get("principal_id"), Tool: query.Get("tool"), Process: query.Get("process"), File: query.Get("file"), Domain: query.Get("domain"), Credential: query.Get("credential"), Resource: query.Get("resource"), Decision: query.Get("decision"), From: from, To: to})
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
	_, _ = w.Write([]byte("{\"code\":\"session_control_rejected\",\"message\":\"Session control operation rejected\",\"retryable\":false}\n"))
}
