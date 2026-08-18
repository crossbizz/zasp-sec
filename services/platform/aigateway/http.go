package aigateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

type GovernedHTTPHandler struct {
	governor  *Governor
	authorize func(*http.Request) bool
}

func NewGovernedHTTPHandler(governor *Governor, authorize func(*http.Request) bool) (*GovernedHTTPHandler, error) {
	if governor == nil || authorize == nil {
		return nil, ErrInvalidConfiguration
	}
	return &GovernedHTTPHandler{governor: governor, authorize: authorize}, nil
}
func (h *GovernedHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || !h.authorize(r) || r.Method != http.MethodPost || r.URL.Path != "/api/v1/ai/explanations" || r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path || strings.HasSuffix(r.URL.Path, "/") {
		writeGovernanceError(w, http.StatusForbidden)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" || r.ContentLength < 0 || r.ContentLength > 16*1024 {
		writeGovernanceError(w, http.StatusBadRequest)
		return
	}
	var request GovernedRequest
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		writeGovernanceError(w, http.StatusBadRequest)
		return
	}
	var extra any
	if decoder.Decode(&extra) == nil {
		writeGovernanceError(w, http.StatusBadRequest)
		return
	}
	result, err := h.governor.Generate(r.Context(), request)
	if err != nil {
		writeGovernanceError(w, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
func writeGovernanceError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("{\"code\":\"ai_governance_rejected\",\"message\":\"AI governance request rejected\",\"retryable\":false}\n"))
}
