package apiserver

import (
	"context"
	"io"
	"net/http"
)

type singleTestRecoveryAuthority interface {
	Request(context.Context, RequestIdentity, SingleTestRecoveryMutation) (SingleTestRecoveryMutationResult, error)
	Get(context.Context, RequestIdentity, string) (SingleTestRecoveryView, error)
}
type singleTestRecoveryHTTPHandler struct{ authority singleTestRecoveryAuthority }

func NewSingleTestRecoveryHTTPHandler(a singleTestRecoveryAuthority) (http.Handler, error) {
	if nilInterface(a) {
		return nil, ErrRepositoryConfiguration
	}
	return &singleTestRecoveryHTTPHandler{a}, nil
}
func (h *singleTestRecoveryHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	route, ok := RoutedOperationFromRequest(r)
	id, authenticated := IdentityFromRequest(r)
	if !ok || !authenticated {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	if r.URL == nil || r.URL.RawQuery != "" || !validProductID(route.PathParameters["id"]) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var raw []byte
	var err error
	if r.Body != nil {
		raw, err = io.ReadAll(io.LimitReader(r.Body, 4097))
		_ = r.Body.Close()
	}
	if err != nil || len(raw) > 4096 {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if route.OperationID == "getSingleTestCleanupRecovery" {
		if r.Method != http.MethodGet || len(raw) != 0 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		v, err := h.authority.Get(r.Context(), id, route.PathParameters["id"])
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		w.Header().Set("ETag", quoteVersion(v.ParentVersion))
		writeJSONValue(w, r, http.StatusOK, v, nil)
		return
	}
	key, version, valid := discoveryMutationHeaders(r, false)
	var body struct {
		DefinitionVersion int64  `json:"definition_version"`
		InputDigest       string `json:"input_digest"`
		Diagnostic        string `json:"diagnostic"`
		StopOriginal      bool   `json:"stop_original"`
	}
	if route.OperationID != "requestSingleTestCleanupRecovery" || r.Method != http.MethodPost || !valid || !exactHeaderValue(r.Header.Values("Content-Type"), "application/json") || recoveryDecode(raw, 4096, &body) != nil || body.Diagnostic != "history_unavailable" || !body.StopOriginal {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	seed := id.PrincipalID.String() + "\x1f" + key
	audit, _ := CanonicalDiscoveryID(id.Scope, "single_test_recovery_audit", seed)
	receipt, _ := CanonicalDiscoveryID(id.Scope, "single_test_recovery_request", seed)
	correlation, ok := r.Context().Value(correlationContextKey{}).(string)
	if !ok || !validProductID(correlation) {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	result, err := h.authority.Request(r.Context(), id, SingleTestRecoveryMutation{RunID: route.PathParameters["id"], DefinitionVersion: body.DefinitionVersion, InputDigest: body.InputDigest, ExpectedVersion: version, IdempotencyKey: key, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt})
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	status := http.StatusAccepted
	if result.Replayed || result.Body.Status == "complete" {
		status = http.StatusOK
	}
	writeRecoveryMutationHeaders(w, id, result.Body.ParentVersion, result.AuditID, result.ReceiptID)
	writeJSONValue(w, r, status, result.Body, nil)
}
