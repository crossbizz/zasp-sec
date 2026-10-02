package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"net/http"
)

type securityAgentExportHTTPHandler struct {
	exports *SecurityAgentExportsRepository
	reader  complianceArtifactReader
}

func (h *securityAgentExportHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	route, routed := RoutedOperationFromRequest(r)
	credential, browser, auth := requestCredential(r)
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == browserSessionCookie {
			count++
		}
	}
	if !ok || !routed || !auth || !browser || count != 1 || i.CredentialKind != CredentialBrowserSession || !validRequestIdentity(i, true) {
		writeComplianceError(w, r, ErrRepositoryAuthentication)
		return
	}
	run, step := route.PathParameters["id"], route.PathParameters["stepId"]
	if !validProductID(run) || !validProductID(step) || r.URL.RawQuery != "" {
		writeComplianceError(w, r, ErrRepositoryOperation)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	if r.Method == http.MethodGet && route.OperationID == "getSecurityAgentExport" {
		status, err := h.exports.Get(r.Context(), i, digest[:], run, step)
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		writeJSONValue(w, r, http.StatusOK, status, nil)
		return
	}
	if r.Method != http.MethodPost || len(r.Header.Values("X-CSRF-Token")) != 1 || r.Header.Get("X-CSRF-Token") != i.CSRFToken {
		writeComplianceError(w, r, ErrRepositoryOperation)
		return
	}
	body, err := complianceRequestBody(r)
	if err != nil {
		writeComplianceError(w, r, err)
		return
	}
	fields := []string{"format"}
	if route.OperationID == "downloadSecurityAgentExport" {
		fields = append(fields, "token")
	} else if route.OperationID != "createSecurityAgentExportDownloadGrant" {
		writeComplianceError(w, r, ErrRepositoryNotFound)
		return
	}
	f, err := auditExportClosedObject(body, 1024, fields...)
	var format, token string
	if err != nil || json.Unmarshal(f["format"], &format) != nil || !stringIn(format, "json", "csv", "human") {
		writeComplianceError(w, r, ErrRepositoryOperation)
		return
	}
	sqlFormat := format
	if format == "human" {
		sqlFormat = "readable"
	}
	if route.OperationID == "createSecurityAgentExportDownloadGrant" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			writeComplianceError(w, r, ErrRepositoryUnavailable)
			return
		}
		token = hex.EncodeToString(b)
		grant, err := h.exports.grantAction(r.Context(), i, digest[:], run, step, token, sqlFormat, "issue")
		if err != nil {
			writeComplianceError(w, r, err)
			return
		}
		writeJSONValue(w, r, http.StatusCreated, map[string]any{"token": token, "format": format, "expires_at": grant.ExpiresAt}, nil)
		return
	}
	if json.Unmarshal(f["token"], &token) != nil || !validExistingTestPublicDigest(token) {
		writeComplianceError(w, r, ErrRepositoryOperation)
		return
	}
	pin, err := h.exports.readGrant(r.Context(), i, digest[:], run, step, token, sqlFormat)
	if err != nil {
		writeComplianceError(w, r, err)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), pin.ReadExpiresAt)
	defer cancel()
	data, err := readSecurityAgentExportDownload(ctx, h.reader, i, pin.Reference, format, pin)
	if err != nil {
		if errors.Is(err, artifactstore.ErrIntegrity) {
			_, _ = h.exports.grantAction(ctx, i, digest[:], run, step, token, sqlFormat, "integrity_failure")
		}
		writeComplianceError(w, r, ErrRepositoryUnavailable)
		return
	}
	if _, err = h.exports.grantAction(ctx, i, digest[:], run, step, token, sqlFormat, "consume"); err != nil {
		writeComplianceError(w, r, err)
		return
	}
	if ctx.Err() != nil {
		writeComplianceError(w, r, ctx.Err())
		return
	}
	media, extension := "application/json", "json"
	if format == "csv" {
		media, extension = "text/csv; charset=utf-8", "csv"
	}
	if format == "human" {
		media, extension = "text/plain; charset=utf-8", "txt"
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Content-Disposition", `attachment; filename="agent-export-`+pin.Reference+`.`+extension+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
func NewCompositionWithSecurityAgentExports(d Dependencies, audit, compliance, agent http.Handler) (http.Handler, error) {
	if _, ok := handlerIdentity(agent); !ok {
		return nil, ErrInvalidComposition
	}
	return newComposition(d, audit, compliance, agent)
}

var securityAgentExportOperations = []OperationDefinition{
	{Method: "GET", Pattern: "/api/v1/security-agent-runs/{id}/steps/{stepId}/export", OperationID: "getSecurityAgentExport"},
	{Method: "POST", Pattern: "/api/v1/security-agent-runs/{id}/steps/{stepId}/export/download-grants", OperationID: "createSecurityAgentExportDownloadGrant"},
	{Method: "POST", Pattern: "/api/v1/security-agent-runs/{id}/steps/{stepId}/export/download", OperationID: "downloadSecurityAgentExport"},
}
