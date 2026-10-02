package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
)

type securityAgentAuditAuthority interface {
	GetSecurityAgentAuditEvent(context.Context, RequestIdentity, string, []byte) (SecurityAgentAuditEvent, error)
}

func (handler *securityAgentPublicHTTPHandler) getAuditEvent(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, authenticated := IdentityFromRequest(request)
	credential, browser, ok := requestCredential(request)
	cookies := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == browserSessionCookie {
			cookies++
		}
	}
	if !authenticated || !ok || !browser || cookies != 1 || identity.CredentialKind != CredentialBrowserSession || !validRequestIdentity(identity, true) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if !slices.Contains(identity.Permissions, "view_audit") {
		writeAuditExportHTTPError(writer, request, ErrAuditExportForbidden)
		return
	}
	id := routed.PathParameters["id"]
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || !validProductID(id) || request.ContentLength > 0 || requireZeroByteInput(request) != nil {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	authority, ok := handler.repository.(securityAgentAuditAuthority)
	if !ok || nilInterface(authority) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	result, err := authority.GetSecurityAgentAuditEvent(request.Context(), identity, id, digest[:])
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	raw, err := json.Marshal(result)
	if err == nil {
		_, err = decodeSecurityAgentAuditEvent(raw, identity, id)
	}
	if err != nil {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}
