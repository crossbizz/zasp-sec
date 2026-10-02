package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func (handler *identityHTTPHandler) serveAuditPublicPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	writer.Header().Set("Cache-Control", "no-store")
	credential, browser, ok := requestCredential(request)
	cookies := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == browserSessionCookie {
			cookies++
		}
	}
	if !ok || !browser || cookies != 1 || identity.CredentialKind != CredentialBrowserSession || !validRequestIdentity(identity, true) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if !currentRequestHasPermission(request.Context(), identity, "view_audit") {
		writeAuditExportHTTPError(writer, request, ErrAuditExportForbidden)
		return
	}
	if request.Method != http.MethodGet || request.ContentLength > 0 || len(handler.signingKey) != 32 {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	if request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(request.Body, 1))
		if err != nil || len(body) > 0 {
			writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	query, err := parseAuditListQuery(request.URL.RawQuery, identity)
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	input := auditPublicPageRequest{sessionDigest: digest[:], filters: query.filters, limit: query.limit}
	if query.cursor != "" {
		position, ok := handler.decodeAdministrationCursor(query.cursor, identity, "listAuditEvents", query.digest)
		at, err := time.Parse(time.RFC3339Nano, position.AfterTime)
		if !ok || err != nil || !validProductID(position.AfterID) || at.Year() < 1 || at.Year() > 9999 || at.Nanosecond()%1000 != 0 {
			writeAuditExportHTTPError(writer, request, ErrRepositoryNotFound)
			return
		}
		input.afterTime = at.UTC()
		input.afterTimeSet = true
		input.afterID = position.AfterID
	}
	page, err := handler.auditPublicPages.read(ctx, identity, input)
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	var cursor any
	if page.hasMore {
		position, ok := administrationCursorPosition("listAuditEvents", page.items[len(page.items)-1])
		if !ok {
			writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
			return
		}
		token := handler.encodeAdministrationCursor(identity, "listAuditEvents", query.digest, position)
		if len(token) == 0 || len(token) > 512 {
			writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
			return
		}
		cursor = token
	}
	// Marshal the exact envelope once. Send precisely the checked bytes, including
	// their sole newline; writeJSONValue would perform a second serialization.
	body, err := json.Marshal(map[string]any{"items": page.items, "page_info": map[string]any{"next_cursor": cursor, "has_more": page.hasMore}})
	if err != nil || len(body)+1 > auditListHardBytes {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	body = append(body, '\n')
	if err := ctx.Err(); err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}
