package apiserver

import (
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
	"time"
)

type securityAgentActivityTargetsAuthority interface {
	ListSecurityAgentRunActivity(context.Context, RequestIdentity, SecurityAgentActivityTargetRequest, []byte) (SecurityAgentActivityTargetPage, error)
}

func (handler *securityAgentPublicHTTPHandler) listRunActivity(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
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
	kind, id := routed.PathParameters["kind"], routed.PathParameters["id"]
	query, queryOK := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": securityAgentActivityCursorMax, "limit": 3})
	limit, limitOK := workflowPageLimit(query)
	if request.Method != http.MethodGet || !stringIn(kind, "finding", "attack_path", "session", "audit") || !validProductID(id) || !queryOK || !limitOK || request.ContentLength > 0 || requireZeroByteInput(request) != nil {
		writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
		return
	}
	if !slices.Contains(identity.Permissions, "view") || kind == "session" && !slices.Contains(identity.Permissions, "investigate_sessions") || kind == "audit" && !slices.Contains(identity.Permissions, "view_audit") {
		writeAuditExportHTTPError(writer, request, ErrAuditExportForbidden)
		return
	}
	input := SecurityAgentActivityTargetRequest{RunID: id, Kind: kind, Limit: limit}
	if query.Has("cursor") {
		_, after, valid := handler.decodeActivityCursor(query.Get("cursor"), identity, "targets", kind, id, limit)
		if !valid {
			writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
			return
		}
		input.AfterID = after
	}
	authority, ok := handler.repository.(securityAgentActivityTargetsAuthority)
	if !ok || nilInterface(authority) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	page, err := authority.ListSecurityAgentRunActivity(request.Context(), identity, input, digest[:])
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	if !validSecurityAgentActivityTargetPage(page, input) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	value := map[string]any{"items": page.Items, "coverage": page.Coverage}
	if page.NextID != "" {
		cursor, err := handler.encodeActivityCursor(identity, "targets", kind, id, limit, time.Time{}, page.NextID)
		if err != nil {
			writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
			return
		}
		value["next_cursor"] = cursor
	}
	writeJSONValue(writer, request, http.StatusOK, value, nil)
}

func validSecurityAgentActivityTargetPage(page SecurityAgentActivityTargetPage, input SecurityAgentActivityTargetRequest) bool {
	if page.Items == nil || len(page.Items) > input.Limit || !stringIn(page.Coverage, "complete", "partial") || input.Kind == "audit" && page.Coverage != "complete" {
		return false
	}
	last := input.AfterID
	for _, item := range page.Items {
		if item.Kind != input.Kind || !validProductID(item.ID) || item.ID <= last {
			return false
		}
		last = item.ID
	}
	return page.NextID == "" || len(page.Items) > 0 && len(page.Items) == input.Limit && page.NextID == last
}
