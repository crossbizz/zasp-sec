package apiserver

import (
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
)

type securityAgentActivityAuthority interface {
	ListSecurityAgentActivityRuns(context.Context, RequestIdentity, SecurityAgentActivityRunRequest, []byte) (SecurityAgentActivityRunPage, error)
}

func (handler *securityAgentPublicHTTPHandler) listActivityRuns(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) {
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
	input := SecurityAgentActivityRunRequest{Kind: kind, EntityID: id, Limit: limit}
	if query.Has("cursor") {
		at, beforeID, valid := handler.decodeActivityCursor(query.Get("cursor"), identity, "runs", kind, id, limit)
		if !valid {
			writeAuditExportHTTPError(writer, request, ErrRepositoryOperation)
			return
		}
		input.BeforeCreatedAt, input.BeforeID = at, beforeID
	}
	authority, ok := handler.repository.(securityAgentActivityAuthority)
	if !ok || nilInterface(authority) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	digest := sha256.Sum256([]byte(credential.Value))
	page, err := authority.ListSecurityAgentActivityRuns(request.Context(), identity, input, digest[:])
	if err != nil {
		writeAuditExportHTTPError(writer, request, err)
		return
	}
	if !validSecurityAgentActivityPage(page, input) {
		writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
		return
	}
	value := map[string]any{"items": page.Items, "coverage": page.Coverage}
	if page.NextCreatedAt != nil {
		cursor, err := handler.encodeActivityCursor(identity, "runs", kind, id, limit, *page.NextCreatedAt, page.NextID)
		if err != nil {
			writeAuditExportHTTPError(writer, request, ErrRepositoryUnavailable)
			return
		}
		value["next_cursor"] = cursor
	}
	writeJSONValue(writer, request, http.StatusOK, value, nil)
}

func validSecurityAgentActivityPage(page SecurityAgentActivityRunPage, input SecurityAgentActivityRunRequest) bool {
	if page.Items == nil || len(page.Items) > input.Limit || !stringIn(page.Coverage, "complete", "partial") || (page.NextCreatedAt == nil) != (page.NextID == "") {
		return false
	}
	if input.Kind == "audit" && (len(page.Items) > 1 || page.NextID != "" || page.Coverage != "complete") {
		return false
	}
	seen := make(map[string]bool, len(page.Items))
	for _, run := range page.Items {
		if !validSecurityAgentRun(run) || run.State == "simulated" || seen[run.ID] {
			return false
		}
		seen[run.ID] = true
	}
	if page.NextCreatedAt != nil {
		if len(page.Items) != input.Limit || len(page.Items) == 0 || page.Items[len(page.Items)-1].ID != page.NextID {
			return false
		}
		if !input.BeforeCreatedAt.IsZero() && (page.NextCreatedAt.After(input.BeforeCreatedAt) || page.NextCreatedAt.Equal(input.BeforeCreatedAt) && page.NextID >= input.BeforeID) {
			return false
		}
	}
	return true
}
