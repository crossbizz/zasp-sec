package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/mcpserver"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Every product read and draft creation passes through the composed router
// so its credential, OpenFGA targets and PostgreSQL statement authorization
// independently govern that operation.
func serveZaspMCP(w http.ResponseWriter, r *http.Request) {
	i, ok := IdentityFromRequest(r)
	if !ok {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	security, _ := r.Context().Value(browserSecurityContextKey{}).(browserSecurityContext)
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && (origins[0] == "" || origins[0] != security.publicOrigin) ||
		i.CredentialKind == CredentialBrowserSession && len(origins) != 1 {
		writeRouterError(w, r, http.StatusForbidden, "request_forbidden", "Request forbidden")
		return
	}
	if r.URL.RawQuery != "" || len(r.Header.Values("Mcp-Session-Id")) > 0 {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	permissions, err := mcpPermissions(r.Context(), i)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	routes := make(map[string]string)
	for _, op := range coreOperations {
		if !slices.Contains(permissions, op.Permission) {
			continue
		}
		scheme := "BrowserSession"
		if i.CredentialKind == CredentialBearerToken {
			scheme = "ProductAPIToken"
		}
		if slices.Contains(op.Security, scheme) {
			routes[op.OperationID] = op.Pattern
		}
	}
	review := &mcpserver.ReviewTools{Visible: func(name string) bool {
		switch name {
		case "propose_policy":
			return routes["createPolicy"] != ""
		case "request_containment":
			return routes["decideSecurityAgentApproval"] != "" && routes["getSecurityAgentApproval"] != ""
		case "trigger_verification":
			return routes["verifySecurityCase"] != "" && routes["getSecurityCaseVerification"] != ""
		}
		return false
	}}
	review.Review = func(ctx context.Context, name string, proposal mcpserver.Proposal) (int, []byte) {
		if !review.Visible(name) {
			return http.StatusForbidden, nil
		}
		readCtx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(ctx, cancel)
		defer cancel()
		defer stop()
		return mcpReview(r.WithContext(readCtx), i, routes, name, proposal)
	}
	reader := &agentEvidencePackHandler{}
	mcpserver.Serve(w, r, func(op string) bool { return routes[op] != "" }, func(ctx context.Context, op, id string, q url.Values) (int, []byte) {
		path, ok := routes[op]
		if !ok {
			return http.StatusForbidden, nil
		}
		readCtx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(ctx, cancel)
		defer cancel()
		defer stop()
		return reader.read(r.WithContext(readCtx), strings.Replace(path, "{id}", id, 1), q)
	}, review)
}

// Current credentials carry identity and a PAT ceiling. Compute visible tools
// at one applied revision; each actual operation still rechecks its own target.
func mcpPermissions(ctx context.Context, i RequestIdentity) ([]string, error) {
	authority := ctx.Value(requestAuthorizerContextKey{})
	if authority == nil {
		return i.Permissions, nil
	}
	a, ok := authority.(*OpenFGAAuthorizer)
	if !ok {
		return nil, authorization.ErrUnavailable
	}
	g, ok := ctx.Value(requestAuthorizationContextKey{}).(RequestAuthorization)
	if !ok || g.OperationID != "callZaspMCP" {
		return nil, authorization.ErrUnavailable
	}
	s := i.Scope
	var checks []authorization.CheckRequest
	for _, perm := range []string{"view", "manage_workflows", "investigate_sessions"} {
		if i.CredentialKind == CredentialBearerToken && !slices.Contains(i.credentialBinding.PATCeiling, perm) {
			continue
		}
		checks = append(checks, authorization.CheckRequest{PrincipalKind: "user", PrincipalID: i.PrincipalID.String(), OrganizationID: s.OrganizationID().String(), WorkspaceID: s.WorkspaceID().String(), EnvironmentID: s.EnvironmentID().String(), ResourceType: "environment", ResourceID: s.EnvironmentID().String(), Permission: perm})
	}
	decisions, err := authorization.CheckRevisionAll(ctx, a.Reader, a.Checker, checks, a.StoreID, a.ModelID)
	if err != nil {
		return nil, err
	}
	var permissions []string
	for _, d := range decisions {
		if d.Revision != g.Revision {
			return nil, authorization.ErrConflict
		}
		if d.Decision.Allowed {
			permissions = append(permissions, d.Request.Permission)
		}
	}
	return permissions, nil
}

// Only a draft can be written here. Containment and verification hand back the
// exact existing record to the authenticated product approval form.
func mcpReview(r *http.Request, i RequestIdentity, routes map[string]string, name string, p mcpserver.Proposal) (int, []byte) {
	ref := p.Reference
	q := url.Values{"organization_id": {i.Scope.OrganizationID().String()}, "workspace_id": {i.Scope.WorkspaceID().String()}, "environment_id": {i.Scope.EnvironmentID().String()}}
	switch name {
	case "propose_policy":
		id := "policy-mcp-" + strings.TrimPrefix(ref, "pid_")
		draft := policy.Policy{ID: id, Name: p.Name, Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: p.Action}}, Action: policy.Action(p.Effect), Rollout: "draft", FailureMode: "closed"}
		raw, err := json.Marshal(draft)
		if err != nil {
			return http.StatusInternalServerError, nil
		}
		status, body := dispatchScopedProduct(r, http.MethodPost, routes["createPolicy"], nil, raw, ref)
		if status != http.StatusCreated {
			return status, nil
		}
		var receipt policy.Policy
		if json.Unmarshal(body, &receipt) != nil || receipt.ID != id || receipt.Rollout != "draft" {
			return http.StatusInternalServerError, nil
		}
		q.Set("draft_id", id)
		return mcpserver.PendingReview(id, "/policies?"+q.Encode())
	case "request_containment":
		status, body := dispatchScopedProduct(r, http.MethodGet, strings.Replace(routes["getSecurityAgentApproval"], "{id}", ref, 1), nil, nil, "")
		if status != http.StatusOK {
			return status, nil
		}
		var approval SecurityAgentApproval
		if json.Unmarshal(body, &approval) != nil || approval.ID != ref || approval.Context == nil ||
			approval.Context.Action != "isolate_session" || approval.State != "pending" || !approval.ExpiresAt.After(time.Now()) {
			return http.StatusNotFound, nil
		}
		q.Set("entity_id", ref)
		return mcpserver.PendingReview(ref, "/protect/approvals?"+q.Encode())
	case "trigger_verification":
		status, body := dispatchScopedProduct(r, http.MethodGet, strings.Replace(routes["getSecurityCaseVerification"], "{id}", ref, 1), nil, nil, "")
		if status != http.StatusOK {
			return status, nil
		}
		var v caseVerification
		if json.Unmarshal(body, &v) != nil || v.CaseID != ref || v.State != "open" || v.Reason == "remediation_pending" {
			return http.StatusNotFound, nil
		}
		q.Set("entity_id", ref)
		return mcpserver.PendingReview(ref, "/protect/security-agents?"+q.Encode())
	}
	return http.StatusForbidden, nil
}
