package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation/issuer"
)

const delegationReceiptSQL = "SELECT zasp_authorization80.delegation_receipt($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)"

func init() {
	productStatementRules[delegationReceiptSQL] = productStatementRule{operations: []string{"createWorkloadActionDecision", "issueRuntimeDelegation", "verifyRuntimeDelegation", "callMCPGateway", "closeMCPGatewaySession", "createGatewayChatCompletion", "createGatewayResponse", "createGatewayMessage"}, arguments: 11, scope: 1, actor: 4, check: func(g RequestAuthorization, args []any) bool {
		return g.Identity.CredentialKind == CredentialBearerToken && g.OperationID == args[4] && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}}
}

func delegationTenant(i RequestIdentity) delegation.Tenant {
	return delegation.Tenant{Organization: i.Scope.OrganizationID().String(), Workspace: i.Scope.WorkspaceID().String(), Environment: i.Scope.EnvironmentID().String()}
}

type verifyDelegation struct {
	Task      string `json:"parent_task_id"`
	Token     string `json:"token,omitempty"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
}

func (h *hostedGatewayHandler) delegationAPI(w http.ResponseWriter, r *http.Request, i RequestIdentity, op RoutedOperation) {
	if h.authority == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	if i.CredentialKind != CredentialBearerToken || i.credentialBinding.ID == "" {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if r.URL.RawQuery != "" || r.Method != http.MethodPost {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	t, cred := delegationTenant(i), i.credentialBinding.ID
	if h.authority.AgentID(t, cred) == "" {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if op.OperationID == "issueRuntimeDelegation" {
		var in issuer.IssueRequest
		if decodeProductionJSON(r, &in) != nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		out, err := h.authority.Issue(t, cred, in, time.Now())
		if err != nil {
			writeProductionError(w, r, ErrRepositoryAuthorization)
			return
		}
		hop := delegationHop{Scope: in.Scope, Parent: h.authority.AgentID(t, cred), Child: in.Child, Depth: out.Depth, MaxDepth: in.MaxDepth, Expires: out.Expires}
		if h.saveDelegation(w, r, i, op.OperationID, in.Task, out.Token, "issued", in.ParentToken, &hop) {
			raw, err := json.Marshal(out)
			writeProductionResponse(w, r, http.StatusOK, raw, err)
		}
		return
	}
	var in verifyDelegation
	if decodeProductionJSON(r, &in) != nil || !delegation.ValidIdentifier(in.Task) || !delegation.ValidIdentifier(in.Operation) || !delegation.ValidIdentifier(in.Resource) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	d := h.authority.Check(t, cred, in.Task, in.Token, in.Operation, in.Resource, time.Now())
	if h.saveDelegation(w, r, i, op.OperationID, in.Task, in.Token, d.Status, "", nil) {
		raw, err := json.Marshal(d)
		writeProductionResponse(w, r, http.StatusOK, raw, err)
	}
}

func (h *hostedGatewayHandler) saveDelegation(w http.ResponseWriter, r *http.Request, i RequestIdentity, op, task, token, status, parentToken string, hop *delegationHop) bool {
	t := delegationTenant(i)
	var record any
	if hop != nil {
		encoded, err := json.Marshal(hop)
		if err != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return false
		}
		record = string(encoded)
	}
	raw, err := h.database.QueryJSON(r.Context(), delegationReceiptSQL, t.Organization, t.Workspace, t.Environment, i.PrincipalID.String(), op, h.authority.AgentID(t, i.credentialBinding.ID), task, grantDigest(token), status, grantDigest(parentToken), record)
	if err != nil {
		writeProductionError(w, r, err)
		return false
	}
	if string(raw) != "true" {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return false
	}
	return true
}

// Tier: 1 | Purpose: enforce delegated authority on hosted MCP traffic.
// Model: none.
// Authority: authenticated API credential, registered MCP server ID and parsed tool name.
// Fallback: block unverified calls and refuse unsupported delegated transports.
func (h *hostedGatewayHandler) delegationTraffic(w http.ResponseWriter, r *http.Request, i RequestIdentity, op RoutedOperation, body []byte) bool {
	if !h.authority.Required(delegationTenant(i), i.credentialBinding.ID) && len(r.Header.Values(delegation.Header)) == 0 && len(r.Header.Values(delegation.TaskHeader)) == 0 {
		return true
	}
	name := ""
	if op.OperationID == "callMCPGateway" && !hasMCPRoutingHeaders(r) {
		name = delegation.MCPOperation(body)
		if name != "" {
			var method string
			if strings.HasPrefix(name, "mcp:") {
				method = strings.TrimPrefix(name, "mcp:")
			} else {
				method = "tools/call"
			}
			if m := r.Header.Get("Mcp-Method"); m != "" && m != method {
				name = ""
			}
			if n := r.Header.Get("Mcp-Name"); n != "" && (method != "tools/call" || n != name) {
				name = ""
			}
		}
	}
	return h.enforceDelegation(w, r, i, op.OperationID, name, op.PathParameters["id"])
}

func (h *hostedGatewayHandler) enforceDelegation(w http.ResponseWriter, r *http.Request, i RequestIdentity, op, name, resource string) bool {
	t, cred := delegationTenant(i), i.credentialBinding.ID
	tokens, tasks := r.Header.Values(delegation.Header), r.Header.Values(delegation.TaskHeader)
	if !h.authority.Required(t, cred) && len(tokens) == 0 && len(tasks) == 0 {
		return true
	}
	if h.authority == nil || h.authority.AgentID(t, cred) == "" {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return false
	}
	task, token := r.Header.Get(delegation.TaskHeader), r.Header.Get(delegation.Header)
	d := h.authority.Check(t, cred, task, token, name, resource, time.Now())
	if len(tokens) > 1 || len(tasks) > 1 {
		d = delegation.Decision{Status: "denied"}
	}
	if token == "" && h.authority.Required(t, cred) {
		d = delegation.Decision{Status: "delegation_unverified"}
	}
	if !delegation.ValidIdentifier(task) {
		task = ""
	}
	if !h.saveDelegation(w, r, i, op, task, token, d.Status, "", nil) {
		return false
	}
	w.Header().Set("X-Zasp-Delegation-Status", d.Status)
	if !d.Allowed {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return false
	}
	return true
}

func hasMCPRoutingHeaders(r *http.Request) bool {
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "mcp-param-") {
			return true
		}
	}
	// Require unambiguous method and name headers if a modern client includes them.
	if len(r.Header.Values("Mcp-Method")) > 1 || len(r.Header.Values("Mcp-Name")) > 1 {
		return true
	}
	return false
}

func grantDigest(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
