package apiserver

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	currentWorkloadBindingWriteSQL = "SELECT zasp_authorization80.workload_binding($1,$2,$3,$4,$5,$6)"
	currentWorkloadBindingReadSQL  = "SELECT zasp_authorization80.workload_binding($1,$2,$3,$4,$5,NULL)"
)

type workloadBinding struct {
	Credential string    `json:"credential_id"`
	Agent      string    `json:"agent_id"`
	Session    string    `json:"session_id"`
	Source     string    `json:"source"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	Error      string    `json:"error,omitempty"`
}

func workloadBindingStatementAllowed(g RequestAuthorization, args []any) bool {
	if !authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) {
		return false
	}
	if g.OperationID == "bindWorkloadCredential" {
		agent, ok := args[5].(string)
		return ok && validProductID(agent)
	}
	return g.OperationID == "getWorkloadCredentialBinding"
}

func (h *workloadActionHandler) binding(w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	id := op.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	q := currentWorkloadBindingReadSQL
	args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), id}
	switch op.OperationID {
	case "bindWorkloadCredential":
		var body struct {
			Agent string `json:"agent_id"`
		}
		if r.Method != http.MethodPut || !i.FreshAuthenticated || decodeProductionJSON(r, &body) != nil || !validProductID(body.Agent) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		q = currentWorkloadBindingWriteSQL
		args = append(args, body.Agent)
	case "getWorkloadCredentialBinding":
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := h.database.QueryJSON(r.Context(), q, args...)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	var value workloadBinding
	if decodeStrictDiscovery(raw, &value) != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	switch value.Error {
	case "ineligible_binding", "unknown_binding":
		writeProductionError(w, r, ErrRepositoryNotFound)
	case "binding_conflict":
		writeProductionStatusError(w, r, 409, "binding_conflict", "This token already belongs to another workload", false)
	case "":
		if value.Credential != id || !validProductID(value.Agent) || !validProductID(value.Session) || value.Source != "administrator_bound_credential" || !validProductID(value.CreatedBy) || value.CreatedAt.IsZero() {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(w, r, http.StatusOK, raw, nil)
	default:
		writeProductionError(w, r, ErrRepositoryUnavailable)
	}
}

const currentWorkloadContainSQL = "SELECT zasp_authorization80.workload_containment($1,$2,$3,$4,$5,$6,$7)"

func workloadControlStatementAllowed(g RequestAuthorization, args []any) bool {
	if args[5] != g.PathParameters["runId"] || !validProductID(g.PathParameters["runId"]) || !authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) {
		return false
	}
	if g.OperationID == "authorizeWorkloadContainment" {
		id, ok := args[6].(string)
		return g.Identity.FreshAuthenticated && ok && validProductID(id)
	}
	return args[6] == nil && (g.OperationID == "getWorkloadContainment" || g.OperationID == "releaseWorkloadContainment" && g.Identity.FreshAuthenticated)
}

func (h *workloadActionHandler) containment(w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	id, run := op.PathParameters["id"], op.PathParameters["runId"]
	if !validProductID(id) || !validProductID(run) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var step any
	switch op.OperationID {
	case "authorizeWorkloadContainment":
		var body struct {
			Step string `json:"step_id"`
		}
		if r.Method != http.MethodPut || !i.FreshAuthenticated || decodeProductionJSON(r, &body) != nil || !validProductID(body.Step) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		step = body.Step
	case "releaseWorkloadContainment":
		if r.Method != http.MethodDelete || !i.FreshAuthenticated || requireZeroByteInput(r) != nil {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	case "getWorkloadContainment":
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := h.database.QueryJSON(r.Context(), currentWorkloadContainSQL, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), id, run, step)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	var msg struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	switch msg.Error {
	case "unknown_binding", "unknown_control", "unverified_source":
		writeProductionError(w, r, ErrRepositoryNotFound)
	case "containment_conflict":
		writeProductionError(w, r, ErrRepositoryConflict)
	case "":
		if !exactJSONFields(raw, "credential_id", "run_id", "step_id", "session_id", "approval_id", "authorized_by", "authorized_at", "expires_at", "state", "block_receipt_id", "release_receipt_id") {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(w, r, http.StatusOK, raw, nil)
	default:
		writeProductionError(w, r, ErrRepositoryUnavailable)
	}
}
