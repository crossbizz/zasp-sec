package apiserver

import (
	"encoding/json"
	"net/http"
)

const postureSummarySQL = "SELECT zasp_authorization80.agent_posture_with_sync($1,$2,$3,$4)"

func init() {
	productStatementRules[postureSummarySQL] = productStatementRule{operations: []string{"getAgentPostureSummary"}, arguments: 4, scope: 1, object: 4, kind: "agent", browserOnly: true}
}

func serveAgentPosture(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := IdentityFromRequest(r)
	if !ok || actor.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := route.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" || r.Method != http.MethodGet {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := actor.Scope
	raw, err := db.QueryJSON(r.Context(), postureSummarySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	var result struct {
		AgentID string `json:"agent_id"`
		Kind    string `json:"deployment_kind"`
	}
	if json.Unmarshal(raw, &result) != nil || result.AgentID != id || !stringIn(result.Kind, "repo_code", "deployed_agent", "unknown") {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}
