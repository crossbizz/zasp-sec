package apiserver

import (
	"encoding/json"
	"net/http"
	"sort"
)

const purposeGetSQL = `SELECT zasp_authorization80.agent_purpose_get($1,$2,$3,$4)`
const purposePutSQL = `SELECT zasp_authorization80.agent_purpose_put($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`

func init() {
	productStatementRules[purposeGetSQL] = productStatementRule{operations: []string{"getAgentPurpose"}, arguments: 4, scope: 1, object: 4, kind: "agent", browserOnly: true}
	productStatementRules[purposePutSQL] = productStatementRule{operations: []string{"putAgentPurpose"}, arguments: 8, scope: 1, actor: 4, object: 5, kind: "agent", browserOnly: true}
}

type agentPurpose struct {
	AgentID        string   `json:"agent_id"`
	Revision       int64    `json:"revision"`
	AllowedToolIDs []string `json:"allowed_tool_ids"`
	UpdatedAt      *string  `json:"updated_at"`
}

func serveAgentPurpose(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(r)
	if !ok || identity.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := route.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := identity.Scope
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	query := purposeGetSQL
	switch route.OperationID {
	case "getAgentPurpose":
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		args = append(args, id)
	case "putAgentPurpose":
		key, n, ok := discoveryMutationHeaders(r, true)
		var raw json.RawMessage
		var in struct {
			Tools []string `json:"allowed_tool_ids"`
		}
		if r.Method != http.MethodPut || !ok || n >= 1000000 || decodeProductionJSON(r, &raw) != nil || !validAgentExportContentJSON(string(raw)) || !exactJSONFields(raw, "allowed_tool_ids") || json.Unmarshal(raw, &in) != nil || in.Tools == nil || len(in.Tools) > 64 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		sort.Strings(in.Tools)
		for j, v := range in.Tools {
			if !validProductID(v) || j > 0 && in.Tools[j-1] == v {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
		}
		tools, _ := json.Marshal(in.Tools)
		args = append(args, identity.PrincipalID.String(), id, key, n, string(tools))
		query = purposePutSQL
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := db.QueryJSON(r.Context(), query, args...)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	if string(raw) == `"conflict"` {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var record agentPurpose
	if json.Unmarshal(raw, &record) != nil || record.AgentID != id || record.Revision < 0 || record.AllowedToolIDs == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	w.Header().Set("ETag", quoteVersion(record.Revision))
	writeProductionResponse(w, r, 200, raw, nil)
}
