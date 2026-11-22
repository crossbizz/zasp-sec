package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const suggestionListSQL = "SELECT zasp_authorization80.agent_suggestions_list($1,$2,$3,$4,$5)"
const suggestionRefreshSQL = "SELECT zasp_authorization80.agent_suggestions_refresh($1,$2,$3,$4,$5,$6,$7::jsonb)"
const suggestionReviewSQL = "SELECT zasp_authorization80.agent_suggestions_review($1,$2,$3,$4,$5,$6,$7,$8)"

func init() {
	productStatementRules[suggestionListSQL] = productStatementRule{operations: []string{"listAgentSuggestions"}, arguments: 5, scope: 1, object: 4, kind: "agent", browserOnly: true}
	productStatementRules[suggestionRefreshSQL] = productStatementRule{operations: []string{"refreshAgentSuggestions"}, arguments: 7, scope: 1, actor: 4, object: 5, kind: "agent", browserOnly: true}
	productStatementRules[suggestionReviewSQL] = productStatementRule{operations: []string{"reviewAgentSuggestion"}, arguments: 8, scope: 1, actor: 4, object: 5, kind: "agent", browserOnly: true, check: func(auth RequestAuthorization, args []any) bool {
		tool, ok := args[6].(string)
		return ok && tool == auth.PathParameters["toolId"]
	}}
}

func isSuggestionOperation(op string) bool {
	return op == "listAgentSuggestions" || op == "refreshAgentSuggestions" || op == "reviewAgentSuggestion"
}

type observedToolEvent struct {
	Tool    string `json:"tool"`
	Event   string `json:"event"`
	Session string `json:"session"`
}
type suggestionScan struct {
	From      time.Time           `json:"from"`
	To        time.Time           `json:"to"`
	Examined  int                 `json:"examined"`
	Truncated bool                `json:"truncated"`
	Events    []observedToolEvent `json:"events"`
}

func (h *PolicyPublicHTTPHandler) suggestions(w http.ResponseWriter, r *http.Request, user RequestIdentity, route RoutedOperation) {
	if h.config.EvidenceDB == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	id := route.PathParameters["id"]
	if user.CredentialKind != CredentialBrowserSession || !validProductID(id) {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	scope := user.Scope
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	var stmt string
	switch route.OperationID {
	case "listAgentSuggestions":
		q := r.URL.Query()
		after := q.Get("after_tool_id")
		if r.Method != http.MethodGet || r.URL.RawQuery != "" && (len(q) != 1 || len(q["after_tool_id"]) != 1 || !validProductID(after)) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		stmt = suggestionListSQL
		args = append(args, id, after)
	case "refreshAgentSuggestions":
		var in struct {
			Revision int64     `json:"purpose_revision"`
			From     time.Time `json:"from"`
			To       time.Time `json:"to"`
		}
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || decodeProductionJSON(r, &in) != nil || in.Revision < 1 || in.Revision > 1000000 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		window := policy.ReplayWindow{AgentID: id, From: in.From, To: in.To}
		if !window.Valid() || in.To.After(time.Now()) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		history, ok := h.config.History.(interface {
			SearchReplayActions(context.Context, domain.Scope, string, policy.ReplayWindow) ([]policy.ActionContext, bool, error)
		})
		if !ok {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		actions, truncated, err := history.SearchReplayActions(r.Context(), scope, "tool", window)
		if err != nil || len(actions) > 100 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		scan := suggestionScan{From: in.From.UTC(), To: in.To.UTC(), Examined: len(actions), Truncated: truncated, Events: []observedToolEvent{}}
		seen := make(map[string]observedToolEvent)
		for _, act := range actions {
			if act.AgentID != id || act.Action != "tool" || act.EnvironmentID != scope.EnvironmentID().String() {
				writeProductionError(w, r, ErrRepositoryUnavailable)
				return
			}
			// A workload fallback or free-text tool name cannot identify an inventory tool.
			if validProductID(act.EventID) && validProductID(act.SessionID) && validProductID(act.ToolID) && act.Resource == act.ToolID {
				source := observedToolEvent{act.ToolID, act.EventID, act.SessionID}
				if prior, exists := seen[act.EventID]; exists {
					if prior != source {
						writeProductionError(w, r, ErrRepositoryUnavailable)
						return
					}
					continue
				}
				seen[act.EventID] = source
				scan.Events = append(scan.Events, source)
			}
		}
		body, _ := json.Marshal(scan)
		stmt = suggestionRefreshSQL
		args = append(args, user.PrincipalID.String(), id, in.Revision, string(body))
	case "reviewAgentSuggestion":
		var in struct {
			Revision int64  `json:"purpose_revision"`
			Decision string `json:"decision"`
		}
		tool := route.PathParameters["toolId"]
		if r.Method != http.MethodPut || r.URL.RawQuery != "" || !validProductID(tool) || decodeProductionJSON(r, &in) != nil || in.Revision < 1 || in.Revision > 1000000 || in.Decision != "request_draft" && in.Decision != "dismiss" {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		stmt = suggestionReviewSQL
		args = append(args, user.PrincipalID.String(), id, in.Revision, tool, in.Decision)
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	result, err := h.config.EvidenceDB.QueryJSON(r.Context(), stmt, args...)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	switch string(result) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var p struct {
		Agent    string            `json:"agent_id"`
		IDs      []json.RawMessage `json:"items"`
		Revision int64             `json:"purpose_revision"`
	}
	if json.Unmarshal(result, &p) != nil || p.Agent != id || p.IDs == nil || len(p.IDs) > 100 || p.Revision < 0 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, 200, result, nil)
}
