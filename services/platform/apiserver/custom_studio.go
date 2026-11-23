package apiserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	studioListSQL = "SELECT zasp_authorization80.studio_read($1,$2,$3,NULL,NULLIF($4,''),$5)"
	studioGetSQL  = "SELECT zasp_authorization80.studio_read($1,$2,$3,$4,NULL,1)"
	studioSaveSQL = "SELECT zasp_authorization80.studio_save($1,$2,$3,$4,$5,$6,$7,$8::jsonb)"
)

type studioDefinition struct {
	ApprovalTools     []string `json:"approval_required_tools,omitempty"`
	MinimumConfidence string   `json:"minimum_evidence_confidence,omitempty"`
	Name              string   `json:"name"`
	Mission           string   `json:"mission"`
	Trigger           string   `json:"trigger"`
	Tools             []string `json:"read_tools"`
	Proposal          string   `json:"proposal"`
	Approval          bool     `json:"require_approval"`
	Steps             int      `json:"max_steps"`
	Budget            int64    `json:"budget_nano_credits"`
	Model             string   `json:"model_pin"`
}

func init() {
	productStatementRules[studioListSQL] = productStatementRule{operations: []string{"listCustomSecurityAgents"}, arguments: 5, scope: 1, browserOnly: true, check: addonEnvAllowed}
	productStatementRules[studioGetSQL] = productStatementRule{operations: []string{"getCustomSecurityAgent"}, arguments: 4, scope: 1, object: 4, browserOnly: true, check: addonEnvAllowed}
	productStatementRules[studioSaveSQL] = productStatementRule{operations: []string{"createCustomSecurityAgent", "updateCustomSecurityAgent"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, fresh: true, check: func(g RequestAuthorization, args []any) bool {
		if !addonEnvAllowed(g, args) {
			return false
		}
		id, idOK := args[4].(string)
		n, nOK := args[6].(int64)
		return idOK && nOK && validProductID(id) && (g.OperationID == "createCustomSecurityAgent" && n == 0 || g.OperationID == "updateCustomSecurityAgent" && n > 0 && g.PathParameters["id"] == id)
	}}
}
func studioText(v string, max int, empty bool) bool {
	return (empty || v != "") && utf8.RuneCountInString(v) <= max && strings.TrimSpace(v) == v && strings.IndexFunc(v, unicode.IsControl) < 0
}
func (d studioDefinition) valid() bool {
	if !studioText(d.Name, 80, false) || !studioText(d.Mission, 512, false) || !studioText(d.Model, 128, true) || !d.Approval || d.Steps < 1 || d.Steps > 6 || d.Budget < 0 || d.Budget > 1000000000000 {
		return false
	}
	if !stringIn(d.Trigger, "manual", "finding_opened") || !stringIn(d.Proposal, "none", "propose_policy", "request_containment") || len(d.Tools) == 0 || len(d.Tools) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, tool := range d.Tools {
		if seen[tool] || !stringIn(tool, "list_agents", "get_posture_summary", "inspect_session", "get_addon_drift") {
			return false
		}
		seen[tool] = true
	}
	if d.MinimumConfidence != "" && !stringIn(d.MinimumConfidence, "strong", "exact") {
		return false
	}
	for _, tool := range d.ApprovalTools {
		if !seen[tool] {
			return false
		}
		delete(seen, tool)
	}
	return true
}
func studioPage(raw string) (string, int, bool) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return "", 0, false
	}
	for k, v := range query {
		if !stringIn(k, "cursor", "limit") || len(v) != 1 {
			return "", 0, false
		}
	}
	cursor := query.Get("cursor")
	limit := 25
	if query.Has("limit") {
		limit, err = strconv.Atoi(query.Get("limit"))
	}
	return cursor, limit, err == nil && limit >= 1 && limit <= 100 && (!query.Has("cursor") || validProductID(cursor))
}
func serveCustomStudio(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := IdentityFromRequest(r)
	if !ok || actor.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	scope := actor.Scope
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	if route.OperationID != "listCustomSecurityAgents" && r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	id := route.PathParameters["id"]
	switch route.OperationID {
	case "getCustomSecurityAgent":
		if !validProductID(id) || r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		body, err := db.QueryJSON(r.Context(), studioGetSQL, append(args, id)...)
		writeStudioResult(w, r, body, err, id, false)
	case "listCustomSecurityAgents":
		cursor, limit, ok := studioPage(r.URL.RawQuery)
		if !ok || r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		body, err := db.QueryJSON(r.Context(), studioListSQL, append(args, cursor, limit)...)
		writeStudioResult(w, r, body, err, "", true)
	case "createCustomSecurityAgent", "updateCustomSecurityAgent":
		if !actor.FreshAuthenticated {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
		saveStudioDefinition(db, w, r, route, append(args, actor.PrincipalID.String()))
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
	}
}
func validStudioFields(raw json.RawMessage) bool {
	fields := []string{"name", "mission", "trigger", "read_tools", "proposal", "require_approval", "max_steps", "budget_nano_credits", "model_pin"}
	var entries map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return false
	}
	for _, key := range []string{"approval_required_tools", "minimum_evidence_confidence"} {
		if v, ok := entries[key]; ok {
			if string(v) == "null" || key == "minimum_evidence_confidence" && string(v) == `""` {
				return false
			}
			fields = append(fields, key)
		}
	}
	return exactJSONFields(raw, fields...)
}
func saveStudioDefinition(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation, args []any) {
	var raw json.RawMessage
	var def studioDefinition
	if decodeProductionJSON(r, &raw) != nil || !validAgentExportContentJSON(string(raw)) || !validStudioFields(raw) || json.Unmarshal(raw, &def) != nil || !def.valid() {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	sort.Strings(def.Tools)
	sort.Strings(def.ApprovalTools)
	encoded, _ := json.Marshal(def)
	var id, key, expectedID string
	var n int64
	if route.OperationID == "createCustomSecurityAgent" {
		values := r.Header.Values("Idempotency-Key")
		if r.Method != http.MethodPost || len(values) != 1 || !validPublicIdempotency(values[0]) || len(r.Header.Values("If-Match")) != 0 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		generated, err := domain.NewProductID()
		if err != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		id, key = generated.String(), values[0]
	} else {
		var ok bool
		key, n, ok = discoveryMutationHeaders(r, false)
		id = route.PathParameters["id"]
		expectedID = id
		if !ok || n >= 1000000 || !validProductID(id) || r.Method != http.MethodPut {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	}
	body, err := db.QueryJSON(r.Context(), studioSaveSQL, append(args, id, key, n, string(encoded))...)
	writeStudioResult(w, r, body, err, expectedID, false)
}
func writeStudioResult(w http.ResponseWriter, r *http.Request, body json.RawMessage, err error, expectedID string, page bool) {
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	switch string(body) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	case `"unqualified"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	if page {
		var p struct {
			Items []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(body, &p) != nil || p.Items == nil || len(p.Items) > 100 {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
	} else {
		var v struct {
			ID         string           `json:"id"`
			Revision   int64            `json:"revision"`
			Definition studioDefinition `json:"definition"`
		}
		if json.Unmarshal(body, &v) != nil || !validProductID(v.ID) || (expectedID != "" && expectedID != v.ID) || v.Revision < 1 || !v.Definition.valid() {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		w.Header().Set("ETag", quoteVersion(v.Revision))
	}
	writeProductionResponse(w, r, http.StatusOK, body, nil)
}
