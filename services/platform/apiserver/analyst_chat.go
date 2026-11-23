package apiserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

const chatThreadsSQL = `SELECT zasp_authorization80.analyst_threads($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const chatTurnSQL = `SELECT zasp_authorization80.analyst_turn($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb)`

type analystChat struct {
	driver  aigateway.ProviderDriver
	binding aigateway.BedrockBinding
}

func analystChatOperation(op string) bool {
	return stringIn(op, "getAnalystThreads", "createAnalystThread", "getAnalystThread", "streamAnalystThread")
}

func init() {
	scope := func(g RequestAuthorization, args []any) bool {
		s, ok := args[4].(string)
		return ok && authorizationNativeTargetAllowed(g, "session", s)
	}
	productStatementRules[chatThreadsSQL] = productStatementRule{operations: []string{"getAnalystThreads", "createAnalystThread", "getAnalystThread"}, arguments: 9, scope: 1, actor: 4, browserOnly: true, check: func(g RequestAuthorization, args []any) bool {
		return scope(g, args) && args[5] == g.OperationID && (g.OperationID != "getAnalystThread" || args[6] == g.PathParameters["id"])
	}}
	productStatementRules[chatTurnSQL] = productStatementRule{operations: []string{"streamAnalystThread"}, arguments: 9, scope: 1, actor: 4, browserOnly: true, check: func(g RequestAuthorization, args []any) bool {
		return scope(g, args) && args[5] == g.PathParameters["id"]
	}}
}

// Only an operator-mounted Bedrock credential can activate a driver. Invalid
// or missing settings keep investigation unavailable without touching Tier 1.
func configuredAnalystChat() *analystChat {
	return configuredPrivateModel(aigateway.PurposeTriage, "ZASP_BEDROCK_TRIAGE_")
}

func chatError(w http.ResponseWriter, r *http.Request, raw json.RawMessage, err error) bool {
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return true
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
	case `"disabled"`:
		writeProductionStatusError(w, r, 409, "ai_disabled_by_policy", "A qualified private investigation model and session investigation controls are required", false)
	case `"limit"`, `"budget"`:
		writeProductionStatusError(w, r, 409, "investigation_limit", "The thread or Environment investigation limit has been reached", false)
	case `"conflict"`:
		writeProductionStatusError(w, r, 409, "investigation_conflict", "An investigation is pending or this request ID has already been used", false)
	case `"no_evidence"`:
		writeProductionStatusError(w, r, 409, "session_evidence_missing", "This session has no linked evidence to investigate", false)
	case `"ineligible"`:
		writeProductionError(w, r, ErrRepositoryOperation)
	default:
		return false
	}
	return true
}

type analystThread struct {
	ID       string           `json:"id"`
	Session  string           `json:"session_id"`
	Created  time.Time        `json:"created_at"`
	Messages []analystMessage `json:"messages,omitempty"`
}
type analystMessage struct {
	ID          string    `json:"id"`
	Role        string    `json:"role"`
	Text        string    `json:"text"`
	Created     time.Time `json:"created_at"`
	EvidenceIDs []string  `json:"evidence_ids"`
}

func validChatHistory(op, s, t string, raw json.RawMessage) bool {
	var rows []analystThread
	if op == "getAnalystThreads" {
		var page struct {
			Items []analystThread `json:"items"`
		}
		if decodeStrictDiscovery(raw, &page) != nil || page.Items == nil || len(page.Items) > 50 {
			return false
		}
		rows = page.Items
	} else {
		var value analystThread
		if decodeStrictDiscovery(raw, &value) != nil || (op == "getAnalystThread" && (value.ID != t || value.Messages == nil)) {
			return false
		}
		rows = []analystThread{value}
	}
	for _, row := range rows {
		if !validProductID(row.ID) || row.Session != s || row.Created.IsZero() || len(row.Messages) > 48 {
			return false
		}
		for _, m := range row.Messages {
			if !validProductID(m.ID) || !stringIn(m.Role, "assistant", "user") || m.Created.IsZero() || m.Text == "" || m.EvidenceIDs == nil || len(m.EvidenceIDs) > 6 {
				return false
			}
		}
	}
	return true
}

func serveAnalystChat(db JSONDatabase, h *analystChat, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	q, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"session_id": 40})
	s := q.Get("session_id")
	if !ok || !validProductID(s) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	sc := i.Scope
	args := []any{sc.OrganizationID().String(), sc.WorkspaceID().String(), sc.EnvironmentID().String(), i.PrincipalID.String(), s}
	t := route.PathParameters["id"]
	if route.OperationID == "streamAnalystThread" {
		serveAnalystTurn(db, h, w, r, route, args)
		return
	}
	var studio, revision any
	if route.OperationID == "createAnalystThread" {
		var req struct {
			Session  string  `json:"session_id"`
			Studio   *string `json:"studio_id"`
			Revision *int64  `json:"studio_revision"`
		}
		t = r.Header.Get("Idempotency-Key")
		if r.Method != http.MethodPost || len(r.Header.Values("Idempotency-Key")) != 1 || !workflowKeyPattern.MatchString(t) || len(t) < 16 || len(t) > 128 || decodeProductionJSON(r, &req) != nil || req.Session != s || (req.Studio == nil) != (req.Revision == nil) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		if req.Studio != nil {
			if !validProductID(*req.Studio) || *req.Revision < 1 {
				writeProductionError(w, r, ErrRepositoryOperation)
				return
			}
			studio, revision = *req.Studio, *req.Revision
		}
	} else if r.Method != http.MethodGet {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	raw, err := db.QueryJSON(r.Context(), chatThreadsSQL, append(args, route.OperationID, t, studio, revision)...)
	if chatError(w, r, raw, err) {
		return
	}
	if !validChatHistory(route.OperationID, s, t, raw) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}

func validQuestion(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && utf8.ValidString(s) && utf8.RuneCountInString(s) <= 1000 && !strings.ContainsRune(s, '\x00')
}
