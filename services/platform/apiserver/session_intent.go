package apiserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sessionintent"
)

const sessionIntentSQL = `SELECT zasp_authorization80.session_intent($1,$2,$3,$4,$5)`

func init() {
	productStatementRules[sessionIntentSQL] = productStatementRule{operations: []string{"getSessionIntent"}, arguments: 5, scope: 1, actor: 4, object: 5, kind: "session", browserOnly: true}
}

type sessionActionEvidence struct {
	AgentID     *string   `json:"agent_id"`
	Confidence  string    `json:"confidence"`
	ID          string    `json:"decision_id"`
	Source      string    `json:"source"`
	Class       string    `json:"class"`
	Action      string    `json:"action"`
	Receipt     string    `json:"receipt"`
	Operation   string    `json:"operation"`
	ObservedAt  time.Time `json:"observed_at"`
	EvidenceIDs []string  `json:"evidence_ids"`
}

type sessionActionResult struct {
	ID          string                `json:"decision_id"`
	Source      string                `json:"source"`
	Operation   string                `json:"operation"`
	ObservedAt  time.Time             `json:"observed_at"`
	EvidenceIDs []string              `json:"evidence_ids"`
	Outcome     sessionintent.Outcome `json:"outcome"`
	Attention   bool                  `json:"attention"`
}

func projectSessionActions(rows []sessionActionEvidence) ([]sessionActionResult, error) {
	results := make([]sessionActionResult, 0, len(rows))
	for _, row := range rows {
		if !validProductID(row.ID) || !stringIn(row.Source, "gateway", "otlp", "tetragon", "authenticated_workload") || row.Operation == "" || row.ObservedAt.IsZero() || len(row.EvidenceIDs) < 1 || len(row.EvidenceIDs) > 2 {
			return nil, ErrRepositoryUnavailable
		}
		for _, id := range row.EvidenceIDs {
			if !validProductID(id) {
				return nil, ErrRepositoryUnavailable
			}
		}
		outcome := sessionintent.Evaluate(row.Source, row.Class, row.Action, row.Receipt)
		results = append(results, sessionActionResult{row.ID, row.Source, row.Operation, row.ObservedAt, row.EvidenceIDs, outcome, outcome == sessionintent.Unknown || row.Action == "block"})
	}
	return results, nil
}

func serveSessionIntent(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := route.PathParameters["id"]
	if r.Method != http.MethodGet || !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := i.Scope
	raw, err := db.QueryJSON(r.Context(), sessionIntentSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), i.PrincipalID.String(), id)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	if string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	var rows []sessionActionEvidence
	if decodeStrictDiscovery(raw, &rows) != nil || rows == nil || len(rows) > 101 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	truncated := len(rows) > 100
	if truncated {
		rows = rows[:100]
	}
	actions, err := projectSessionActions(rows)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	observations := make([]sessionintent.Observation, 0, len(rows))
	for _, row := range rows {
		if row.AgentID == nil || !validProductID(*row.AgentID) || !stringIn(row.Confidence, "exact", "strong") {
			continue
		}
		observations = append(observations, sessionintent.Observation{ID: row.ID, AgentID: *row.AgentID, Class: row.Class, Action: row.Action, Source: row.Source, At: row.ObservedAt})
	}
	writeJSONValue(w, r, 200, map[string]any{"session_id": id, "actions": actions, "truncated": truncated, "links": sessionintent.PossibleLinks(observations)}, nil)
}

// Historical runtime events have no downstream receipt. Preserve every field
// returned by the source-qualified repository, including sandbox lineage.
func runtimeEventOutcome(raw json.RawMessage) (json.RawMessage, error) {
	var keys map[string]json.RawMessage
	var event struct{ Source, Class, Action string }
	if json.Unmarshal(raw, &event) != nil || json.Unmarshal(raw, &keys) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if event.Class == "" || event.Source == "" {
		return raw, nil
	}
	keys["outcome"], _ = json.Marshal(sessionintent.Evaluate(event.Source, event.Class, event.Action, ""))
	return json.Marshal(keys)
}

func runtimePageOutcomes(raw json.RawMessage) (json.RawMessage, error) {
	var page map[string]json.RawMessage
	if json.Unmarshal(raw, &page) != nil {
		return nil, ErrRepositoryUnavailable
	}
	var events []json.RawMessage
	if json.Unmarshal(page["items"], &events) != nil || events == nil {
		return nil, ErrRepositoryUnavailable
	}
	for n, event := range events {
		v, err := runtimeEventOutcome(event)
		if err != nil {
			return nil, err
		}
		events[n] = v
	}
	page["items"], _ = json.Marshal(events)
	return json.Marshal(page)
}
