package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/inventorymcp"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionintent"
)

type analystTurn struct {
	ExternalAgent string                  `json:"external_agent_id,omitempty"`
	AssistantID   string                  `json:"assistant_id"`
	Text          string                  `json:"text"`
	Evidence      []sessionActionEvidence `json:"evidence"`
	EvidenceIDs   []string                `json:"evidence_ids"`
}

func (f analystTurn) answered() bool {
	if !validProductID(f.AssistantID) || f.Text == "" || len(f.EvidenceIDs) == 0 || len(f.EvidenceIDs) > 6 || f.Evidence != nil || f.ExternalAgent != "" {
		return false
	}
	for _, id := range f.EvidenceIDs {
		if !validProductID(id) {
			return false
		}
	}
	return true
}

func validTurnApprovals(values []string) bool {
	if len(values) > 2 {
		return false
	}
	slices.Sort(values)
	for n, s := range values {
		if s != "inspect_session" && s != inventorymcp.Tool || n > 0 && s == values[n-1] {
			return false
		}
	}
	return true
}

func serveAnalystTurn(db JSONDatabase, h *analystChat, w http.ResponseWriter, r *http.Request, op RoutedOperation, args []any) {
	id := op.PathParameters["id"]
	var msg struct {
		Approved  []string `json:"approved_read_tools,omitempty"`
		Message   string   `json:"message"`
		RequestID string   `json:"request_id"`
	}
	if r.Method != http.MethodPost || !validProductID(id) || decodeProductionJSON(r, &msg) != nil || !validQuestion(msg.Message) || !validProductID(msg.RequestID) || !validTurnApprovals(msg.Approved) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if len(msg.Approved) > 0 {
		identity, ok := IdentityFromRequest(r)
		if !ok || !identity.FreshAuthenticated {
			writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
			return
		}
	}
	assistant, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	var binding any
	if h != nil {
		binding, _ = json.Marshal(h.binding)
	}
	args = append(args, id, msg.RequestID)
	query := func(ctx context.Context, q map[string]any) (json.RawMessage, error) {
		payload, _ := json.Marshal(q)
		return db.QueryJSON(ctx, chatTurnSQL, append(args, json.RawMessage(payload), binding)...)
	}
	start := map[string]any{"phase": "start", "question": msg.Message, "assistant_id": assistant}
	if len(msg.Approved) > 0 {
		start["approved_read_tools"] = msg.Approved
	}
	raw, err := query(r.Context(), start)
	if chatError(w, r, raw, err) {
		return
	}
	var turn analystTurn
	if decodeStrictDiscovery(raw, &turn) != nil || !validProductID(turn.AssistantID) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	if turn.answered() {
		writeAnalystSSE(w, turn)
		return
	}
	if h == nil || h.driver == nil || turn.AssistantID != assistant || len(turn.Evidence) < 1 || len(turn.Evidence) > 101 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	inventoryStatus := ""
	if turn.ExternalAgent != "" || slices.Contains(msg.Approved, inventorymcp.Tool) {
		if !validProductID(turn.ExternalAgent) || !slices.Contains(msg.Approved, inventorymcp.Tool) {
			writeProductionError(w, r, ErrRepositoryAuthorization)
			return
		}
		inventoryStatus, err = studioInventoryStatus(r, op, turn.ExternalAgent, turn.Evidence, h.inventoryStatus)
		if err != nil {
			_, _ = query(r.Context(), map[string]any{"phase": "fail", "assistant_id": assistant})
			writeProductionStatusError(w, r, http.StatusServiceUnavailable, "coverage_degraded", "The private inventory status could not be verified for this session agent", true)
			return
		}
	}
	answer, err := investigateAuthorizedRowsWithInventory(r.Context(), h, msg.Message, turn.Evidence, inventoryStatus)
	if err != nil {
		_, _ = query(r.Context(), map[string]any{"phase": "fail", "assistant_id": assistant})
		writeProductionStatusError(w, r, http.StatusServiceUnavailable, "coverage_degraded", "The private investigation model did not return a verified response", true)
		return
	}
	switch inventoryStatus {
	case "present":
		answer.Text += "\n\nThe private inventory lists this agent."
	case "not_listed":
		answer.Text += "\n\nThe private inventory reports that this agent is absent from its records."
	case "unknown":
		answer.Text += "\n\nThe private inventory reports this agent’s status as unknown."
	}
	ctx, err := refreshChatAuthorization(r, op)
	if err != nil {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	raw, err = query(ctx, map[string]any{"phase": "finish", "assistant_id": assistant, "text": answer.Text, "evidence_ids": answer.EvidenceIDs})
	if chatError(w, r, raw, err) {
		return
	}
	var completed analystTurn
	if decodeStrictDiscovery(raw, &completed) != nil || !completed.answered() || completed.AssistantID != assistant {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeAnalystSSE(w, completed)
}

func refreshChatAuthorization(r *http.Request, op RoutedOperation) (context.Context, error) {
	ctx := r.Context()
	i, ok := IdentityFromRequest(r)
	a, available := ctx.Value(requestAuthorizerContextKey{}).(RequestAuthorizer)
	if !ok || !available || nilInterface(a) {
		return nil, ErrRepositoryAuthorization
	}
	g, err := a.Authorize(context.WithValue(ctx, authorizationQueryContextKey{}, r.URL.Query()), i, i.credentialBinding, op)
	if err != nil || g.OperationID != op.OperationID || g.Identity.Scope != i.Scope || g.Identity.PrincipalID != i.PrincipalID {
		return nil, ErrRepositoryAuthorization
	}
	return context.WithValue(ctx, requestAuthorizationContextKey{}, g), nil
}

func investigateAuthorizedRows(ctx context.Context, h *analystChat, question string, rows []sessionActionEvidence) (securityagent.InvestigationResult, error) {
	return investigateAuthorizedRowsWithInventory(ctx, h, question, rows, "")
}

func investigateAuthorizedRowsWithInventory(ctx context.Context, h *analystChat, question string, rows []sessionActionEvidence, inventoryStatus string) (securityagent.InvestigationResult, error) {
	actions := make([]securityagent.InvestigationAction, 0, len(rows))
	for _, row := range rows {
		if !validProductID(row.ID) || len(row.EvidenceIDs) < 1 || len(row.EvidenceIDs) > 2 {
			return securityagent.InvestigationResult{}, ErrRepositoryUnavailable
		}
		evidenceID := row.EvidenceIDs[len(row.EvidenceIDs)-1]
		if !validProductID(evidenceID) {
			return securityagent.InvestigationResult{}, ErrRepositoryUnavailable
		}
		actions = append(actions, securityagent.InvestigationAction{ID: evidenceID, Source: row.Source, Outcome: string(sessionintent.Evaluate(row.Source, row.Class, row.Action, row.Receipt))})
	}
	return securityagent.InvestigateSessionWithInventory(ctx, h.driver, question, actions, inventoryStatus)
}

// Send only committed responses. Reconnecting with the same request ID replays
// the same server message, even when the original connection ended mid-frame.
func writeAnalystSSE(w http.ResponseWriter, t analystTurn) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Vercel-AI-UI-Message-Stream", "v1")
	w.WriteHeader(http.StatusOK)
	flush := http.NewResponseController(w)
	part := t.AssistantID + "/text"
	frames := []map[string]any{{"type": "start", "messageId": t.AssistantID}, {"type": "text-start", "id": part}, {"type": "text-delta", "id": part, "delta": t.Text}, {"type": "text-delta", "id": part, "delta": "\n\nEvidence: " + strings.Join(t.EvidenceIDs, ", ")}, {"type": "text-end", "id": part}, {"type": "finish", "finishReason": "stop"}}
	for _, f := range frames {
		raw, _ := json.Marshal(f)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
			return
		}
		_ = flush.Flush()
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	_ = flush.Flush()
}

// Admission identifies one agent from exact local observations. Recheck both
// the current session grant and the agent's own product read before sending
// any identifiers to the operator-bound peer.
func studioInventoryStatus(r *http.Request, op RoutedOperation, agent string, rows []sessionActionEvidence, read func(context.Context, inventorymcp.Target) (string, error)) (string, error) {
	if len(rows) == 0 || !validProductID(agent) {
		return "", ErrRepositoryAuthorization
	}
	for _, row := range rows {
		if row.AgentID == nil || *row.AgentID != agent || row.Confidence != "exact" {
			return "", ErrRepositoryAuthorization
		}
	}
	ctx, err := refreshChatAuthorization(r, op)
	i, ok := IdentityFromRequest(r)
	if err != nil || !ok || i.CredentialKind != CredentialBrowserSession || !i.FreshAuthenticated {
		return "", ErrRepositoryAuthorization
	}
	agentRoute := RoutedOperation{OperationID: "getAgent", PathParameters: map[string]string{"id": agent}}
	if _, err := secondaryRequestAuthorization(ctx, i, agentRoute); err != nil {
		return "", err
	}
	status, raw := dispatchScopedProduct(r.WithContext(ctx), http.MethodGet, "/api/v1/agents/"+agent, nil, nil, "")
	var item InventoryDetail
	if status != http.StatusOK || json.Unmarshal(raw, &item) != nil || item.Summary.ID != agent || item.Summary.Kind != InventoryKindAgent {
		return "", ErrRepositoryAuthorization
	}
	if read == nil {
		c, err := inventorymcp.Load(os.Getenv("ZASP_STUDIO_INVENTORY_MCP_FILE"))
		if err != nil {
			return "", err
		}
		read = c.Status
	}
	return read(ctx, inventorymcp.Target{Organization: i.Scope.OrganizationID().String(), Workspace: i.Scope.WorkspaceID().String(), Environment: i.Scope.EnvironmentID().String(), Agent: agent})
}
