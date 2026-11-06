package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAgentOwnerPageSQL = `SELECT zasp_agent_owner_filter_v1.page($1,$2,$3,NULLIF($4,''),$5,$6,$7)`

type agentOwnerPageRepository interface {
	ListAgentOwnerPage(context.Context, domain.Scope, string, string, int) (InventoryPage, error)
}

func validAgentOwnerReadLabel(s string) bool {
	if !utf8.ValidString(s) || len(s) > 512 || utf8.RuneCountInString(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

type agentOwnerCursor struct {
	Version      int    `json:"v"`
	Organization string `json:"o"`
	Workspace    string `json:"w"`
	Environment  string `json:"e"`
	Operation    string `json:"op"`
	Kind         string `json:"k"`
	Parent       string `json:"p"`
	Limit        int    `json:"l"`
	After        string `json:"a"`
	Filter       string `json:"f"`
}

func agentOwnerDigest(owner string) string {
	v, _ := json.Marshal([]any{"owner-filter-v1", true, owner})
	d := sha256.Sum256(v)
	return hex.EncodeToString(d[:])
}
func (h *inventoryHTTPHandler) ownerCursor(scope domain.Scope, owner, after string, limit int) string {
	raw, _ := json.Marshal(agentOwnerCursor{2, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "listAgents", "agent", "", limit, after, agentOwnerDigest(owner)})
	m := hmac.New(sha256.New, h.signingKey)
	_, _ = m.Write([]byte("agent-owner-page-v2\x00"))
	_, _ = m.Write(raw)
	return base64.RawURLEncoding.EncodeToString(append(raw, m.Sum(nil)...))
}
func (h *inventoryHTTPHandler) decodeOwnerCursor(value string, scope domain.Scope, owner string, limit int) (string, bool) {
	if len(value) > 512 {
		return "", false
	}
	raw, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != value || len(raw) <= sha256.Size {
		return "", false
	}
	p, sig := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	m := hmac.New(sha256.New, h.signingKey)
	_, _ = m.Write([]byte("agent-owner-page-v2\x00"))
	_, _ = m.Write(p)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return "", false
	}
	var c agentOwnerCursor
	if decodeStrictInventory(p, &c) != nil || c.Version != 2 || c.Organization != scope.OrganizationID().String() || c.Workspace != scope.WorkspaceID().String() || c.Environment != scope.EnvironmentID().String() || c.Operation != "listAgents" || c.Kind != "agent" || c.Parent != "" || c.Limit != limit || c.Filter != agentOwnerDigest(owner) || !validProductID(c.After) {
		return "", false
	}
	return c.After, true
}

// Returns true for every request carrying an owner key, including rejected forms.
func (h *inventoryHTTPHandler) agentOwnerPage(w http.ResponseWriter, r *http.Request, identity RequestIdentity) bool {
	values, e := parseOwnerQueryPresence(r.URL.RawQuery)
	if e != nil {
		writeProductionError(w, r, ErrRepositoryOperation)
		return true
	}
	if !values {
		return false
	}
	query, ok := exactWorkflowQuery(r.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3, "owner": 512})
	if !ok || r.Method != http.MethodGet {
		h.writePageQueryError(w, r)
		return true
	}
	owners, exists := query["owner"]
	if !exists || len(owners) != 1 || !validAgentOwnerReadLabel(owners[0]) {
		h.writePageQueryError(w, r)
		return true
	}
	owner := owners[0]
	limit, ok := workflowPageLimit(query)
	if !ok {
		h.writePageQueryError(w, r)
		return true
	}
	after := ""
	if v, has := query["cursor"]; has {
		if len(v) != 1 || v[0] == "" {
			h.writePageQueryError(w, r)
			return true
		}
		after, ok = h.decodeOwnerCursor(v[0], identity.Scope, owner, limit)
		if !ok {
			h.writePageQueryError(w, r)
			return true
		}
	}
	repository, ok := h.repository.(agentOwnerPageRepository)
	if !ok {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return true
	}
	page, err := repository.ListAgentOwnerPage(r.Context(), identity.Scope, owner, after, limit)
	if err != nil {
		writeProductionError(w, r, err)
		return true
	}
	info := map[string]any{"next_cursor": nil, "has_more": false}
	if page.NextKey != "" {
		info["next_cursor"] = h.ownerCursor(identity.Scope, owner, page.NextKey, limit)
		info["has_more"] = true
	}
	writeJSONValue(w, r, http.StatusOK, map[string]any{"items": page.Items, "page_info": info}, nil)
	return true
}
func (r *PostgresInventoryRepository) ListAgentOwnerPage(ctx context.Context, scope domain.Scope, owner, after string, limit int) (InventoryPage, error) {
	if r == nil || r.agentOwnerProfileChecksum == "" {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	if !validInventoryCall(r, ctx, scope, InventoryKindAgent, after, limit) || !validAgentOwnerReadLabel(owner) {
		return InventoryPage{}, ErrRepositoryOperation
	}
	payload, e := r.database.QueryJSON(ctx, postgresAgentOwnerPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), after, limit, owner, r.agentOwnerProfileChecksum)
	if e != nil {
		return InventoryPage{}, inventoryProviderError(e)
	}
	var env struct {
		Items  []InventorySummary `json:"items"`
		NextID *string            `json:"next_id"`
	}
	if decodeStrictInventory(payload, &env) != nil || env.Items == nil || len(env.Items) > limit {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for _, v := range env.Items {
		if !validInventorySummary(v, InventoryKindAgent) || v.Owner != owner || prior != "" && v.ID <= prior {
			return InventoryPage{}, ErrRepositoryUnavailable
		}
		prior = v.ID
	}
	next, ok := validInventoryNextKey(env.NextID, prior, len(env.Items), limit)
	if !ok {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	return InventoryPage{Items: env.Items, NextKey: next}, nil
}
func (r *PostgresRepository) RequireAgentOwnerFilterProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsAgentOwnerFilterProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentOwnerProfileChecksum = pin
	return nil
}

func parseOwnerQueryPresence(raw string) (bool, error) {
	q, e := url.ParseQuery(raw)
	if e != nil {
		return false, e
	}
	_, ok := q["owner"]
	return ok, nil
}
func ownerFilterStatementArguments(args []any) bool {
	if len(args) != 7 {
		return false
	}
	after, aok := args[3].(string)
	limit, lok := args[4].(int)
	owner, ook := args[5].(string)
	pin, pok := args[6].(string)
	return aok && (after == "" || validProductID(after)) && lok && limit >= 1 && limit <= 100 && ook && validAgentOwnerReadLabel(owner) && pok && migrations.IsAgentOwnerFilterProfileChecksum(pin)
}
func (d *PostgresJSONDatabase) AgentOwnerFilterProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsAgentOwnerFilterProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if e := d.driver.QueryRow(ctx, `SELECT zasp_agent_owner_filter_v1.caller_ready($1)`, pin).Scan(&ready); e != nil {
		return false, classifyPostgresError(e)
	}
	return ready, nil
}
