package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAgentExposurePageSQL = `SELECT zasp_agent_exposure_filter_v1.page($1,$2,$3,NULLIF($4,''),$5,$6::jsonb,$7)`
const postgresAgentExposureRiskSQL = `SELECT zasp_agent_exposure_filter_v1.resolve_risk($1,$2,$3,$4)`

type agentExposurePageRepository interface {
	AgentExposureFilterProfileChecksum() string
	ListAgentExposurePage(context.Context, domain.Scope, json.RawMessage, string, int) (InventoryPage, error)
}

// A flat token decoder preserves exact key presence and refuses duplicate,
// aliased, null or untyped selectors before any SQL or cursor processing.
func parseAgentExposureFilters(raw json.RawMessage) (map[string]string, bool) {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, false
	}
	result := map[string]string{}
	for d.More() {
		token, e := d.Token()
		key, ok := token.(string)
		if e != nil || !ok {
			return nil, false
		}
		if _, exists := result[key]; exists {
			return nil, false
		}
		var value any
		if d.Decode(&value) != nil {
			return nil, false
		}
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		switch key {
		case "owner":
			if !validAgentOwnerReadLabel(text) {
				return nil, false
			}
		case "risk":
			if !stringIn(text, "critical", "high", "medium", "low", "unknown") {
				return nil, false
			}
		case "execution":
			if !stringIn(text, "shell", "code", "shell_or_code", "unknown") {
				return nil, false
			}
		case "impact":
			if !stringIn(text, "high", "unknown") {
				return nil, false
			}
		default:
			return nil, false
		}
		result[key] = text
	}
	if end, e := d.Token(); e != nil || end != json.Delim('}') {
		return nil, false
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return result, true
}
func agentExposureQuery(raw string) (json.RawMessage, string, int, bool) {
	values, ok := exactWorkflowQuery(raw, map[string]int{"owner": 512, "risk": 8, "execution": 13, "impact": 7, "cursor": 512, "limit": 3})
	if !ok {
		return nil, "", 0, false
	}
	limit, ok := workflowPageLimit(values)
	if !ok {
		return nil, "", 0, false
	}
	selected := map[string]string{}
	for _, key := range []string{"owner", "risk", "execution", "impact"} {
		if v, present := values[key]; present {
			if len(v) != 1 || !utf8.ValidString(v[0]) {
				return nil, "", 0, false
			}
			selected[key] = v[0]
		}
	}
	encoded, _ := json.Marshal(selected)
	if _, ok = parseAgentExposureFilters(encoded); !ok {
		return nil, "", 0, false
	}
	cursor := ""
	if v, present := values["cursor"]; present {
		if len(v) != 1 || v[0] == "" {
			return nil, "", 0, false
		}
		cursor = v[0]
	}
	return encoded, cursor, limit, true
}
func agentExposureDigest(value any) string {
	b, _ := json.Marshal(value)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

type agentExposureCursor struct {
	Version int    `json:"v"`
	Scope   string `json:"s"`
	After   string `json:"a"`
	Limit   int    `json:"l"`
	Filters string `json:"f"`
	Profile string `json:"c"`
}

func (h *inventoryHTTPHandler) exposureCursor(scope domain.Scope, filters json.RawMessage, pin, after string, limit int) string {
	raw, _ := json.Marshal(agentExposureCursor{1, agentExposureDigest([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}), after, limit, agentExposureDigest(filters), pin})
	m := hmac.New(sha256.New, h.signingKey)
	_, _ = m.Write([]byte("agent-exposure-listAgents-agent-v1\x00"))
	_, _ = m.Write(raw)
	return base64.RawURLEncoding.EncodeToString(append(raw, m.Sum(nil)...))
}
func (h *inventoryHTTPHandler) decodeExposureCursor(value string, scope domain.Scope, filters json.RawMessage, pin string, limit int) (string, bool) {
	if len(value) > 512 {
		return "", false
	}
	raw, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != value || len(raw) <= sha256.Size {
		return "", false
	}
	p, sig := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	m := hmac.New(sha256.New, h.signingKey)
	_, _ = m.Write([]byte("agent-exposure-listAgents-agent-v1\x00"))
	_, _ = m.Write(p)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return "", false
	}
	var c agentExposureCursor
	if decodeStrictInventory(p, &c) != nil || c.Version != 1 || c.Scope != agentExposureDigest([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}) || c.Filters != agentExposureDigest(filters) || c.Profile != pin || c.Limit != limit || !validProductID(c.After) {
		return "", false
	}
	return c.After, true
}
func (h *inventoryHTTPHandler) agentExposurePage(w http.ResponseWriter, r *http.Request, identity RequestIdentity) bool {
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		h.writePageQueryError(w, r)
		return true
	}
	explicit := false
	for _, key := range []string{"risk", "execution", "impact"} {
		if _, ok := query[key]; ok {
			explicit = true
		}
	}
	repository, supported := h.repository.(agentExposurePageRepository)
	pin := ""
	if supported {
		pin = repository.AgentExposureFilterProfileChecksum()
	}
	if !explicit && pin == "" {
		return false
	}
	filters, cursor, limit, valid := agentExposureQuery(r.URL.RawQuery)
	if !valid || r.Method != http.MethodGet {
		h.writePageQueryError(w, r)
		return true
	}
	if !supported || !migrations.IsAgentExposureFilterProfileChecksum(pin) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return true
	}
	after := ""
	if cursor != "" {
		var ok bool
		after, ok = h.decodeExposureCursor(cursor, identity.Scope, filters, pin, limit)
		if !ok {
			h.writePageQueryError(w, r)
			return true
		}
	}
	page, err := repository.ListAgentExposurePage(r.Context(), identity.Scope, filters, after, limit)
	if err != nil {
		writeProductionError(w, r, err)
		return true
	}
	info := map[string]any{"next_cursor": nil, "has_more": false}
	if page.NextKey != "" {
		info["next_cursor"] = h.exposureCursor(identity.Scope, filters, pin, page.NextKey, limit)
		info["has_more"] = true
	}
	writeJSONValue(w, r, http.StatusOK, map[string]any{"items": page.Items, "page_info": info}, nil)
	return true
}
func (r *PostgresRepository) RequireAgentExposureFilterProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsAgentExposureFilterProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentExposureFilterProfileChecksum = pin
	return nil
}
func (r *PostgresInventoryRepository) AgentExposureFilterProfileChecksum() string {
	if r == nil {
		return ""
	}
	return r.agentExposureFilterProfileChecksum
}
func (r *PostgresInventoryRepository) ListAgentExposurePage(ctx context.Context, scope domain.Scope, filters json.RawMessage, after string, limit int) (InventoryPage, error) {
	if r == nil || !migrations.IsAgentExposureFilterProfileChecksum(r.agentExposureFilterProfileChecksum) {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	if !validInventoryCall(r, ctx, scope, InventoryKindAgent, after, limit) {
		return InventoryPage{}, ErrRepositoryOperation
	}
	selected, ok := parseAgentExposureFilters(filters)
	if !ok {
		return InventoryPage{}, ErrRepositoryOperation
	}
	canonical, _ := json.Marshal(selected)
	payload, err := r.database.QueryJSON(ctx, postgresAgentExposurePageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), after, limit, json.RawMessage(canonical), r.agentExposureFilterProfileChecksum)
	if err != nil {
		return InventoryPage{}, inventoryProviderError(err)
	}
	var env struct {
		Items []InventorySummary `json:"items"`
		Next  *string            `json:"next_id"`
	}
	if decodeStrictInventory(payload, &env) != nil || env.Items == nil || len(env.Items) > limit {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	prior := after
	for _, item := range env.Items {
		if !validInventorySummary(item, InventoryKindAgent) || prior != "" && item.ID <= prior {
			return InventoryPage{}, ErrRepositoryUnavailable
		}
		if owner, present := selected["owner"]; present && item.Owner != owner {
			return InventoryPage{}, ErrRepositoryUnavailable
		}
		prior = item.ID
	}
	next, ok := validInventoryNextKey(env.Next, prior, len(env.Items), limit)
	if !ok {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	return InventoryPage{Items: env.Items, NextKey: next}, nil
}
func agentExposureStatementAllowed(g RequestAuthorization, q string, args []any) (bool, bool) {
	if q != postgresAgentExposurePageSQL {
		return false, false
	}
	if g.OperationID != "listAgents" || !g.Collection || len(args) != 7 || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) {
		return true, false
	}
	for n, want := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()} {
		v, ok := args[n].(string)
		if !ok || v != want {
			return true, false
		}
	}
	after, aok := args[3].(string)
	limit, lok := args[4].(int)
	filters, fok := args[5].(json.RawMessage)
	pin, pok := args[6].(string)
	if !aok || after != "" && !validProductID(after) || !lok || limit < 1 || limit > 100 || !fok || !pok || !migrations.IsAgentExposureFilterProfileChecksum(pin) {
		return true, false
	}
	_, valid := parseAgentExposureFilters(filters)
	return true, valid
}
func (d *PostgresJSONDatabase) AgentExposureFilterProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsAgentExposureFilterProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if err := d.driver.QueryRow(ctx, `SELECT zasp_agent_exposure_filter_v1.caller_ready($1)`, pin).Scan(&ready); err != nil {
		return false, classifyPostgresError(err)
	}
	return ready, nil
}
