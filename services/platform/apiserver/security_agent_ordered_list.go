package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Candidate pages own only ordering. Legacy and ordered semantic authorities
// remain separate, and a failed classification never authorizes a legacy read.
type securityAgentLegacyListAuthority interface {
	GetSecurityAgentRun(context.Context, RequestIdentity, string) (SecurityAgentRunDetail, error)
	GetSecurityAgentApproval(context.Context, RequestIdentity, string) (SecurityAgentApproval, error)
}

type orderedListCandidate struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}
type orderedListCandidates struct {
	ContractVersion int                    `json:"contract_version"`
	OrganizationID  string                 `json:"organization_id"`
	WorkspaceID     string                 `json:"workspace_id"`
	EnvironmentID   string                 `json:"environment_id"`
	Operation       string                 `json:"operation"`
	Items           []orderedListCandidate `json:"items"`
	NextCreatedAt   string                 `json:"next_created_at"`
	NextID          string                 `json:"next_id"`
}

const orderedListTimeFormat = "2006-01-02T15:04:05.000000Z"

func orderedListTime(s string) (time.Time, bool) {
	t, err := time.Parse(orderedListTimeFormat, s)
	return t, err == nil && t.Location() == time.UTC && t.Year() >= 1 && t.Format(orderedListTimeFormat) == s
}

// The prototype DTO decoder intentionally limits arrays to ten. Keep that
// boundary unchanged; this closed candidate envelope alone supports 100 IDs.
func orderedListDecode(raw json.RawMessage, page *orderedListCandidates) bool {
	fields, ok := orderedDeploymentClosedObject(raw, 32768, "contract_version", "organization_id", "workspace_id", "environment_id", "operation", "items", "next_created_at", "next_id")
	if !ok {
		return false
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	var items []json.RawMessage
	if json.Unmarshal(fields["items"], &items) != nil || len(items) > 100 {
		return false
	}
	for _, rawItem := range items {
		var item orderedListCandidate
		if public62Decode(rawItem, &item) != nil {
			return false
		}
	}
	return json.Unmarshal(raw, page) == nil
}

func (a *SecurityAgentOrderedResourceAuthority) candidates(ctx context.Context, id RequestIdentity, op, filter, state string, limit int, before time.Time, beforeID string) (orderedListCandidates, error) {
	var zero orderedListCandidates
	if a == nil || a.resolver == nil || nilInterface(a.resolver.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(id, id.CredentialKind == CredentialBrowserSession) || !stringIn(string(id.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !stringIn(op, "run_candidates", "approval_candidates") || filter != "" && !public62ID(filter) || limit < 1 || limit > 100 || before.IsZero() != (beforeID == "") || !before.IsZero() && (before.Location() != time.UTC || !public62ID(beforeID) || before.Nanosecond()%1000 != 0) || state != "" && (op == "run_candidates" && !validSecurityAgentRunState(state) || op == "approval_candidates" && !validSecurityAgentApprovalState(state)) {
		return zero, ErrRepositoryOperation
	}
	stamp := ""
	if !before.IsZero() {
		stamp = before.Format(orderedListTimeFormat)
	}
	q, _ := json.Marshal(map[string]any{"organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "operation": op, "resource_filter": filter, "state_filter": state, "limit": limit, "before_created_at": stamp, "before_id": beforeID})
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := a.resolver.database.QueryJSON(bounded, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(q))
	if err != nil {
		return zero, public62ProviderError(err, op)
	}
	var page orderedListCandidates
	if bounded.Err() != nil || !orderedListDecode(raw, &page) || page.ContractVersion != 62 || page.OrganizationID != id.Scope.OrganizationID().String() || page.WorkspaceID != id.Scope.WorkspaceID().String() || page.EnvironmentID != id.Scope.EnvironmentID().String() || page.Operation != op || page.Items == nil || len(page.Items) > limit || (page.NextCreatedAt == "") != (page.NextID == "") {
		return zero, ErrRepositoryUnavailable
	}
	seen := map[string]bool{}
	previous, previousID := before, beforeID
	for _, item := range page.Items {
		at, ok := orderedListTime(item.CreatedAt)
		if !ok || !public62ID(item.ID) || seen[item.ID] || !previous.IsZero() && (at.After(previous) || at.Equal(previous) && item.ID >= previousID) {
			return zero, ErrRepositoryUnavailable
		}
		seen[item.ID] = true
		previous, previousID = at, item.ID
	}
	if page.NextID != "" && (len(page.Items) != limit || page.NextID != page.Items[len(page.Items)-1].ID || page.NextCreatedAt != page.Items[len(page.Items)-1].CreatedAt) {
		return zero, ErrRepositoryUnavailable
	}
	return page, nil
}

func (h *securityAgentOrderedHTTPHandler) list(w http.ResponseWriter, r *http.Request, operation string) {
	id, ok := IdentityFromRequest(r)
	if !ok || r.URL == nil || r.Method != http.MethodGet || requireZeroByteInput(r) != nil {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	runs := operation == "listSecurityAgentRuns"
	fields := map[string]int{"state": 64, "run_id": 128, "cursor": 512, "limit": 3}
	if runs {
		fields = map[string]int{"agent_id": 128, "status": 64, "environment_id": 128, "cursor": 512, "limit": 3}
	}
	query, valid := exactWorkflowQuery(r.URL.RawQuery, fields)
	limit, limitOK := workflowPageLimit(query)
	filter, state, op, kind := query.Get("run_id"), query.Get("state"), "approval_candidates", SecurityAgentResourceApproval
	definition, run := "", filter
	if runs {
		filter, state, op, kind = query.Get("agent_id"), query.Get("status"), "run_candidates", SecurityAgentResourceRun
		definition, run = filter, ""
	}
	if !valid || !limitOK || runs && query.Has("environment_id") && query.Get("environment_id") != id.Scope.EnvironmentID().String() {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var before time.Time
	var beforeID string
	if query.Has("cursor") {
		before, beforeID, valid = h.cursor.decodePageCursor(query.Get("cursor"), id, operation, limit, definition, state, run)
		if !valid {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	page, err := h.authority.candidates(ctx, id, op, filter, state, limit, before, beforeID)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	families := make([]SecurityAgentFamily, len(page.Items))
	// Classify the entire page before any semantic read. A bearer page containing
	// one ordered item must not read or expose even its earlier ordered items.
	for i, item := range page.Items {
		families[i], err = h.authority.resolver.Resolve(ctx, id, kind, item.ID)
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		if families[i] == SecurityAgentFamilyOrderedRelease61 && id.CredentialKind != CredentialBrowserSession {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
	}
	items := make([]json.RawMessage, 0, len(page.Items))
	for i, item := range page.Items {
		var value any
		if runs {
			var v SecurityAgentRun
			if families[i] == SecurityAgentFamilyOrderedRelease61 {
				var ordered SecurityAgentOrderedRunResource
				ordered, err = h.authority.Run(ctx, id, item.ID)
				v = ordered.Detail.Run
				if err == nil && ordered.CreatedAt.Format(orderedListTimeFormat) != item.CreatedAt {
					err = ErrRepositoryUnavailable
				}
			} else {
				var legacy SecurityAgentRunDetail
				legacy, err = h.lists.GetSecurityAgentRun(ctx, id, item.ID)
				v = legacy.Run
				if err == nil && !validSecurityAgentRun(v) {
					err = ErrRepositoryUnavailable
				}
			}
			if err == nil && (v.ID != item.ID || filter != "" && v.AgentID != filter || state != "" && v.State != state) {
				err = ErrRepositoryUnavailable
			}
			value = v
		} else {
			var v SecurityAgentApproval
			if families[i] == SecurityAgentFamilyOrderedRelease61 {
				var ordered SecurityAgentOrderedApprovalResource
				ordered, err = h.authority.Approval(ctx, id, item.ID)
				v = ordered.Approval
				if err == nil && ordered.CreatedAt.Format(orderedListTimeFormat) != item.CreatedAt {
					err = ErrRepositoryUnavailable
				}
			} else {
				v, err = h.lists.GetSecurityAgentApproval(ctx, id, item.ID)
				if err == nil && !validSecurityAgentApproval(v) {
					err = ErrRepositoryUnavailable
				}
			}
			if err == nil && (v.ID != item.ID || filter != "" && v.RunID != filter || state != "" && v.State != state) {
				err = ErrRepositoryUnavailable
			}
			value = v
		}
		if err != nil {
			if err == ErrSecurityAgentNotOwned {
				err = ErrRepositoryUnavailable
			}
			writeProductionError(w, r, err)
			return
		}
		raw, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		if !runs && !exactHeaderValue(r.Header.Values("X-Zasp-Approval-Context"), "v1") {
			approval, typed := value.(SecurityAgentApproval)
			if !typed || !requiredFindingApprovalContext(approval) {
				raw = orderedListWithoutContext(raw)
			}
		}
		items = append(items, raw)
	}
	// Detect family changes while collecting a page; never send partial output.
	for i, item := range page.Items {
		family, e := h.authority.resolver.Resolve(ctx, id, kind, item.ID)
		if e != nil {
			writeProductionError(w, r, e)
			return
		}
		if family != families[i] {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
	}
	if ctx.Err() != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	value := map[string]any{"items": items}
	if page.NextID != "" {
		at, _ := orderedListTime(page.NextCreatedAt)
		value["next_cursor"] = h.cursor.encodePageCursor(id, operation, limit, definition, state, run, at, page.NextID)
	}
	writeJSONValue(w, r, http.StatusOK, value, nil)
}

// Preserve the serialized field order and values of the typed legacy DTO.
// Optional context is suppressed without depending on a later DTO extension.
func orderedListWithoutContext(raw []byte) []byte {
	d := json.NewDecoder(bytes.NewReader(raw))
	_, _ = d.Token()
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	for d.More() {
		key, _ := d.Token()
		var value json.RawMessage
		_ = d.Decode(&value)
		if key == "approval_context" {
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(key)
		out.Write(k)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes()
}
