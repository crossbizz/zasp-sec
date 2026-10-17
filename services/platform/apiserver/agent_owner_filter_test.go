package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This seam models only the new read operation, never SQL/FGA permission proof.
type ownerFilterRepository struct {
	inventoryRepositoryStub
	ownerCalls        int
	owner, ownerAfter string
	unavailable       bool
}

func (r *ownerFilterRepository) ListAgentOwnerPage(_ context.Context, _ domain.Scope, owner, after string, limit int) (InventoryPage, error) {
	r.ownerCalls++
	r.owner, r.ownerAfter, r.limit = owner, after, limit
	if r.unavailable {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	return r.page, nil
}
func ownerFilterHandler(t *testing.T, r InventoryRepository) *inventoryHTTPHandler {
	t.Helper()
	h, e := newInventoryHTTPHandler(r, []byte("01234567890123456789012345678901"))
	if e != nil {
		t.Fatal("handler unavailable")
	}
	return h
}
func ownerFilterGet(t *testing.T, h *inventoryHTTPHandler, query string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, inventoryRequest(t, "listAgents", "https://app.zasp.test/api/v1/agents"+query))
	return w
}
func TestAgentOwnerFilterPresenceAndLiteralLabels(t *testing.T) {
	for _, v := range []struct {
		name, query, want string
		filtered          bool
	}{
		{"all", "?limit=1", "", false}, {"unowned", "?limit=1&owner=", "", true},
		{"literal-spaces", "?limit=1&owner=" + url.QueryEscape("  Security  "), "  Security  ", true},
		{"whitespace-only", "?limit=1&owner=+++", "   ", true},
		{"unicode-scalars", "?limit=1&owner=" + url.QueryEscape(strings.Repeat("😀", 128)), strings.Repeat("😀", 128), true},
	} {
		t.Run(v.name, func(t *testing.T) {
			r := &ownerFilterRepository{}
			h := ownerFilterHandler(t, r)
			w := ownerFilterGet(t, h, v.query)
			if w.Code != http.StatusOK {
				t.Fatalf("owner query refused: status=%d", w.Code)
			}
			if v.filtered {
				if r.ownerCalls != 1 || r.pageCalls != 0 || r.owner != v.want {
					t.Fatal("explicit literal owner did not use filtered read exclusively")
				}
			} else if r.pageCalls != 1 || r.ownerCalls != 0 {
				t.Fatal("unfiltered compatibility changed")
			}
		})
	}
}
func TestAgentOwnerFilterCursorBindsPresenceAndExactBytes(t *testing.T) {
	id := "pid_10000001-0000-4000-8000-000000000001"
	r := &ownerFilterRepository{inventoryRepositoryStub: inventoryRepositoryStub{page: InventoryPage{Items: []InventorySummary{{ID: id}}, NextKey: id}}}
	h := ownerFilterHandler(t, r)
	w := ownerFilterGet(t, h, "?limit=1&owner=Security")
	if w.Code != http.StatusOK {
		t.Fatal("filtered first page unavailable")
	}
	var page struct {
		PageInfo struct {
			NextCursor string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page.PageInfo.NextCursor == "" {
		t.Fatal("filtered cursor absent")
	}
	if len(page.PageInfo.NextCursor) > 512 {
		t.Fatal("filtered cursor exceeds bounded Agents ABI")
	}
	w = ownerFilterGet(t, h, "?limit=1&owner=Security&cursor="+page.PageInfo.NextCursor)
	if w.Code != http.StatusOK || r.ownerAfter != id {
		t.Fatal("same filter continuation rejected")
	}
	before := r.ownerCalls + r.pageCalls
	for _, q := range []string{"?limit=1&owner=security", "?limit=1&owner=+Security", "?limit=1&owner=", "?limit=1", "?limit=2&owner=Security"} {
		w = ownerFilterGet(t, h, q+"&cursor="+page.PageInfo.NextCursor)
		if w.Code == http.StatusOK {
			t.Fatal("cursor crossed exact filter/presence/limit boundary")
		}
	}
	if r.ownerCalls+r.pageCalls != before {
		t.Fatal("invalid filtered cursor reached repository")
	}
}
func TestAgentOwnerFilterRefusesUnsupportedAndMalformedBeforeLegacyRead(t *testing.T) {
	legacy := &inventoryRepositoryStub{}
	w := ownerFilterGet(t, ownerFilterHandler(t, legacy), "?owner=")
	if w.Code == http.StatusOK || legacy.pageCalls != 0 {
		t.Fatal("unsupported explicit owner silently used unfiltered path")
	}
	r := &ownerFilterRepository{unavailable: true}
	h := ownerFilterHandler(t, r)
	w = ownerFilterGet(t, h, "?owner=security")
	if w.Code == http.StatusOK || r.pageCalls != 0 {
		t.Fatal("unready filtered request fell back")
	}
	before := r.ownerCalls
	for _, q := range []string{"?owner=a&owner=b", "?Owner=a", "?owner=%00", "?owner=%7F", "?owner=%FF", "?owner=%ED%A0%80", "?owner=" + url.QueryEscape(strings.Repeat("😀", 129)), "?owner=a&environment=production"} {
		w = ownerFilterGet(t, h, q)
		if w.Code == http.StatusOK {
			t.Fatal("invalid owner query accepted")
		}
	}
	if r.ownerCalls != before || r.pageCalls != 0 {
		t.Fatal("invalid owner query reached read")
	}
}
func TestAgentOwnerPersistedReadDomainDoesNotRelaxWriter(t *testing.T) {
	value := InventorySummary{ID: "pid_10000001-0000-4000-8000-000000000001", Name: "Agent", Kind: InventoryKindAgent, Team: "platform", Tags: []string{}, EvidenceID: "pid_20000001-0000-4000-8000-000000000001", ConfidenceBasisPoints: 9500, FirstSeen: "2026-08-19T00:00:00Z", LastSeen: "2026-08-19T01:00:00Z", ObservedAt: "2026-08-19T01:00:00Z", FreshUntil: "2026-08-19T01:15:00Z", FreshnessState: "fresh", Version: 1}
	for _, owner := range []string{"", "   ", " Security ", strings.Repeat("😀", 128)} {
		value.Owner = owner
		if !validInventorySummary(value, InventoryKindAgent) {
			t.Fatal("valid persisted owner read refused")
		}
	}
	for _, owner := range []string{strings.Repeat("😀", 129), "a\x00b", "a\x7fb", string([]byte{0xff})} {
		value.Owner = owner
		if validInventorySummary(value, InventoryKindAgent) {
			t.Fatal("invalid persisted owner read accepted")
		}
	}
	for _, owner := range []string{"", " Security ", strings.Repeat("😀", 128)} {
		if validAgentOwnershipInput(AgentOwnershipInput{Owner: owner, Team: "platform", Tags: []string{}}) {
			t.Fatal("owner writer canonical domain relaxed")
		}
	}
}
