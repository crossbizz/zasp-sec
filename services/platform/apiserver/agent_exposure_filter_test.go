package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Only the optional read seam is modeled here. Native classification, complete
// related-finding Checks and SQL row visibility require separate acceptance.
type exposureFilterRepository struct {
	ownerFilterRepository
	exposureCalls int
	filters       json.RawMessage
	after         string
	pin           string
}

func (r *exposureFilterRepository) AgentExposureFilterProfileChecksum() string { return r.pin }
func (r *exposureFilterRepository) ListAgentExposurePage(_ context.Context, _ domain.Scope, filters json.RawMessage, after string, limit int) (InventoryPage, error) {
	r.exposureCalls++
	r.filters = append(json.RawMessage(nil), filters...)
	r.after, r.limit = after, limit
	if r.unavailable {
		return InventoryPage{}, ErrRepositoryUnavailable
	}
	return r.page, nil
}
func exposureFilterGet(t *testing.T, h *inventoryHTTPHandler, query string, revision int64) *httptest.ResponseRecorder {
	t.Helper()
	g := agentCurrentReadGrant(t, "listAgents")
	g.Collection = true
	g.Revision.Desired = revision
	g.Revision.Applied = revision
	request := inventoryRequest(t, "listAgents", "https://app.zasp.test/api/v1/agents"+query)
	request = request.WithContext(context.WithValue(request.Context(), requestAuthorizationContextKey{}, g))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	return w
}
func TestAgentExposureFilterActualHandlerPreservesPresenceAndConjunction(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		want        map[string]string
		oldOwner    bool
	}{
		{"combined", "?limit=1&owner=&risk=high&execution=shell_or_code&impact=high", map[string]string{"owner": "", "risk": "high", "execution": "shell_or_code", "impact": "high"}, false},
		{"unknown_not_safe", "?limit=1&risk=unknown&execution=unknown&impact=unknown", map[string]string{"risk": "unknown", "execution": "unknown", "impact": "unknown"}, false},
		{"literal_owner", "?limit=1&owner=" + url.QueryEscape("  Security 😀  ") + "&execution=code", map[string]string{"owner": "  Security 😀  ", "execution": "code"}, false},
		{"omitted", "?limit=1", nil, false},
		{"new_omitted", "?limit=1", map[string]string{}, false},
		{"new_owner_only", "?limit=1&owner=", map[string]string{"owner": ""}, false},
		{"owner_only_compatibility", "?limit=1&owner=", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &exposureFilterRepository{pin: migrations.AgentExposureFilterProfileChecksum()}
			if tc.name == "omitted" || tc.oldOwner {
				r.pin = ""
			}
			r.page.Items = []InventorySummary{}
			w := exposureFilterGet(t, ownerFilterHandler(t, r), tc.query, 1)
			if w.Code != http.StatusOK {
				t.Fatal("supported exact Agents filter request refused")
			}
			if tc.want != nil {
				var got map[string]string
				if json.Unmarshal(r.filters, &got) != nil || !reflect.DeepEqual(got, tc.want) || r.exposureCalls != 1 || r.pageCalls != 0 || r.ownerCalls != 0 {
					t.Fatal("combined filters lost literal presence or used a delegated/unfiltered page")
				}
			} else if tc.oldOwner {
				if r.ownerCalls != 1 || r.exposureCalls != 0 {
					t.Fatal("original owner-only route changed")
				}
			} else if r.pageCalls != 1 || r.exposureCalls != 0 || r.ownerCalls != 0 {
				t.Fatal("omitted filters changed original list route")
			}
		})
	}
}
func TestAgentExposureFilterCursorBindsAllSelectorsProfileAndRevision(t *testing.T) {
	id := "pid_10000001-0000-4000-8000-000000000001"
	r := &exposureFilterRepository{pin: migrations.AgentExposureFilterProfileChecksum()}
	r.page = InventoryPage{Items: []InventorySummary{{ID: id}}, NextKey: id}
	h := ownerFilterHandler(t, r)
	base := "?limit=1&owner=&risk=high&execution=shell&impact=high"
	first := exposureFilterGet(t, h, base, 1)
	var page struct {
		PageInfo struct {
			Next string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &page) != nil || page.PageInfo.Next == "" || len(page.PageInfo.Next) > 512 {
		t.Fatal("combined filter cursor unavailable or outside original bounded ABI")
	}
	if w := exposureFilterGet(t, h, base+"&cursor="+url.QueryEscape(page.PageInfo.Next), 1); w.Code != http.StatusOK || r.after != id {
		t.Fatal("exact filter continuation refused")
	}
	before := r.exposureCalls + r.ownerCalls + r.pageCalls
	for _, query := range []string{"?limit=1&risk=high&execution=shell&impact=high", "?limit=1&owner=Security&risk=high&execution=shell&impact=high", "?limit=1&owner=&risk=critical&execution=shell&impact=high", "?limit=1&owner=&risk=high&execution=code&impact=high", "?limit=1&owner=&risk=high&execution=shell&impact=unknown", "?limit=2&owner=&risk=high&execution=shell&impact=high"} {
		if w := exposureFilterGet(t, h, query+"&cursor="+url.QueryEscape(page.PageInfo.Next), 1); w.Code == http.StatusOK {
			t.Fatal("cursor crossed filter presence/value/limit boundary")
		}
	}
	if w := exposureFilterGet(t, h, base+"&cursor="+url.QueryEscape(page.PageInfo.Next), 2); w.Code == http.StatusOK {
		t.Fatal("cursor crossed current authorization revision")
	}
	r.pin = migrations.AgentExposureFilterAuditProfileChecksum()
	if w := exposureFilterGet(t, h, base+"&cursor="+url.QueryEscape(page.PageInfo.Next), 1); w.Code == http.StatusOK {
		t.Fatal("cursor crossed selected compiled profile")
	}
	if r.exposureCalls+r.ownerCalls+r.pageCalls != before {
		t.Fatal("invalid cursor reached repository")
	}
}
func TestAgentExposureFilterMalformedAndUnavailableNeverUseLegacyPage(t *testing.T) {
	r := &exposureFilterRepository{pin: migrations.AgentExposureFilterProfileChecksum()}
	h := ownerFilterHandler(t, r)
	for _, query := range []string{"?risk=", "?execution=", "?impact=", "?risk=HIGH", "?risk=none", "?execution=any", "?execution=false", "?impact=reachable", "?impact=false", "?risk=high&risk=low", "?execution=shell&execution=code", "?impact=high&impact=unknown", "?Risk=high", "?execution=shell&owner=%00", "?execution=shell&owner=%FF", "?execution=shell&environment=production", "?execution=shell&invented=true"} {
		if w := exposureFilterGet(t, h, query, 1); w.Code == http.StatusOK {
			t.Fatal("malformed filter accepted")
		}
	}
	if r.exposureCalls+r.ownerCalls+r.pageCalls != 0 {
		t.Fatal("malformed filters reached a repository")
	}
	r.unavailable = true
	if w := exposureFilterGet(t, h, "?risk=high&execution=shell_or_code&impact=high", 1); w.Code == http.StatusOK || r.pageCalls != 0 || r.ownerCalls != 0 {
		t.Fatal("unavailable new profile fell back to owner or unfiltered page")
	}
	legacy := &inventoryRepositoryStub{}
	if w := exposureFilterGet(t, ownerFilterHandler(t, legacy), "?execution=shell", 1); w.Code == http.StatusOK || legacy.pageCalls != 0 {
		t.Fatal("unsupported filter silently used legacy list")
	}
}
