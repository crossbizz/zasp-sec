package opensearchdriver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type retentionVisibilityFunc func(context.Context, domain.Scope, []string) (map[string]bool, error)

func (f retentionVisibilityFunc) VisibleEvents(ctx context.Context, scope domain.Scope, ids []string) (map[string]bool, error) {
	return f(ctx, scope, ids)
}

func TestSessionRetentionMatchingEvidenceAndContinuation(t *testing.T) {
	scope := testDriverBatch(t).Scope
	session := testProductID(t, 7).String()
	event := testProductID(t, 8).String()
	for _, tc := range []struct {
		name                   string
		count                  int
		state                  map[string]bool
		gateErr                error
		foreign, missing       bool
		wantVisible, wantError bool
	}{
		{name: "expired matching event cannot reveal live session", count: 1, state: map[string]bool{event: false}},
		{name: "live matching event retains membership", count: 1, state: map[string]bool{event: true}, wantVisible: true},
		{name: "truncated all expired is unavailable", count: 33, state: map[string]bool{event: false}, wantError: true},
		{name: "truncated live still proves membership", count: 33, state: map[string]bool{event: true}, wantVisible: true},
		{name: "unknown event is unavailable", count: 1, state: map[string]bool{}, wantError: true},
		{name: "authority unavailable", count: 1, gateErr: errors.New("private database error"), wantError: true},
		{name: "foreign witness", count: 1, state: map[string]bool{event: true}, foreign: true, wantError: true},
		{name: "missing witnesses", count: 1, state: map[string]bool{event: true}, missing: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := sessionSearchResponse(session)
			var value map[string]any
			if json.Unmarshal([]byte(body), &value) != nil {
				t.Fatal("fixture")
			}
			bucket := value["aggregations"].(map[string]any)["sessions"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
			bucket["doc_count"] = tc.count
			if !tc.missing {
				org := scope.OrganizationID().String()
				if tc.foreign {
					org = testProductID(t, 9).String()
				}
				hits := []any{}
				n := tc.count
				if n > 32 {
					n = 32
				}
				for i := 0; i < n; i++ {
					document := strings.Repeat("a", 62) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
					hits = append(hits, map[string]any{"_index": sessionIndexName, "_id": document, "_score": nil, "sort": []string{event, document}, "_source": map[string]string{"organization_id": org, "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "record_type": "runtime_session_event", "investigation_id": session, "event_id": event}})
				}
				bucket["matching_events"] = map[string]any{"hits": map[string]any{"total": map[string]any{"value": tc.count, "relation": "eq"}, "max_score": nil, "hits": hits}}
			}
			raw, _ := json.Marshal(value)
			index := sessionIndexFixture(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				query, _ := io.ReadAll(request.Body)
				if !strings.Contains(string(query), `"matching_events"`) || !strings.Contains(string(query), `"top_hits"`) {
					t.Error("matching event witnesses not requested before grouping")
				}
				return jsonResponse(200, string(raw)), nil
			}))
			index.retention = retentionVisibilityFunc(func(_ context.Context, got domain.Scope, ids []string) (map[string]bool, error) {
				if got != scope || len(ids) != 1 || ids[0] != event {
					t.Fatalf("unscoped or repeated ids: %v", ids)
				}
				return tc.state, tc.gateErr
			})
			page, err := index.Search(context.Background(), scope, sessionsearch.Filters{}, "", 25)
			if tc.wantError {
				if err == nil || page.InvestigationIDs != nil || strings.Contains(err.Error(), "private") {
					t.Fatalf("unsafe response %#v %v", page, err)
				}
				return
			}
			if err != nil || page.After != session || len(page.InvestigationIDs) != btoi(tc.wantVisible) {
				t.Fatalf("hidden bucket lost continuation or incorrect membership: %#v %v", page, err)
			}
		})
	}
}
func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

var _ runtimeindex.EventVisibility = retentionVisibilityFunc(nil)

func TestSessionRetentionFinalBarrierRechecksEarlierMatchingEvents(t *testing.T) {
	scope := testDriverBatch(t).Scope
	sessions := []string{testProductID(t, 7).String(), testProductID(t, 8).String()}
	events := []string{testProductID(t, 9).String(), testProductID(t, 10).String()}
	states := map[string]bool{events[0]: true, events[1]: true}
	calls := 0
	index := sessionIndexFixture(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		n := calls
		calls++
		var response map[string]any
		_ = json.Unmarshal([]byte(sessionSearchResponse(sessions[n])), &response)
		bucket := response["aggregations"].(map[string]any)["sessions"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
		bucket["doc_count"] = 1
		document := strings.Repeat("a", 64)
		bucket["matching_events"] = map[string]any{"hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "max_score": nil, "hits": []any{map[string]any{"_index": sessionIndexName, "_id": document, "_score": nil, "sort": []string{events[n], document}, "_source": map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "record_type": "runtime_session_event", "investigation_id": sessions[n], "event_id": events[n]}}}}}
		body, _ := json.Marshal(response)
		return jsonResponse(200, string(body)), nil
	}))
	index.retention = retentionVisibilityFunc(func(_ context.Context, _ domain.Scope, ids []string) (map[string]bool, error) {
		result := map[string]bool{}
		for _, id := range ids {
			result[id] = states[id]
		}
		return result, nil
	})
	pages := make([]SessionSearchPage, 0, 2)
	after := ""
	for range sessions {
		page, err := index.Search(context.Background(), scope, sessionsearch.Filters{}, after, 1)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, page)
		after = page.After
	}
	if err := index.RecheckRetainedCandidates(context.Background(), scope, pages); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(pages)
	if strings.Contains(string(encoded), events[0]) || strings.Contains(string(encoded), "retentionWitnesses") {
		t.Fatal("private witnesses escaped serialization")
	}
	states[events[0]] = false
	if err := index.RecheckRetainedCandidates(context.Background(), scope, pages); !errors.Is(err, runtimeindex.ErrRetryable) {
		t.Fatalf("earlier query witness expiry accepted: %v", err)
	}
	states[events[0]] = true
	altered := append([]SessionSearchPage(nil), pages...)
	altered[0].InvestigationIDs = []string{sessions[1]}
	if err := index.RecheckRetainedCandidates(context.Background(), scope, altered); err == nil {
		t.Fatal("forged page witnesses accepted")
	}
	other := *index
	if err := other.RecheckRetainedCandidates(context.Background(), scope, pages); err == nil {
		t.Fatal("different index reused page witness authority")
	}
	foreign, _ := domain.NewScope(testProductID(t, 100), testProductID(t, 101), testProductID(t, 102))
	if err := index.RecheckRetainedCandidates(context.Background(), foreign, pages); err == nil {
		t.Fatal("foreign scope reused page witnesses")
	}
}
