package opensearchhistory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type visibilityFunc func(context.Context, domain.Scope, []string) (map[string]bool, error)

func (f visibilityFunc) VisibleEvents(ctx context.Context, s domain.Scope, ids []string) (map[string]bool, error) {
	return f(ctx, s, ids)
}

func TestPolicyHistoryRetentionSkipsExpiredWithBoundedContinuation(t *testing.T) {
	scope := historyScope(t)
	for _, tc := range []struct {
		name                       string
		unknown, failed, neverEnds bool
	}{
		{name: "expired first page continues to live event"}, {name: "unknown cannot become empty", unknown: true}, {name: "permission revocation unavailable", failed: true}, {name: "unbounded hidden history unavailable", neverEnds: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			doer := historyDoerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				raw, _ := io.ReadAll(request.Body)
				var query map[string]any
				_ = json.Unmarshal(raw, &query)
				if calls > 1 {
					if _, ok := query["search_after"]; !ok {
						t.Error("missing bounded continuation")
					}
				}
				n := calls
				event := fmt.Sprintf("pid_700000%02d-0000-4000-8000-%012d", n, n)
				doc := fmt.Sprintf("evt_%064x", n)
				instant := fmt.Sprintf("2026-08-28T11:%02d:00.000Z", 60-n)
				source := map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "record_type": "runtime_event", "event_id": event, "event_class": "tool", "action": "invoke", "agent_id": "pid_70000001-0000-4000-8000-000000000001", "session_id": "pid_70000002-0000-4000-8000-000000000002", "tool_id": "shell", "source_event_id": "source-1", "event_time": instant}
				body, _ := json.Marshal(map[string]any{"timed_out": false, "hits": map[string]any{"hits": []any{map[string]any{"_id": doc, "sort": []string{instant, doc}, "_source": source}}}})
				return historyResponse(200, string(body)), nil
			})
			driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, doer, historyReady{}, func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) })
			if err != nil {
				t.Fatal(err)
			}
			driver.retention = visibilityFunc(func(_ context.Context, got domain.Scope, ids []string) (map[string]bool, error) {
				if got != scope {
					t.Fatal("scope drift")
				}
				if tc.failed {
					return nil, errors.New("private permission detail")
				}
				state := map[string]bool{}
				if tc.unknown {
					return state, nil
				}
				for _, id := range ids {
					state[id] = !tc.neverEnds && id == "pid_70000002-0000-4000-8000-000000000002"
				}
				return state, nil
			})
			values, err := driver.SearchPolicyActions(context.Background(), scope, "tool", 1)
			if tc.unknown || tc.failed || tc.neverEnds {
				if err == nil || values != nil || calls > 8 {
					t.Fatalf("retention failure fabricated data or unbounded request: %#v %v calls=%d", values, err, calls)
				}
				return
			}
			if err != nil || len(values) != 1 || calls != 2 {
				t.Fatalf("expired history not continued: %#v %v calls=%d", values, err, calls)
			}
		})
	}
}

func TestPolicyHistoryRetentionRequiresExplicitProviderEnd(t *testing.T) {
	scope := historyScope(t)
	for _, tc := range []struct {
		name, body string
		empty      bool
	}{
		{name: "missing response fields", body: `{}`},
		{name: "missing timeout", body: `{"hits":{"hits":[]}}`},
		{name: "null timeout", body: `{"timed_out":null,"hits":{"hits":[]}}`},
		{name: "missing hits", body: `{"timed_out":false}`},
		{name: "null hits", body: `{"timed_out":false,"hits":null}`},
		{name: "missing hit array", body: `{"timed_out":false,"hits":{}}`},
		{name: "null hit array", body: `{"timed_out":false,"hits":{"hits":null}}`},
		{name: "actual explicit empty end", body: `{"timed_out":false,"hits":{"hits":[]}}`, empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, historyDoerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return historyResponse(http.StatusOK, tc.body), nil
			}), historyReady{}, func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) })
			if err != nil {
				t.Fatal(err)
			}
			driver.retention = visibilityFunc(func(context.Context, domain.Scope, []string) (map[string]bool, error) {
				t.Fatal("empty or malformed provider page must not invent event IDs")
				return nil, nil
			})
			values, err := driver.SearchPolicyActions(context.Background(), scope, "tool", 1)
			if calls != 1 {
				t.Fatalf("unexpected continuation: %d", calls)
			}
			if tc.empty {
				if err != nil || values == nil || len(values) != 0 {
					t.Fatalf("actual end rejected: %v %v", values, err)
				}
				return
			}
			if err == nil || values != nil {
				t.Fatalf("missing provider fields fabricated exhaustion: %v %v", values, err)
			}
		})
	}
}
