package opensearchhistory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/opensearchaccess"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestDriverSearchesOnlyBoundedTenantTriggerHistory(t *testing.T) {
	scope := historyScope(t)
	doer := historyDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/zasp-runtime-events-v1/_search" || request.URL.Query().Get("filter_path") != "hits.hits._id,hits.hits._source,hits.hits.sort,timed_out" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Authorization") != "signed" {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL.String(), request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		var query map[string]any
		if json.Unmarshal(body, &query) != nil || query["size"] != float64(25) || query["track_total_hits"] != false {
			t.Fatalf("query=%s", body)
		}
		expected := []string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "tool"}
		for _, value := range expected {
			if !strings.Contains(string(body), value) {
				t.Fatalf("query missing %q: %s", value, body)
			}
		}
		response := historyResponse(http.StatusOK, `{"timed_out":false,"hits":{"hits":[{"_id":"evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sort":["2026-08-28T12:00:00.000Z","evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"_source":{"organization_id":"`+scope.OrganizationID().String()+`","workspace_id":"`+scope.WorkspaceID().String()+`","environment_id":"`+scope.EnvironmentID().String()+`","record_type":"runtime_event","event_id":"`+historyID(t).String()+`","event_class":"tool","action":"invoke","agent_id":"pid_70000001-0000-4000-8000-000000000001","session_id":"pid_70000002-0000-4000-8000-000000000002","tool_id":"shell","source_event_id":"source-1","event_time":"2026-08-28T12:00:00.000Z"}}]}}`)
		response.Header.Set("Content-Type", "application/json; charset=UTF-8")
		return response, nil
	})
	driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, doer, historyReady{}, func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	values, err := driver.SearchPolicyActions(context.Background(), scope, "tool", 25)
	if err != nil || len(values) != 1 || values[0].PrincipalID != values[0].AgentID || values[0].Resource != "shell" || values[0].Metadata["action"] != "invoke" || values[0].EnvironmentID != scope.EnvironmentID().String() {
		t.Fatalf("values=%#v err=%v", values, err)
	}
}

func TestDriverFailsClosedOnForeignMalformedOrUnboundedHistory(t *testing.T) {
	scope := historyScope(t)
	foreign := historyScope(t)
	tests := map[string]string{
		"foreign scope": `{"timed_out":false,"hits":{"hits":[{"_id":"evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sort":["2026-08-28T12:00:00.000Z","evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"_source":{"organization_id":"` + foreign.OrganizationID().String() + `","workspace_id":"` + scope.WorkspaceID().String() + `","environment_id":"` + scope.EnvironmentID().String() + `","record_type":"runtime_event","event_id":"` + historyID(t).String() + `","event_class":"tool","action":"invoke","agent_id":"pid_70000001-0000-4000-8000-000000000001","session_id":"pid_70000002-0000-4000-8000-000000000002","tool_id":"shell","source_event_id":"source-1","event_time":"2026-08-28T12:00:00.000Z"}}]}}`,
		"timed out":     `{"timed_out":true,"hits":{"hits":[]}}`,
		"unknown field": `{"timed_out":false,"secret":"provider-body","hits":{"hits":[]}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, historyDoerFunc(func(*http.Request) (*http.Response, error) { return historyResponse(http.StatusOK, body), nil }), historyReady{}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if values, err := driver.SearchPolicyActions(context.Background(), scope, "tool", 100); err == nil || values != nil {
				t.Fatalf("values=%#v err=%v", values, err)
			}
		})
	}
}

func TestDriverReadinessRequiresExactSchemaAuthority(t *testing.T) {
	ready := &historyReadyStub{err: ErrHistory}
	driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, historyDoerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected search"); return nil, nil }), ready, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Ready(context.Background()); err == nil || ready.calls != 1 {
		t.Fatalf("ready err=%v calls=%d", err, ready.calls)
	}
}

func TestDriverAllowsLoopbackOnlyThroughExplicitTestAuthority(t *testing.T) {
	base := Config{Endpoint: "http://127.0.0.1:19092", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumResponseBytes: 1 << 20}
	client := historyDoerFunc(func(*http.Request) (*http.Response, error) { return nil, ErrHistory })
	if driver, err := newWithClient(base, historyCredentials{}, historySigner{}, client, historyReady{}, time.Now); err == nil || driver != nil {
		t.Fatalf("loopback accepted without test authority: %#v %v", driver, err)
	}
	base.AllowTestLoopback = true
	if driver, err := newWithClient(base, historyCredentials{}, historySigner{}, client, historyReady{}, time.Now); err != nil || driver == nil {
		t.Fatalf("explicit test loopback rejected: %#v %v", driver, err)
	}
	base.Endpoint = "http://10.0.0.1:19092"
	if driver, err := newWithClient(base, historyCredentials{}, historySigner{}, client, historyReady{}, time.Now); err == nil || driver != nil {
		t.Fatalf("non-loopback test authority accepted: %#v %v", driver, err)
	}
}

type historyCredentials struct{}

func (historyCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "token"}, nil
}

type historySigner struct{}

func (historySigner) SignHTTP(_ context.Context, _ aws.Credentials, request *http.Request, _ string, service, region string, _ time.Time, _ ...func(*SignerOptions)) error {
	if service != "es" || region != "us-west-2" {
		return ErrHistory
	}
	request.Header.Set("Authorization", "signed")
	return nil
}

type historyDoerFunc func(*http.Request) (*http.Response, error)

func (function historyDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type historyReady struct{}

func (historyReady) Ready(context.Context) error { return nil }

type historyReadyStub struct {
	err   error
	calls int
}

func (stub *historyReadyStub) Ready(context.Context) error { stub.calls++; return stub.err }

func historyResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func historyScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(historyID(t), historyID(t), historyID(t))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func historyID(t *testing.T) domain.ProductID {
	t.Helper()
	value, err := domain.NewProductID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPolicyReplayScopesAgentAndRejectsPartialSearch(t *testing.T) {
	scope := historyScope(t)
	id := historyID(t).String()
	other := historyID(t).String()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := platformpolicy.ReplayWindow{AgentID: id, From: base, To: base.Add(time.Hour)}
	for _, tc := range []struct {
		name          string
		size          int
		agent         string
		offset        time.Duration
		shardFailures int
		valid         bool
	}{
		{"empty", 0, id, 0, 0, true}, {"at limit", 100, id, 0, 0, true}, {"more indexed", 101, id, 0, 0, true}, {"foreign agent", 1, other, 0, 0, false}, {"exclusive end", 1, id, time.Hour, 0, false}, {"partial search", 1, id, 0, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := historyDoerFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{`"format":"strict_date_time"`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), `"agent_id":"` + id + `"`, `"gte":"2026-01-01T00:00:00.000Z"`, `"lt":"2026-01-01T01:00:00.000Z"`, `"size":500`} {
					if !strings.Contains(string(body), want) {
						t.Fatal(string(body))
					}
				}
				stamp := base.Add(tc.offset).Format("2006-01-02T15:04:05.000Z")
				hits := make([]any, 0, tc.size)
				for i := 0; i < tc.size; i++ {
					doc := fmt.Sprintf("evt_%064x", i+1)
					event := fmt.Sprintf("pid_%08x-0000-4000-8000-%012x", i+1, i+1)
					hits = append(hits, map[string]any{"_id": doc, "sort": []string{stamp, event}, "_source": historyStoredDocument{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RecordType: "runtime_event", EventID: event, EventClass: "tool", Action: "invoke", AgentID: tc.agent, SessionID: other, ToolID: "send", SourceEventID: "source", EventTime: stamp}})
				}
				reply, _ := json.Marshal(map[string]any{"timed_out": false, "_shards": map[string]any{"failed": tc.shardFailures}, "hits": map[string]any{"hits": hits}})
				return historyResponse(200, string(reply)), nil
			})
			driver, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, transport, historyReady{}, func() time.Time { return base })
			if err != nil {
				t.Fatal(err)
			}
			values, truncated, err := driver.SearchReplayActions(t.Context(), scope, "tool", window)
			if (err == nil) != tc.valid || tc.valid && (len(values) != tc.size || truncated) {
				t.Fatalf("len %d, truncated %v, error %v", len(values), truncated, err)
			}
		})
	}
}

func TestPolicyReplayThreePagesTiesAndAdjacentWindows(t *testing.T) {
	scope := historyScope(t)
	agent, session := historyID(t).String(), historyID(t).String()
	at := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	stamp := at.Format("2006-01-02T15:04:05.000Z")
	id := func(i int) string { return fmt.Sprintf("pid_%08x-0000-4000-8000-%012x", i, i) }
	calls := 0
	changeTotal := false
	client := historyDoerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		var q struct {
			Size  int              `json:"size"`
			After []string         `json:"search_after"`
			Sort  []map[string]any `json:"sort"`
			Query json.RawMessage  `json:"query"`
		}
		if json.NewDecoder(req.Body).Decode(&q) != nil || len(q.Sort) != 2 || q.Sort[1]["event_id"] == nil {
			t.Fatalf("wrong sort")
		}
		start := 1
		if len(q.After) > 0 {
			if len(q.After) != 2 || q.After[0] != stamp {
				t.Fatalf("bad continuation %v", q.After)
			}
			for start <= 250 && id(start) <= q.After[1] {
				start++
			}
		}
		var hits []any
		for i := start; i <= 250 && len(hits) < q.Size; i++ {
			doc := fmt.Sprintf("evt_%064x", i)
			hits = append(hits, map[string]any{"_id": doc, "sort": []string{stamp, id(i)}, "_source": historyStoredDocument{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RecordType: "runtime_event", EventID: id(i), EventClass: "tool", Action: "invoke", AgentID: agent, SessionID: session, ToolID: "ticket", EventTime: stamp}})
		}
		total := 250
		if changeTotal && len(q.After) > 0 {
			total++
		}
		if strings.Contains(string(q.Query), `"lt":"2026-01-02T10:00:00.000Z"`) && !strings.Contains(string(q.Query), `"gt"`) {
			hits = []any{}
			total = 0
		}
		if strings.Contains(string(q.Query), `"gt"`) {
			total = 50
		}
		if hits == nil {
			hits = []any{}
		}
		data, _ := json.Marshal(map[string]any{"timed_out": false, "_shards": map[string]int{"failed": 0}, "hits": map[string]any{"total": map[string]any{"value": total, "relation": "eq"}, "hits": hits}})
		return historyResponse(200, string(data)), nil
	})
	d, err := newWithClient(Config{Endpoint: "https://vpc-zasp.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: time.Second, MaximumResponseBytes: 1 << 20}, historyCredentials{}, historySigner{}, client, historyReady{}, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	w := platformpolicy.ReplayWindow{AgentID: agent, From: at, To: at.Add(time.Hour)}
	got, truncated, err := d.replayPages(t.Context(), scope, "tool", w, 100, 10)
	if err != nil || truncated || len(got) != 250 || calls != 3 {
		t.Fatalf("%d hits, %d calls, truncated %t: %v", len(got), calls, truncated, err)
	}
	earlier, cut, err := d.replayPages(t.Context(), scope, "tool", platformpolicy.ReplayWindow{AgentID: agent, From: at.Add(-time.Hour), To: at}, 100, 10)
	if err != nil || cut || len(earlier) != 0 {
		t.Fatal("adjacent window included the boundary event")
	}
	got, truncated, err = d.replayPages(t.Context(), scope, "tool", w, 100, 2)
	if err != nil || !truncated || len(got) != 200 {
		t.Fatal("budget not enforced")
	}
	w.To = got[199].EventTime
	w.BeforeEventID = got[199].EventID
	if !w.Valid() {
		t.Fatal("exact boundary continuation rejected")
	}
	tail, truncated, err := d.replayPages(t.Context(), scope, "tool", w, 100, 10)
	if err != nil || truncated || len(tail) != 50 || tail[0].EventID != id(201) {
		t.Fatal("same-timestamp continuation lost or duplicated events", err, len(tail))
	}
	w.To = at.Add(time.Hour)
	w.BeforeEventID = ""
	changeTotal = true
	inconsistent, cut, err := d.replayPages(t.Context(), scope, "tool", w, 100, 10)
	if err == nil || inconsistent != nil || cut {
		t.Fatal("partial read emitted despite inconsistent page counts")
	}
}

func TestPrivateSearchSelectsWorkloadIdentity(t *testing.T) {
	sent := false
	client := historyDoerFunc(func(request *http.Request) (*http.Response, error) {
		sent = true
		if request.URL.Host != opensearchaccess.Host+":9200" || request.Header.Get("Authorization") != "" {
			t.Fatal("unexpected private search authority")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	config := Config{AuthMode: opensearchaccess.MutualTLS, Endpoint: opensearchaccess.Endpoint, Region: "us-west-2", RequestTimeout: time.Second, MaximumResponseBytes: 4096}
	driver, err := newWithClient(config, nil, nil, client, historyReady{}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	resp, err := driver.request(context.Background(), "/zasp-runtime-events-v1/_search", []byte("{}"))
	if err == nil {
		resp.Body.Close()
	}
	if err != nil || !sent {
		t.Fatalf("private request: sent %t, error %v", sent, err)
	}
	config.Endpoint = "https://search-foreign.us-west-2.es.amazonaws.com"
	if _, err = newWithClient(config, nil, nil, client, historyReady{}, func() time.Time { return time.Now().UTC() }); err == nil {
		t.Fatal("accepted a different search authority")
	}
}
