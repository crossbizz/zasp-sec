package opensearchdriver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

func sessionIndexFixture(t *testing.T, handle HTTPDoer) *SessionIndex {
	t.Helper()
	return &SessionIndex{transport: testDriver(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/zasp-runtime-sessions-v1/_mapping":
			if request.Method != http.MethodGet {
				t.Fatal("mutated mapping in read path")
			}
			return jsonResponse(http.StatusOK, `{"zasp-runtime-sessions-v1":`+sessionIndexSchemaJSON+`}`), nil
		case "/zasp-runtime-sessions-v1/_doc/_zasp_session_schema_v1":
			marker, _ := json.Marshal(expectedSessionSchemaMarker())
			return jsonResponse(http.StatusOK, `{"_index":"zasp-runtime-sessions-v1","_id":"_zasp_session_schema_v1","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(marker)+`}`), nil
		default:
			return handle.Do(request)
		}
	}))}
}

func sessionSearchResponse(ids ...string) string {
	buckets := make([]map[string]any, len(ids))
	aggregation := map[string]any{"buckets": buckets}
	for i, id := range ids {
		buckets[i] = map[string]any{"key": map[string]string{"investigation_id": id}, "doc_count": 3}
	}
	if len(ids) > 0 {
		aggregation["after_key"] = map[string]string{"investigation_id": ids[len(ids)-1]}
	}
	body, _ := json.Marshal(map[string]any{"took": 1, "timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": map[string]any{"max_score": nil, "hits": []any{}}, "aggregations": map[string]any{"sessions": aggregation}})
	return string(body)
}

func TestSessionIndexSearchUsesDedicatedScopedBoundedQuery(t *testing.T) {
	scope := testDriverBatch(t).Scope
	id := testProductID(t, 7).String()
	calls := 0
	driver := sessionIndexFixture(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.Path != "/zasp-runtime-sessions-v1/_search" || request.URL.Query().Get("allow_partial_search_results") != "false" || request.URL.Query().Get("typed_keys") != "false" || request.URL.Query().Get("timeout") != "5s" || request.URL.Query().Has("q") {
			t.Fatalf("unbounded or wrong search request: %s %s", request.Method, request.URL)
		}
		body, _ := io.ReadAll(request.Body)
		want, _ := sessionsearch.BuildQuery(scope, sessionsearch.Filters{Tool: "shell"}, "", 25)
		if !bytes.Equal(body, want) {
			t.Fatal("query was not the closed structured query")
		}
		return jsonResponse(http.StatusOK, sessionSearchResponse(id, "unattributed")), nil
	}))
	page, err := driver.Search(context.Background(), scope, sessionsearch.Filters{Tool: "shell"}, "", 25)
	if err != nil || calls != 1 || len(page.InvestigationIDs) != 2 || page.InvestigationIDs[0] != id || page.After != "unattributed" {
		t.Fatalf("page=%#v error=%v", page, err)
	}
	encoded, _ := json.Marshal(page)
	if bytes.Contains(encoded, []byte("doc_count")) {
		t.Fatal("occurrence counts exposed as canonical event counts")
	}
}

func TestSessionIndexAcceptsObservedNoHitCollectorTerminationWithoutQueryLimit(t *testing.T) {
	// OpenSearch 3.8.0 reports terminated_early for its size=0 hit collector even
	// with terminate_after=0; aggregation buckets still have their own collector.
	body := `{"took":111,"timed_out":false,"terminated_early":true,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"max_score":null,"hits":[]},"aggregations":{"sessions":{"after_key":{"investigation_id":"unattributed"},"buckets":[{"key":{"investigation_id":"unattributed"},"doc_count":1}]}}}`
	index := sessionIndexFixture(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("terminate_after") != "0" {
			t.Fatal("aggregation can be cut off by a hit limit")
		}
		return jsonResponse(200, body), nil
	}))
	page, err := index.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{}, "", 25)
	if err != nil || len(page.InvestigationIDs) != 1 || page.InvestigationIDs[0] != "unattributed" {
		t.Fatalf("observed response rejected: %#v %v", page, err)
	}
}

func TestSessionIndexRejectsInvalidSearchBeforeNetwork(t *testing.T) {
	driver := &SessionIndex{transport: testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid query performed network IO")
		return nil, nil
	}))}
	if _, err := driver.Search(context.Background(), domain.Scope{}, sessionsearch.Filters{}, "", 25); !errors.Is(err, runtimeindex.ErrRejected) {
		t.Fatal(err)
	}
	if _, err := driver.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{RawQuery: "*:*"}, "", 25); !errors.Is(err, runtimeindex.ErrRejected) {
		t.Fatal(err)
	}
}

func TestSessionIndexRejectsPartialMalformedAndUnorderedResponses(t *testing.T) {
	id := testProductID(t, 7).String()
	valid := sessionSearchResponse(id)
	for _, body := range []string{
		strings.Replace(valid, `"timed_out":false`, `"timed_out":true`, 1),
		strings.Replace(valid, `"failed":0`, `"failed":1`, 1),
		strings.Replace(valid, `"failed":0,`, ``, 1),
		strings.Replace(valid, `"timed_out":false`, `"timed_out":true,"timed_out":false`, 1),
		strings.Replace(valid, `"successful":1`, `"successful":0`, 1),
		strings.Replace(valid, `"doc_count":3`, `"doc_count":0`, 1),
		strings.Replace(valid, id, "session-console", -1),
		sessionSearchResponse("unattributed", id), sessionSearchResponse(id, id), valid + ` {}`,
		`{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"failed":0},"hits":{"max_score":null,"hits":[]}}`,
	} {
		driver := sessionIndexFixture(t, httpDoerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(http.StatusOK, body), nil }))
		if page, err := driver.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{}, "", 25); err == nil || page.InvestigationIDs != nil {
			t.Fatalf("partial/invalid search admitted: %#v %s", page, body)
		}
	}
}

func TestSessionIndexDoesNotTreatUnavailableSearchAsEmpty(t *testing.T) {
	for _, status := range []int{201, 204, 400, 401, 403, 404, 429, 500, 503} {
		driver := sessionIndexFixture(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(status, `{"error":"provider-secret"}`), nil
		}))
		if page, err := driver.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{}, "", 25); err == nil || page.InvestigationIDs != nil || strings.Contains(err.Error(), "provider-secret") {
			t.Fatalf("failure treated as data: %#v %v", page, err)
		}
	}
	driver := sessionIndexFixture(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, sessionSearchResponse()), nil
	}))
	if page, err := driver.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{}, "", 25); err != nil || page.InvestigationIDs == nil || len(page.InvestigationIDs) != 0 || page.After != "" {
		t.Fatalf("real empty search rejected: %#v %v", page, err)
	}
}

func TestP7SessionIndexAuthorizationFiltersAndProviderBounds(t *testing.T) {
	const allowed = "pid_10000007-0000-4000-8000-000000000007"
	const other = "pid_10000008-0000-4000-8000-000000000008"
	for _, test := range []struct {
		name         string
		restricted   bool
		ids, buckets []string
		after        string
		wantError    bool
	}{
		{name: "allowed", restricted: true, ids: []string{allowed}, buckets: []string{allowed}, after: allowed},
		{name: "explicit_unattributed", restricted: true, ids: []string{allowed, "unattributed"}, buckets: []string{allowed, "unattributed"}, after: "unattributed"},
		{name: "empty", restricted: true},
		{name: "foreign_bucket", restricted: true, ids: []string{allowed}, buckets: []string{allowed, other}, after: other, wantError: true},
		{name: "implicit_unattributed", restricted: true, ids: []string{allowed}, buckets: []string{"unattributed"}, after: "unattributed", wantError: true},
		{name: "foreign_after", restricted: true, ids: []string{allowed}, buckets: []string{allowed}, after: other, wantError: true},
		{name: "implicit_unattributed_after", restricted: true, ids: []string{allowed}, buckets: []string{allowed}, after: "unattributed", wantError: true},
		{name: "empty_set_foreign_bucket", restricted: true, buckets: []string{allowed}, after: allowed, wantError: true},
		{name: "allowed_after_beyond_last_bucket", restricted: true, ids: []string{allowed, other}, buckets: []string{allowed}, after: other},
		{name: "legacy", restricted: false, buckets: []string{allowed, "unattributed"}, after: "unattributed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			index := sessionIndexFixture(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodPost || request.URL.Path != "/zasp-runtime-sessions-v1/_search" {
					t.Fatalf("wrong search: %s %s", request.Method, request.URL)
				}
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				var query struct {
					Query struct {
						Bool struct {
							Filter []map[string]json.RawMessage `json:"filter"`
						} `json:"bool"`
					} `json:"query"`
				}
				if err := json.Unmarshal(body, &query); err != nil {
					t.Fatal(err)
				}
				restrictions := 0
				for _, clause := range query.Query.Bool.Filter {
					if raw, ok := clause["terms"]; ok {
						var fields map[string][]string
						if err := json.Unmarshal(raw, &fields); err != nil {
							t.Fatal(err)
						}
						if len(fields) != 1 || !reflect.DeepEqual(fields["investigation_id"], test.ids) {
							t.Fatalf("wrong allow keys: %s", raw)
						}
						restrictions++
					}
					if raw, ok := clause["match_none"]; ok {
						if len(test.ids) != 0 || string(raw) != "{}" {
							t.Fatalf("wrong empty restriction: %s", raw)
						}
						restrictions++
					}
				}
				wantRestrictions := 0
				if test.restricted {
					wantRestrictions = 1
				}
				if restrictions != wantRestrictions {
					t.Errorf("authorization missing before provider aggregation: %s", body)
				}
				response := sessionSearchResponse(test.buckets...)
				if len(test.buckets) > 0 {
					response = strings.Replace(response, `"after_key":{"investigation_id":"`+test.buckets[len(test.buckets)-1]+`"}`, `"after_key":{"investigation_id":"`+test.after+`"}`, 1)
				}
				return jsonResponse(http.StatusOK, response), nil
			}))
			page, err := index.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{AuthorizationRestricted: test.restricted, AllowedInvestigationIDs: test.ids}, "", 25)
			if calls != 1 {
				t.Fatalf("search calls=%d", calls)
			}
			if test.wantError {
				if !errors.Is(err, runtimeindex.ErrDrift) || page.InvestigationIDs != nil || page.After != "" {
					t.Fatalf("unauthorized provider output retained: %#v %v", page, err)
				}
				return
			}
			if err != nil || len(page.InvestigationIDs) != len(test.buckets) || page.After != test.after {
				t.Fatalf("authorized page changed: %#v %v", page, err)
			}
			for i, id := range test.buckets {
				if page.InvestigationIDs[i] != id {
					t.Fatalf("wrong returned key: %#v", page)
				}
			}
			if len(test.buckets) == 0 && page.InvestigationIDs == nil {
				t.Fatal("empty authorized page must retain empty-list semantics")
			}
		})
	}
}

func TestP7SessionIndexRejectsInvalidAuthorizationBeforeNetwork(t *testing.T) {
	index := &SessionIndex{transport: testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid authorization set performed provider IO")
		return nil, errors.New("unexpected request")
	}))}
	if page, err := index.Search(context.Background(), testDriverBatch(t).Scope, sessionsearch.Filters{AuthorizationRestricted: true, AllowedInvestigationIDs: []string{""}}, "", 25); !errors.Is(err, runtimeindex.ErrRejected) || page.InvestigationIDs != nil {
		t.Fatalf("invalid authorization not rejected: %#v %v", page, err)
	}
}
