package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/eventstore"
)

func TestOpenSearchEventDriverIndexesAndSearchesExactScopedDocument(t *testing.T) {
	t.Parallel()
	spec := expectedIndexSpec(testMarker)
	document := productDriverDocument()
	query := productDriverQuery(10)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		step := requests.Add(1)
		response.Header().Set("content-type", "application/json")
		switch step {
		case 1:
			if request.Method != http.MethodPut || request.URL.EscapedPath() != "/"+spec.Name+"/_create/"+document.EventID ||
				request.URL.RawQuery != "refresh=wait_for&timeout=5s" {
				t.Errorf("index request = %s %s?%s", request.Method, request.URL.EscapedPath(), request.URL.RawQuery)
			}
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode index body: %v", err)
			}
			want := map[string]any{
				"organization_id": document.OrganizationID, "workspace_id": document.WorkspaceID,
				"environment_id": document.EnvironmentID, "event_id": document.EventID,
				"session_id": document.SessionID, "agent_id": document.AgentID,
				"source": "runtime_gateway", "source_event_id": "source-event-1",
				"event_class": "tool", "action": "invoke", "decision": "allowed",
				"event_time": "2026-08-15T20:21:22.123Z",
			}
			if !reflect.DeepEqual(body, want) {
				t.Errorf("index body = %#v", body)
			}
			response.WriteHeader(http.StatusCreated)
			fmt.Fprintf(response, `{"_index":%q,"_id":%q,"_version":1,"result":"created","_shards":{"total":1,"successful":1,"failed":0},"_seq_no":0,"_primary_term":1}`, spec.Name, document.EventID)
		case 2:
			if request.Method != http.MethodPost || request.URL.EscapedPath() != "/"+spec.Name+"/_search" || request.URL.RawQuery != "" {
				t.Errorf("search request = %s %s?%s", request.Method, request.URL.EscapedPath(), request.URL.RawQuery)
			}
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode search body: %v", err)
			}
			want := map[string]any{
				"size": float64(10), "track_total_hits": true,
				"sort": []any{
					map[string]any{"event_time": map[string]any{"order": "asc"}},
					map[string]any{"event_id": map[string]any{"order": "asc"}},
				},
				"query": map[string]any{"bool": map[string]any{"filter": []any{
					map[string]any{"term": map[string]any{"organization_id": document.OrganizationID}},
					map[string]any{"term": map[string]any{"workspace_id": document.WorkspaceID}},
					map[string]any{"term": map[string]any{"environment_id": document.EnvironmentID}},
					map[string]any{"term": map[string]any{"session_id": document.SessionID}},
				}}},
			}
			if !reflect.DeepEqual(body, want) {
				t.Errorf("search body = %#v", body)
			}
			fmt.Fprintf(response, `{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":1,"relation":"eq"},"max_score":null,"hits":[{"_index":%q,"_id":%q,"_score":null,"_source":{"organization_id":%q,"workspace_id":%q,"environment_id":%q,"event_id":%q,"session_id":%q,"agent_id":%q,"source":"runtime_gateway","source_event_id":"source-event-1","event_class":"tool","action":"invoke","decision":"allowed","event_time":"2026-08-15T20:21:22.123Z"},"sort":[1786825282123,%q]}]}}`,
				spec.Name, document.EventID, document.OrganizationID, document.WorkspaceID, document.EnvironmentID,
				document.EventID, document.SessionID, document.AgentID, document.EventID)
		default:
			t.Errorf("unexpected request %d", step)
		}
	}))
	defer server.Close()

	backend, err := newHTTPBackend(context.Background(), server.URL, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	driver, err := newOpenSearchEventDriver(backend)
	if err != nil {
		t.Fatalf("newOpenSearchEventDriver: %v", err)
	}
	indexed, err := driver.Index(context.Background(), document)
	if err != nil || indexed != (eventstore.DriverIndexed{EventID: document.EventID}) {
		t.Fatalf("Index = %#v, %v", indexed, err)
	}
	documents, err := driver.Search(context.Background(), query)
	if err != nil || !reflect.DeepEqual(documents, []eventstore.DriverDocument{document}) {
		t.Fatalf("Search = %#v, %v", documents, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d", requests.Load())
	}
}

func productDriverDocument() eventstore.DriverDocument {
	return eventstore.DriverDocument{
		OrganizationID: "pid_10000000-0000-4000-8000-000000000001",
		WorkspaceID:    "pid_20000000-0000-4000-8000-000000000002",
		EnvironmentID:  "pid_30000000-0000-4000-8000-000000000003",
		EventID:        "pid_40000000-0000-4000-8000-000000000004",
		SessionID:      "pid_50000000-0000-4000-8000-000000000005",
		AgentID:        "pid_60000000-0000-4000-8000-000000000006",
		Source:         "runtime_gateway",
		SourceEventID:  "source-event-1",
		Class:          "tool",
		Action:         "invoke",
		Decision:       "allowed",
		EventTime:      "2026-08-15T20:21:22.123Z",
	}
}

func productDriverQuery(limit int) eventstore.DriverQuery {
	document := productDriverDocument()
	return eventstore.DriverQuery{
		OrganizationID: document.OrganizationID, WorkspaceID: document.WorkspaceID,
		EnvironmentID: document.EnvironmentID, SessionID: document.SessionID,
		Limit: limit, Sort: []string{"event_time", "event_id"},
	}
}

func TestOpenSearchEventDriverRejectsInvalidScopeBeforeIO(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	driver, err := newOpenSearchEventDriver(backend)
	if err != nil {
		t.Fatal(err)
	}
	document := productDriverDocument()
	document.OrganizationID = "foreign"
	if _, err := driver.Index(context.Background(), document); !errors.Is(err, errContent) {
		t.Fatalf("Index error = %v, want content", err)
	}
	query := productDriverQuery(10)
	query.Sort = []string{"event_id", "event_time"}
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, errScope) {
		t.Fatalf("Search error = %v, want scope", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid product state reached OpenSearch %d times", requests.Load())
	}
}

func TestOpenSearchEventDriverClassifiesCreateOnlyOutcomes(t *testing.T) {
	t.Parallel()
	document := productDriverDocument()
	spec := expectedIndexSpec(testMarker)
	t.Run("definitive rejection is never reconciled", func(t *testing.T) {
		var requests atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			writer.Header().Set("content-type", "application/json")
			writer.WriteHeader(http.StatusConflict)
			_, _ = writer.Write([]byte(`{"untrusted":true}`))
		}))
		defer server.Close()
		driver := productDriverForServer(t, server, spec)
		if _, err := driver.Index(context.Background(), document); !isRejectedMutation(err) {
			t.Fatalf("Index error = %v, want definitive rejection", err)
		}
		if requests.Load() != 1 {
			t.Fatalf("definitive rejection entered reconciliation: requests=%d", requests.Load())
		}
	})
	t.Run("malformed applied success reconciles exact state", func(t *testing.T) {
		var requests atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			step := requests.Add(1)
			writer.Header().Set("content-type", "application/json")
			if step == 1 {
				writer.WriteHeader(http.StatusCreated)
				_, _ = writer.Write([]byte(`{}`))
				return
			}
			if request.Method != http.MethodGet || request.URL.EscapedPath() != "/"+spec.Name+"/_doc/"+document.EventID {
				t.Errorf("reconcile request = %s %s", request.Method, request.URL.EscapedPath())
			}
			fmt.Fprintf(writer, `{"_index":%q,"_id":%q,"_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":{"organization_id":%q,"workspace_id":%q,"environment_id":%q,"event_id":%q,"session_id":%q,"agent_id":%q,"source":"runtime_gateway","source_event_id":"source-event-1","event_class":"tool","action":"invoke","decision":"allowed","event_time":"2026-08-15T20:21:22.123Z"}}`,
				spec.Name, document.EventID, document.OrganizationID, document.WorkspaceID, document.EnvironmentID,
				document.EventID, document.SessionID, document.AgentID)
		}))
		defer server.Close()
		driver := productDriverForServer(t, server, spec)
		indexed, err := driver.Index(context.Background(), document)
		if err != nil || indexed.EventID != document.EventID || requests.Load() != 2 {
			t.Fatalf("Index = %#v, %v; requests=%d", indexed, err, requests.Load())
		}
	})
}

func TestOpenSearchEventDriverRejectsMalformedForeignDuplicateAndUnorderedHits(t *testing.T) {
	t.Parallel()
	document := productDriverDocument()
	spec := expectedIndexSpec(testMarker)
	validHit := fmt.Sprintf(`{"_index":%q,"_id":%q,"_score":null,"_source":{"organization_id":%q,"workspace_id":%q,"environment_id":%q,"event_id":%q,"session_id":%q,"agent_id":%q,"source":"runtime_gateway","source_event_id":"source-event-1","event_class":"tool","action":"invoke","decision":"allowed","event_time":"2026-08-15T20:21:22.123Z"},"sort":[1786825282123,%q]}`,
		spec.Name, document.EventID, document.OrganizationID, document.WorkspaceID, document.EnvironmentID,
		document.EventID, document.SessionID, document.AgentID, document.EventID)
	tests := map[string]string{
		"duplicate hit":            validHit + "," + validHit,
		"foreign scope":            strings.Replace(validHit, document.OrganizationID, "pid_90000000-0000-4000-8000-000000000009", 1),
		"wrong sort":               strings.Replace(validHit, "1786825282123", "1786825282124", 1),
		"fractional sort":          strings.Replace(validHit, "1786825282123", "1786825282123.5", 1),
		"unknown provider field":   strings.Replace(validHit, `"_score":null`, `"_score":null,"provider":"detail"`, 1),
		"duplicate provider field": strings.Replace(validHit, `"_score":null`, `"_score":null,"_score":null`, 1),
	}
	for name, hits := range tests {
		name, hits := name, hits
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("content-type", "application/json")
				count := 1
				if name == "duplicate hit" {
					count = 2
				}
				fmt.Fprintf(writer, `{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":%d,"relation":"eq"},"max_score":null,"hits":[%s]}}`, count, hits)
			}))
			defer server.Close()
			driver := productDriverForServer(t, server, spec)
			if result, err := driver.Search(context.Background(), productDriverQuery(10)); err == nil || result != nil {
				t.Fatalf("Search accepted %s: %#v", name, result)
			}
		})
	}
}

func TestOpenSearchEventDriverAcceptsBoundedPageWhenMoreScopedHitsExist(t *testing.T) {
	t.Parallel()
	document := productDriverDocument()
	spec := expectedIndexSpec(testMarker)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		fmt.Fprintf(writer, `{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":2,"relation":"eq"},"max_score":null,"hits":[{"_index":%q,"_id":%q,"_score":null,"_source":{"organization_id":%q,"workspace_id":%q,"environment_id":%q,"event_id":%q,"session_id":%q,"agent_id":%q,"source":"runtime_gateway","source_event_id":"source-event-1","event_class":"tool","action":"invoke","decision":"allowed","event_time":"2026-08-15T20:21:22.123Z"},"sort":[1786825282123,%q]}]}}`,
			spec.Name, document.EventID, document.OrganizationID, document.WorkspaceID, document.EnvironmentID,
			document.EventID, document.SessionID, document.AgentID, document.EventID)
	}))
	defer server.Close()

	driver := productDriverForServer(t, server, spec)
	documents, err := driver.Search(context.Background(), productDriverQuery(1))
	if err != nil || !reflect.DeepEqual(documents, []eventstore.DriverDocument{document}) {
		t.Fatalf("Search bounded page = %#v, %v", documents, err)
	}
}

func productDriverForServer(t *testing.T, server *httptest.Server, spec IndexSpec) *openSearchEventDriver {
	t.Helper()
	backend, err := newHTTPBackend(context.Background(), server.URL, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Close)
	driver, err := newOpenSearchEventDriver(backend)
	if err != nil {
		t.Fatal(err)
	}
	return driver
}
