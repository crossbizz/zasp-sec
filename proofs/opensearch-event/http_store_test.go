package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPBackendUsesTheStrictScopedOpenSearchRESTContract(t *testing.T) {
	t.Parallel()
	spec := expectedIndexSpec(testMarker)
	event := expectedEvent(testMarker, "org-a-"+testMarker)
	fixture := newOpenSearchHTTPFixture(t, spec)
	server := httptest.NewServer(fixture)
	defer server.Close()

	backend, err := newHTTPBackend(context.Background(), server.URL, spec)
	if err != nil {
		t.Fatalf("newHTTPBackend returned %v", err)
	}
	defer backend.Close()

	if indexes, err := backend.ListIndexes(context.Background(), proofPrefix+testMarker); err != nil || len(indexes) != 0 {
		t.Fatalf("initial ListIndexes = %#v, %v", indexes, err)
	}
	created, err := backend.CreateIndex(context.Background(), spec)
	if err != nil || !validIndexState(created, spec) {
		t.Fatalf("CreateIndex = %#v, %v", created, err)
	}
	inspected, err := backend.InspectIndex(context.Background(), spec.Name)
	if err != nil || !validIndexState(inspected, spec) {
		t.Fatalf("InspectIndex = %#v, %v", inspected, err)
	}
	scope, err := newOrganizationScope(event.OrganizationID)
	if err != nil {
		t.Fatalf("newOrganizationScope returned %v", err)
	}
	if err := backend.IndexSessionEvent(context.Background(), scope, event); err != nil {
		t.Fatalf("IndexSessionEvent returned %v", err)
	}
	hits, err := backend.QuerySession(context.Background(), scope, SessionFilter{SessionID: event.SessionID, EnvironmentID: event.EnvironmentID})
	if err != nil || !reflect.DeepEqual(hits, []NormalizedSessionEvent{event}) {
		t.Fatalf("QuerySession = %#v, %v", hits, err)
	}
	documents, err := backend.ListDocuments(context.Background(), spec.Name, 2)
	if err != nil || !reflect.DeepEqual(documents, []NormalizedSessionEvent{event}) {
		t.Fatalf("ListDocuments = %#v, %v", documents, err)
	}
	if err := backend.DeleteIndex(context.Background(), spec.Name); err != nil {
		t.Fatalf("DeleteIndex returned %v", err)
	}
	if indexes, err := backend.ListIndexes(context.Background(), proofPrefix+testMarker); err != nil || len(indexes) != 0 {
		t.Fatalf("final ListIndexes = %#v, %v", indexes, err)
	}

	fixture.assertContract(t, event)
}

func TestHTTPBackendRejectsMissingOrMismatchedScopeBeforeIO(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
	if err != nil {
		t.Fatalf("newHTTPBackend returned %v", err)
	}
	defer backend.Close()
	event := expectedEvent(testMarker, "org-a-"+testMarker)
	if err := backend.IndexSessionEvent(context.Background(), OrganizationScope{}, event); !errors.Is(err, errScope) {
		t.Fatalf("IndexSessionEvent error = %v, want scope", err)
	}
	foreign, _ := newOrganizationScope("org-b-" + testMarker)
	if err := backend.IndexSessionEvent(context.Background(), foreign, event); !errors.Is(err, errScope) {
		t.Fatalf("IndexSessionEvent mismatch error = %v, want scope", err)
	}
	if _, err := backend.QuerySession(context.Background(), OrganizationScope{}, SessionFilter{SessionID: event.SessionID, EnvironmentID: event.EnvironmentID}); !errors.Is(err, errScope) {
		t.Fatalf("QuerySession error = %v, want scope", err)
	}
	if requests.Load() != 0 {
		t.Fatal("invalid scope reached OpenSearch")
	}
}

func TestHTTPBackendRejectsAProviderResultOutsideTheRequestedOrganization(t *testing.T) {
	t.Parallel()
	spec := expectedIndexSpec(testMarker)
	foreign := expectedEvent(testMarker, "org-a-"+testMarker)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("content-type", "application/json")
		if request.Method != http.MethodPost || request.URL.Path != "/"+spec.Name+"/_search" {
			t.Error("unexpected provider request")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(t, writer, map[string]any{
			"took": 1, "timed_out": false, "_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
			"hits": map[string]any{
				"total": map[string]any{"value": 1, "relation": "eq"}, "max_score": nil,
				"hits": []map[string]any{{"_index": spec.Name, "_id": foreign.EventID, "_score": nil, "_source": foreign}},
			},
		})
	}))
	defer server.Close()
	backend, err := newHTTPBackend(context.Background(), server.URL, spec)
	if err != nil {
		t.Fatalf("newHTTPBackend returned %v", err)
	}
	defer backend.Close()
	scope, _ := newOrganizationScope("org-b-" + testMarker)
	filter := SessionFilter{SessionID: foreign.SessionID, EnvironmentID: foreign.EnvironmentID}
	if _, err := backend.QuerySession(context.Background(), scope, filter); !errors.Is(err, errScope) {
		t.Fatalf("QuerySession error = %v, want scope", err)
	}
}

func TestDecodeExactJSONRejectsProviderSchemaMutations(t *testing.T) {
	t.Parallel()
	valid := `{"acknowledged":true,"shards_acknowledged":true,"index":"proof"}`
	var response createIndexResponse
	if err := decodeExactJSON([]byte(valid), &response); err != nil {
		t.Fatalf("decodeExactJSON rejected valid response: %v", err)
	}
	invalid := []string{
		``, `null`, `[]`,
		`{"acknowledged":true,"shards_acknowledged":true}`,
		`{"acknowledged":true,"shards_acknowledged":true,"index":null}`,
		`{"acknowledged":true,"acknowledged":false,"shards_acknowledged":true,"index":"proof"}`,
		`{"Acknowledged":true,"shards_acknowledged":true,"index":"proof"}`,
		`{"acknowledged":true,"shards_acknowledged":true,"index":"proof","extra":true}`,
		`{"acknowledged":true,"shards_acknowledged":true,"index":"proof"}{}`,
	}
	for _, raw := range invalid {
		response = createIndexResponse{}
		if err := decodeExactJSON([]byte(raw), &response); err == nil {
			t.Fatal("decodeExactJSON accepted malformed or non-exact provider JSON")
		}
	}
}

func TestHTTPBackendRetriesOnlySafeReadsAndBoundsResponses(t *testing.T) {
	t.Parallel()
	t.Run("safe transient read retries once", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			if attempts.Add(1) == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writer.Header().Set("content-type", "application/json")
			_, _ = writer.Write([]byte(`[]`))
		}))
		defer server.Close()
		backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
		if err != nil {
			t.Fatalf("newHTTPBackend returned %v", err)
		}
		defer backend.Close()
		if _, err := backend.ListIndexes(context.Background(), proofPrefix+testMarker); err != nil {
			t.Fatalf("ListIndexes returned %v", err)
		}
		if attempts.Load() != 2 {
			t.Fatalf("safe read attempts = %d, want 2", attempts.Load())
		}
	})
	t.Run("mutation never retries", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			writer.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
		if err != nil {
			t.Fatalf("newHTTPBackend returned %v", err)
		}
		defer backend.Close()
		_, _ = backend.CreateIndex(context.Background(), expectedIndexSpec(testMarker))
		if attempts.Load() != 1 {
			t.Fatalf("mutation attempts = %d, want 1", attempts.Load())
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("content-type", "application/json")
			_, _ = writer.Write([]byte(strings.Repeat("x", maximumResponseBytes+1)))
		}))
		defer server.Close()
		backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
		if err != nil {
			t.Fatalf("newHTTPBackend returned %v", err)
		}
		defer backend.Close()
		if _, err := backend.ListIndexes(context.Background(), proofPrefix+testMarker); !errors.Is(err, errProvider) {
			t.Fatalf("oversized ListIndexes error = %v", err)
		}
	})
	t.Run("endless body respects caller deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("content-type", "application/json")
			flusher := writer.(http.Flusher)
			for {
				if _, err := writer.Write([]byte(" ")); err != nil {
					return
				}
				flusher.Flush()
				time.Sleep(5 * time.Millisecond)
			}
		}))
		defer server.Close()
		backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
		if err != nil {
			t.Fatalf("newHTTPBackend returned %v", err)
		}
		defer backend.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		started := time.Now()
		if _, err := backend.ListIndexes(ctx, proofPrefix+testMarker); !errors.Is(err, errProvider) {
			t.Fatalf("stalled ListIndexes error = %v", err)
		}
		if time.Since(started) > 500*time.Millisecond {
			t.Fatal("stalled response exceeded the caller deadline")
		}
	})
}

func TestEndpointAndDialerAcceptOnlyExplicitLoopbackHTTP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, valid := range []string{"http://127.0.0.1:49152", "http://[::1]:49153", "http://localhost:49154"} {
		if _, err := validateEndpoint(ctx, valid, staticResolver{addresses: []string{"127.0.0.1", "::1"}}); err != nil {
			t.Errorf("validateEndpoint rejected valid loopback endpoint")
		}
	}
	for _, invalid := range []string{
		"", "https://127.0.0.1:49152", "http://127.0.0.1", "http://127.0.0.1:80",
		"http://0.0.0.0:49152", "http://example.com:49152", "http://user@127.0.0.1:49152",
		"http://127.0.0.1:49152/", "http://127.0.0.1:49152/path", "http://127.0.0.1:49152?x=1",
	} {
		if _, err := validateEndpoint(ctx, invalid, staticResolver{addresses: []string{"203.0.113.10"}}); err == nil {
			t.Error("validateEndpoint accepted an invalid destination")
		}
	}

	endpoint := validatedEndpoint{hostname: "localhost", port: "49152"}
	var dialed []string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("unavailable")
	}
	loopback := loopbackDialerWithResolverAndDialer(endpoint, staticResolver{addresses: []string{"127.0.0.1", "::1"}}, dial)
	_, _ = loopback(context.Background(), "tcp", "localhost:49152")
	if !reflect.DeepEqual(dialed, []string{"127.0.0.1:49152", "[::1]:49152"}) {
		t.Fatalf("dialed = %v", dialed)
	}
	beforeForeignHost := len(dialed)
	if _, err := loopback(context.Background(), "tcp", "127.0.0.1:49152"); !errors.Is(err, errConfiguration) {
		t.Fatalf("foreign loopback host dial error = %v", err)
	}
	if len(dialed) != beforeForeignHost {
		t.Fatal("dialer reached a loopback host outside the validated endpoint identity")
	}
	rebound := loopbackDialerWithResolverAndDialer(endpoint, staticResolver{addresses: []string{"127.0.0.1", "203.0.113.10"}}, dial)
	before := len(dialed)
	if _, err := rebound(context.Background(), "tcp", "localhost:49152"); !errors.Is(err, errConfiguration) {
		t.Fatalf("rebound dial error = %v", err)
	}
	if len(dialed) != before {
		t.Fatal("dialer reached a destination after non-loopback resolution")
	}
}

type staticResolver struct{ addresses []string }

func (r staticResolver) LookupHost(context.Context, string) ([]string, error) {
	return append([]string(nil), r.addresses...), nil
}

type openSearchHTTPFixture struct {
	t       *testing.T
	spec    IndexSpec
	created bool
	event   *NormalizedSessionEvent
	queries []map[string]any
	creates []map[string]any
	writes  []map[string]any
}

func newOpenSearchHTTPFixture(t *testing.T, spec IndexSpec) *openSearchHTTPFixture {
	return &openSearchHTTPFixture{t: t, spec: spec}
}

func (f *openSearchHTTPFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("content-type", "application/json")
	switch {
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/_cat/indices/"):
		if request.URL.Query().Get("format") != "json" || request.URL.Query().Get("h") != "index" || request.URL.Query().Get("expand_wildcards") != "all" {
			f.t.Error("CAT indices query was not exact")
		}
		if f.created {
			writeJSON(f.t, writer, []map[string]string{{"index": f.spec.Name}})
		} else {
			writeJSON(f.t, writer, []map[string]string{})
		}
	case request.Method == http.MethodPut && request.URL.Path == "/"+f.spec.Name && request.URL.RawQuery == "":
		f.creates = append(f.creates, decodeMap(f.t, request))
		f.created = true
		writeJSON(f.t, writer, map[string]any{"acknowledged": true, "shards_acknowledged": true, "index": f.spec.Name})
	case request.Method == http.MethodGet && request.URL.Path == "/"+f.spec.Name+"/_mapping":
		writeJSON(f.t, writer, mappingResponse(f.spec))
	case request.Method == http.MethodGet && request.URL.Path == "/"+f.spec.Name+"/_settings/index.number_of_shards,index.number_of_replicas":
		if request.URL.Query().Get("flat_settings") != "true" || request.URL.Query().Get("include_defaults") != "false" {
			f.t.Error("settings query was not exact")
		}
		writeJSON(f.t, writer, map[string]any{f.spec.Name: map[string]any{"settings": map[string]string{"index.number_of_shards": "1", "index.number_of_replicas": "0"}}})
	case request.Method == http.MethodPut && request.URL.Path == "/"+f.spec.Name+"/_doc/event-"+testMarker:
		if request.URL.Query().Get("refresh") != "wait_for" || request.URL.Query().Get("timeout") != "5s" {
			f.t.Error("document mutation query was not bounded")
		}
		body := decodeMap(f.t, request)
		f.writes = append(f.writes, body)
		encoded, _ := json.Marshal(body)
		var event NormalizedSessionEvent
		if err := json.Unmarshal(encoded, &event); err != nil {
			f.t.Error("document body did not match the normalized event")
		}
		f.event = &event
		writeJSON(f.t, writer, map[string]any{
			"_index": f.spec.Name, "_id": event.EventID, "_version": 1, "result": "created",
			"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0}, "_seq_no": 0, "_primary_term": 1,
		})
	case request.Method == http.MethodPost && request.URL.Path == "/"+f.spec.Name+"/_search":
		query := decodeMap(f.t, request)
		f.queries = append(f.queries, query)
		var hits []map[string]any
		if f.event != nil && queryMatchesEvent(query, *f.event) {
			hits = append(hits, map[string]any{"_index": f.spec.Name, "_id": f.event.EventID, "_score": nil, "_source": f.event})
		}
		writeJSON(f.t, writer, map[string]any{
			"took": 1, "timed_out": false, "_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
			"hits": map[string]any{"total": map[string]any{"value": len(hits), "relation": "eq"}, "max_score": nil, "hits": hits},
		})
	case request.Method == http.MethodDelete && request.URL.Path == "/"+f.spec.Name:
		f.created, f.event = false, nil
		writeJSON(f.t, writer, map[string]bool{"acknowledged": true})
	default:
		f.t.Errorf("unexpected OpenSearch request method/path")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{}`))
	}
}

func (f *openSearchHTTPFixture) assertContract(t *testing.T, event NormalizedSessionEvent) {
	t.Helper()
	if len(f.creates) != 1 || len(f.writes) != 1 || len(f.queries) != 2 {
		t.Fatalf("request counts create=%d write=%d query=%d", len(f.creates), len(f.writes), len(f.queries))
	}
	mappings := f.creates[0]["mappings"].(map[string]any)
	if mappings["dynamic"] != "strict" {
		t.Fatal("create body omitted strict mapping")
	}
	properties := mappings["properties"].(map[string]any)
	if len(properties) != 12 {
		t.Fatalf("mapping property count = %d", len(properties))
	}
	for _, forbidden := range []string{"prompt", "response", "content", "body", "secret"} {
		if _, exists := f.writes[0][forbidden]; exists {
			t.Fatalf("durable event included forbidden field %q", forbidden)
		}
	}
	if f.writes[0]["organization_id"] != event.OrganizationID || f.writes[0]["session_id"] != event.SessionID || f.writes[0]["environment_id"] != event.EnvironmentID {
		t.Fatal("durable event lost required Organization/session/Environment scope")
	}
	filters := f.queries[0]["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	if len(filters) != 3 || f.queries[0]["size"] != float64(2) || f.queries[0]["track_total_hits"] != true {
		t.Fatal("scoped query was not the exact bounded three-filter contract")
	}
}

func mappingResponse(spec IndexSpec) map[string]any {
	properties := map[string]any{}
	for name, fieldType := range spec.Fields {
		if strings.HasPrefix(fieldType, "date:") {
			properties[name] = map[string]any{"type": "date", "format": strings.TrimPrefix(fieldType, "date:")}
		} else {
			properties[name] = map[string]any{"type": fieldType}
		}
	}
	return map[string]any{spec.Name: map[string]any{"mappings": map[string]any{
		"dynamic": spec.Dynamic, "_meta": map[string]any{"zasp_proof": "m0-08", "zasp_marker": spec.Marker, "zasp_role": spec.Role}, "properties": properties,
	}}}
}

func queryMatchesEvent(query map[string]any, event NormalizedSessionEvent) bool {
	queryNode, ok := query["query"].(map[string]any)
	if !ok {
		return false
	}
	if _, matchAll := queryNode["match_all"]; matchAll {
		return true
	}
	boolNode, ok := queryNode["bool"].(map[string]any)
	if !ok {
		return false
	}
	filters, ok := boolNode["filter"].([]any)
	if !ok {
		return false
	}
	want := map[string]string{"organization_id": event.OrganizationID, "session_id": event.SessionID, "environment_id": event.EnvironmentID}
	for _, raw := range filters {
		term := raw.(map[string]any)["term"].(map[string]any)
		for field, value := range term {
			if want[field] != value {
				return false
			}
			delete(want, field)
		}
	}
	return len(want) == 0
}

func decodeMap(t *testing.T, request *http.Request) map[string]any {
	t.Helper()
	defer request.Body.Close()
	var result map[string]any
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("request JSON decode failed: %v", err)
	}
	return result
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("fixture response encode failed: %v", err)
	}
}

func TestHTTPBackendRefusesRedirectsAndAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://203.0.113.10:65535")
	t.Setenv("HTTPS_PROXY", "http://203.0.113.11:65535")
	var redirected atomic.Bool
	foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("location", foreign.URL)
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	backend, err := newHTTPBackend(context.Background(), server.URL, expectedIndexSpec(testMarker))
	if err != nil {
		t.Fatalf("newHTTPBackend returned %v", err)
	}
	defer backend.Close()
	_, _ = backend.ListIndexes(context.Background(), proofPrefix+testMarker)
	if redirected.Load() {
		t.Fatal("OpenSearch client followed a redirect")
	}
}
