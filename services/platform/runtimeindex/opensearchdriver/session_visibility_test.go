package opensearchdriver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type visibleDocumentVerifier interface {
	VerifyVisibleDocuments(context.Context, []sessionsearch.Document) error
}

type visibilityCancelAtEOF struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body visibilityCancelAtEOF) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	if err == io.EOF {
		body.cancel()
	}
	return n, err
}

func TestSessionVisibilityRefusesCancellationAtFinalResponseRead(t *testing.T) {
	binding, receipt, archive := sessionWriteFixture(t)
	documents, err := sessionsearch.BuildDocuments(binding, receipt, archive)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	index := sessionIndexFixture(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		wire, _ := json.Marshal(map[string]any{"took": 1, "timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "max_score": nil, "hits": []any{map[string]any{"_index": sessionIndexName, "_id": documents[0].DocumentID, "_version": 1, "_seq_no": 0, "_primary_term": 1, "_score": nil, "_source": documents[0]}}}})
		response := jsonResponse(200, string(wire))
		response.Body = visibilityCancelAtEOF{ReadCloser: response.Body, cancel: cancel}
		return response, nil
	}))
	if err := index.VerifyVisibleDocuments(ctx, documents); !errors.Is(err, runtimeindex.ErrCanceled) {
		t.Fatal("visibility succeeded after parent cancellation at final read")
	}
	if ctx.Err() == nil {
		t.Fatal("fixture did not cancel the actual parent")
	}
}

// An investigation aggregation can stay healthy while one occurrence is absent.
// The verifier must inspect full search hits, never aggregation or realtime mget.
func TestSessionVisibilityRequiresEveryExactSearchHit(t *testing.T) {
	binding, receipt, archive := sandboxSessionWriteFixture(t)
	documents, err := sessionsearch.BuildDocuments(binding, receipt, archive)
	if err != nil {
		t.Fatal(err)
	}
	second := documents[0]
	second.DocumentID = strings.Repeat("a", 64)
	second.EventID = testProductID(t, 88).String()
	documents = append(documents, second)
	for _, fault := range []string{"none", "missing", "duplicate", "foreign", "source", "version", "timeout", "partial", "early", "total", "malformed", "missing-sequence", "unknown-field", "mapping", "marker", "deadline"} {
		t.Run(fault, func(t *testing.T) {
			var calls []string
			var callsMu sync.Mutex
			var index *SessionIndex
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callsMu.Lock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				callsMu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /zasp-runtime-sessions-v2/_mapping":
					if fault == "mapping" {
						io.WriteString(w, `{}`)
						return
					}
					io.WriteString(w, `{"zasp-runtime-sessions-v2":`+index.schemaJSON()+`}`)
				case "GET /zasp-runtime-sessions-v2/_doc/_zasp_session_schema_v2":
					if fault == "marker" {
						http.Error(w, "missing", http.StatusNotFound)
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"_index": index.indexName(), "_id": index.markerID(), "_version": 1, "_seq_no": 0, "_primary_term": 1, "found": true, "_source": index.expectedMarker()})
				case "POST /zasp-runtime-sessions-v2/_search":
					var query map[string]any
					body, _ := io.ReadAll(r.Body)
					if json.Unmarshal(body, &query) != nil || query["size"] != float64(2) || query["track_total_hits"] != true || query["version"] != true || r.URL.Query().Get("allow_partial_search_results") != "false" {
						t.Error("unbounded visibility query", string(body), r.URL)
					}
					for _, field := range []string{"organization_id", "workspace_id", "environment_id", "ids", documents[0].DocumentID, second.DocumentID} {
						if !strings.Contains(string(body), field) {
							t.Error("missing scope or exact ID", field)
						}
					}
					filters := query["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
					for i, field := range []string{"organization_id", "workspace_id", "environment_id"} {
						want := []string{binding.Scope.OrganizationID().String(), binding.Scope.WorkspaceID().String(), binding.Scope.EnvironmentID().String()}[i]
						if filters[i].(map[string]any)["term"].(map[string]any)[field] != want {
							t.Error("wrong tenant filter", field)
						}
					}
					if fault == "deadline" {
						select {
						case <-r.Context().Done():
						case <-time.After(time.Second):
						}
						return
					}
					hits := []map[string]any{}
					for i := len(documents) - 1; i >= 0; i-- {
						hits = append(hits, map[string]any{"_index": index.indexName(), "_id": documents[i].DocumentID, "_version": 1, "_seq_no": i, "_primary_term": 1, "_score": nil, "_source": documents[i]})
					}
					shards := map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0}
					total := map[string]any{"value": 2, "relation": "eq"}
					response := map[string]any{"took": 1, "timed_out": false, "_shards": shards, "hits": map[string]any{"total": total, "max_score": nil, "hits": hits}}
					switch fault {
					case "missing":
						response["hits"].(map[string]any)["hits"] = hits[:1]
					case "duplicate":
						hits[1] = hits[0]
					case "foreign":
						hits[0]["_index"] = "foreign-index"
					case "source":
						altered := second
						altered.SandboxID = "forged"
						hits[0]["_source"] = altered
					case "version":
						hits[0]["_version"] = 2
					case "timeout":
						response["timed_out"] = true
					case "partial":
						shards["successful"] = 0
						shards["failed"] = 1
					case "early":
						response["terminated_early"] = true
					case "total":
						total["relation"] = "gte"
					case "malformed":
						io.WriteString(w, `{"took":1,"took":2}`)
						return
					case "missing-sequence":
						delete(hits[0], "_seq_no")
					case "unknown-field":
						hits[0]["unexpected"] = true
					}
					json.NewEncoder(w).Encode(response)
				default:
					t.Error("visibility attempted non-read route", r.Method, r.URL)
					http.Error(w, "rejected", 400)
				}
			}))
			defer server.Close()
			index = &SessionIndex{sandboxV2: true, transport: testDriver(t, server.Client())}
			index.transport.endpoint, _ = url.Parse(server.URL)
			verifier, ok := any(index).(visibleDocumentVerifier)
			if !ok {
				t.Fatal("exact document search visibility verification is missing")
			}
			ctx := context.Background()
			if fault == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			err := verifier.VerifyVisibleDocuments(ctx, documents)
			if (err == nil) != (fault == "none") {
				t.Fatalf("fault=%s error=%v", fault, err)
			}
			if fault == "deadline" && !errors.Is(err, runtimeindex.ErrCanceled) {
				t.Fatal("inherited deadline not preserved", err)
			}
			wantCalls := 3
			callsMu.Lock()
			defer callsMu.Unlock()
			if fault == "mapping" {
				wantCalls = 1
			}
			if fault == "marker" {
				wantCalls = 2
			}
			if len(calls) != wantCalls {
				t.Fatalf("expected mapping, marker and one search, got %v", calls)
			}
		})
	}
}

func TestSessionVisibilityRejectsUnboundedOrMixedAuthorityBeforeIO(t *testing.T) {
	binding, receipt, archive := sandboxSessionWriteFixture(t)
	documents, err := sessionsearch.BuildDocuments(binding, receipt, archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"empty", "too-many", "duplicate", "mixed-scope", "invalid-scope", "invalid-id", "wrong-record", "bytes", "request-bytes", "cancelled", "nil-context"} {
		t.Run(fault, func(t *testing.T) {
			input := append([]sessionsearch.Document(nil), documents...)
			index := &SessionIndex{sandboxV2: true, transport: testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
				t.Error("invalid authority reached provider")
				return jsonResponse(500, `{}`), nil
			}))}
			ctx := context.Background()
			switch fault {
			case "empty":
				input = nil
			case "too-many":
				input = make([]sessionsearch.Document, 1001)
			case "duplicate":
				input = append(input, input[0])
			case "mixed-scope":
				other := input[0]
				other.DocumentID = strings.Repeat("a", 64)
				other.EnvironmentID = testProductID(t, 99).String()
				input = append(input, other)
			case "invalid-scope":
				input[0].OrganizationID = "*"
			case "invalid-id":
				input[0].DocumentID = "../other"
			case "wrong-record":
				input[0].RecordType = "schema_marker"
			case "bytes":
				input[0].SandboxID = strings.Repeat("a", 1<<20)
			case "request-bytes":
				index.transport.config.MaximumRequestBytes = 1
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			if err := index.VerifyVisibleDocuments(ctx, input); err == nil {
				t.Fatal("invalid input accepted", fault)
			}
		})
	}
}
