package opensearchdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

type purgeAuthorityFunc func(context.Context, domain.Scope, string) error

func (f purgeAuthorityFunc) AuthorizeRetentionPurge(ctx context.Context, s domain.Scope, id string) error {
	return f(ctx, s, id)
}

func TestRetentionPurgeConditionalScopedEffectsAndReconciliation(t *testing.T) {
	for _, kind := range []string{"raw", "session"} {
		for _, mode := range []string{"confirmed", "lost acknowledgement", "already absent", "foreign source", "changed sequence", "authority revoked", "readback unavailable", "late replay", "many batches converge across bounded retries", "missing search envelope"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				scope := testDriverBatch(t).Scope
				event := testProductID(t, 7).String()
				target, record, idPrefix := indexName, "runtime_event", "evt_"
				if kind == "session" {
					target, record, idPrefix = sessionIndexName, "runtime_session_event", ""
				}
				documents := map[string]bool{}
				n := 1
				if mode == "already absent" {
					n = 0
				}
				if mode == "many batches converge across bounded retries" {
					n = 65
				}
				for i := 0; i < n; i++ {
					documents[idPrefix+fmt.Sprintf("%064x", i+1)] = true
				}
				deletes, searches, authorityCalls := 0, 0, 0
				doer := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
					path := request.URL.Path
					if path == "/"+target+"/_mapping" {
						schema := indexSchemaJSON
						if kind == "session" {
							schema = sessionIndexSchemaJSON
						}
						return jsonResponse(200, `{"`+target+`":`+schema+`}`), nil
					}
					markerID, marker := schemaMarkerID, expectedSchemaMarker()
					if kind == "session" {
						markerID, marker = sessionSchemaMarkerID, expectedSessionSchemaMarker()
					}
					if path == "/"+target+"/_doc/"+markerID {
						raw, _ := json.Marshal(marker)
						return jsonResponse(200, `{"_index":"`+target+`","_id":"`+markerID+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(raw)+`}`), nil
					}
					if path == "/"+target+"/_search" {
						searches++
						body, _ := io.ReadAll(request.Body)
						for _, literal := range []string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), event, record, `"seq_no_primary_term":true`, `"track_total_hits":true`} {
							if !strings.Contains(string(body), literal) {
								t.Fatalf("unscoped query: %s", body)
							}
						}
						if request.Method != http.MethodPost || strings.Contains(path, "*") {
							t.Fatal("unbounded target")
						}
						if mode == "missing search envelope" {
							return jsonResponse(200, `{}`), nil
						}
						if mode == "late replay" && searches > 1 {
							documents[idPrefix+fmt.Sprintf("%064x", 99)] = true
						}
						keys := []string{}
						for id := range documents {
							keys = append(keys, id)
						}
						// Closed query sorts document_id ascending; fixture mirrors that order.
						sort.Strings(keys)
						hits := []any{}
						for i, id := range keys {
							if i == 64 {
								break
							}
							org := scope.OrganizationID().String()
							if mode == "foreign source" {
								org = testProductID(t, 99).String()
							}
							hits = append(hits, map[string]any{"_index": target, "_id": id, "_seq_no": 7, "_primary_term": 2, "_score": nil, "sort": []string{id}, "_source": map[string]string{"organization_id": org, "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "record_type": record, "event_id": event, "document_id": id}})
						}
						response, _ := json.Marshal(map[string]any{"took": 1, "timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": len(keys), "relation": "eq"}, "max_score": nil, "hits": hits}})
						return jsonResponse(200, string(response)), nil
					}
					id := strings.TrimPrefix(path, "/"+target+"/_doc/")
					if id == path {
						t.Fatalf("arbitrary mutation target: %s", path)
					}
					switch request.Method {
					case http.MethodDelete:
						deletes++
						q := request.URL.Query()
						if q.Get("if_seq_no") != "7" || q.Get("if_primary_term") != "2" || q.Get("refresh") != "wait_for" {
							t.Fatalf("unconditional delete %s", request.URL)
						}
						if mode == "changed sequence" {
							return jsonResponse(http.StatusConflict, `{"error":"private-provider-detail"}`), nil
						}
						delete(documents, id)
						if mode == "lost acknowledgement" {
							return nil, errors.New("private-provider-detail")
						}
						return jsonResponse(200, `{"_index":"`+target+`","_id":"`+id+`","result":"deleted"}`), nil
					case http.MethodGet:
						if mode == "readback unavailable" {
							return jsonResponse(503, `{"error":"private-provider-detail"}`), nil
						}
						return jsonResponse(404, `{"_index":"`+target+`","_id":"`+id+`","found":false}`), nil
					default:
						t.Fatalf("unexpected %s %s", request.Method, path)
					}
					return nil, nil
				})
				authority := purgeAuthorityFunc(func(_ context.Context, got domain.Scope, id string) error {
					authorityCalls++
					if got != scope || id != event {
						t.Fatal("authority scope changed")
					}
					if mode == "authority revoked" && authorityCalls > 1 {
						return runtimeindex.ErrDenied
					}
					return nil
				})
				var purger *RetentionPurger
				var err error
				if kind == "raw" {
					purger, err = NewRawRetentionPurger(testDriver(t, doer), authority)
				} else {
					purger, err = NewSessionRetentionPurger(&SessionIndex{transport: testDriver(t, doer)}, authority)
				}
				if err != nil {
					t.Fatal(err)
				}
				outcome, err := purger.PurgeEvent(context.Background(), scope, event)
				success := mode == "confirmed" || mode == "lost acknowledgement" || mode == "already absent"
				if success {
					if err != nil || !outcome.IndexObservedEmpty || outcome.DocumentsAbsent != n {
						t.Fatalf("confirmed scoped absence not reconciled: %+v %v", outcome, err)
					}
				} else {
					if err == nil || outcome.IndexObservedEmpty || strings.Contains(err.Error(), "private-provider-detail") {
						t.Fatalf("uncertain cleanup accepted: %+v %v", outcome, err)
					}
				}
				if (mode == "foreign source" || mode == "authority revoked" || mode == "missing search envelope" || mode == "already absent") && deletes != 0 {
					t.Fatal("unadmitted delete")
				}
				if mode == "many batches converge across bounded retries" {
					if deletes != 64 || outcome.DocumentsAbsent != 64 {
						t.Fatalf("bounded cohort made no safe progress: %+v deletes=%d", outcome, deletes)
					}
					firstDeletes := deletes
					next, nextErr := purger.PurgeEvent(context.Background(), scope, event)
					if nextErr != nil || !next.IndexObservedEmpty || next.DocumentsAbsent != 1 || deletes-firstDeletes != 1 || len(documents) != 0 {
						t.Fatalf("many-batch retry never converged: %+v %v deletes=%d", next, nextErr, deletes)
					}
				} else if deletes > 64 {
					t.Fatal("unbounded cleanup effects")
				}
			})
		}
	}
}

func TestRetentionPurgeRequiresRealDriverAndClaimAuthority(t *testing.T) {
	denyNetwork := httpDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid purge constructor performed network I/O")
		return nil, nil
	})
	authority := purgeAuthorityFunc(func(context.Context, domain.Scope, string) error { return nil })
	driver := testDriver(t, denyNetwork)
	if p, err := NewRawRetentionPurger(driver, nil); err == nil || p != nil {
		t.Fatal("missing claim authority admitted")
	}
	if p, err := NewRawRetentionPurger(&Driver{}, authority); err == nil || p != nil {
		t.Fatal("unconfigured driver admitted")
	}
	if p, err := NewSessionRetentionPurger(&SessionIndex{}, authority); err == nil || p != nil {
		t.Fatal("unconfigured session index admitted")
	}
	p, err := NewRawRetentionPurger(driver, authority)
	if err != nil {
		t.Fatal(err)
	}
	if p.FixedKind() != "raw-index" {
		t.Fatal("raw cleanup intent binding changed")
	}
	for _, family := range []struct {
		sandbox bool
		kind    string
	}{{false, "session-index-v1"}, {true, "session-index-v2"}} {
		target, err := NewSessionRetentionPurger(&SessionIndex{transport: driver, sandboxV2: family.sandbox}, authority)
		if err != nil || target.FixedKind() != family.kind {
			t.Fatal("session cleanup intent crossed fixed index generation")
		}
	}
	if result, err := p.PurgeEvent(context.Background(), domain.Scope{}, "*"); err == nil || result.IndexObservedEmpty {
		t.Fatal("invalid tenant/event admitted")
	}
}
