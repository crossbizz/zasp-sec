package opensearchdriver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"io"
	"net/http"
	"strings"
	"testing"
)

type journalFlowAuthority struct {
	*terminalFlowAuthority
	begun, reserved, claimed, appended int
	descriptor                         runtimeindex.RetainedRequestDescriptor
	failure                            string
}

func (g *journalFlowAuthority) BeginRetainedExecution(_ context.Context, input runtimeindex.RetainedExecutionInput) (runtimeindex.RetainedExecutionJournal, error) {
	g.begun++
	if len(input.DocumentIDs) == 0 || len(input.DocumentIDs) != len(input.EventIDs) {
		return nil, runtimeindex.ErrRejected
	}
	return g, nil
}
func (g *journalFlowAuthority) ReserveRequest(_ context.Context, d runtimeindex.RetainedRequestDescriptor) error {
	g.reserved++
	g.descriptor = d
	if g.failure == "reserve failure" {
		return runtimeindex.ErrUnknownOutcome
	}
	hash, err := hex.DecodeString(d.BodySHA256)
	if err != nil || len(hash) != sha256.Size || d.BodyLength < 1 || d.Method != "POST" || d.Path != "/"+d.Target+"/_bulk" || d.MediaType != "application/x-ndjson" || d.SerializerProfile != "runtime-retained-bulk-v1" || len(d.DocumentIDs) == 0 || len(d.DocumentIDs) != len(d.EventIDs) {
		return runtimeindex.ErrRejected
	}
	return nil
}
func (g *journalFlowAuthority) ClaimSend(context.Context) (bool, error) {
	g.claimed++
	if g.failure == "unknown claim" {
		return true, runtimeindex.ErrUnknownOutcome
	}
	if g.failure == "replay claim" {
		return false, nil
	}
	return true, nil
}
func (g *journalFlowAuthority) AppendTerminal(_ context.Context, status int, body []byte) error {
	g.appended++
	if g.failure == "append failure" {
		return runtimeindex.ErrUnknownOutcome
	}
	if status != 200 || len(body) == 0 {
		return runtimeindex.ErrRejected
	}
	return nil
}
func TestRetainedJournalAtActualSerializedBulkBoundary(t *testing.T) {
	for _, family := range []string{"raw", "session-v1", "session-v2"} {
		for _, outcome := range []string{"created", "known conflict", "lost acknowledgement", "truncated response", "reserve failure", "unknown claim", "replay claim", "append failure"} {
			t.Run(family+"/"+outcome, func(t *testing.T) {
				binding, receipt, archive := sessionWriteFixture(t)
				if family == "session-v2" {
					binding, receipt, archive = sandboxSessionWriteFixture(t)
				}
				gate := &journalFlowAuthority{terminalFlowAuthority: &terminalFlowAuthority{}, failure: outcome}
				var captured []json.RawMessage
				var ids []string
				writes, reads, refreshes := 0, 0, 0
				var session *SessionIndex
				target := "zasp-runtime-events-v1"
				if family == "session-v1" {
					target = sessionIndexName
				}
				if family == "session-v2" {
					target = "zasp-runtime-sessions-v2"
				}
				doer := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
					switch {
					case strings.HasSuffix(request.URL.Path, "/_mapping"):
						return jsonResponse(200, `{"`+target+`":`+session.schemaJSON()+`}`), nil
					case strings.Contains(request.URL.Path, "/_doc/_zasp_session_schema_"):
						marker, _ := json.Marshal(session.expectedMarker())
						return jsonResponse(200, `{"_index":"`+target+`","_id":"`+session.markerID()+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(marker)+`}`), nil
					case strings.HasSuffix(request.URL.Path, "/_bulk"):
						writes++
						body, _ := io.ReadAll(request.Body)
						actual := sha256.Sum256(body)
						if gate.reserved != 1 || gate.claimed != 1 || gate.descriptor.BodySHA256 != hex.EncodeToString(actual[:]) || gate.descriptor.BodyLength != len(body) || gate.descriptor.Query != request.URL.RawQuery || gate.descriptor.Path != request.URL.Path {
							t.Fatal("transport crossed journal claim or exact serialized descriptor boundary")
						}

						lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
						ids = nil
						captured = nil
						for i := 0; i < len(lines); i += 2 {
							var action struct {
								Create struct {
									ID string `json:"_id"`
								} `json:"create"`
							}
							if i+1 >= len(lines) || json.Unmarshal([]byte(lines[i]), &action) != nil {
								t.Fatal("actual bulk fixture malformed")
							}
							ids = append(ids, action.Create.ID)
							captured = append(captured, json.RawMessage(lines[i+1]))
						}
						if outcome == "lost acknowledgement" {
							return nil, errors.New("private uncertain mutation")
						}
						if outcome == "response read failed" {
							return &http.Response{StatusCode: 200, Header: make(http.Header), Body: terminalFlowReadFailure{}}, nil
						}
						if outcome == "proxy unavailable" {
							return jsonResponse(503, `{"error":"private upstream failure"}`), nil
						}
						item := map[string]any{"_index": target, "_id": ids[0], "_version": 1, "result": "created", "status": 201, "_seq_no": 0, "_primary_term": 1, "_shards": map[string]int{"total": 1, "successful": 1, "failed": 0}}
						hasError := false
						switch outcome {
						case "underreplicated created":
							item["_shards"] = map[string]int{"total": 2, "successful": 1, "failed": 0}
						case "truncated response":
							return jsonResponse(200, `{"errors":false,"items":[`), nil
						case "missing items":
							return jsonResponse(200, `{"errors":false,"took":1,"items":[]}`), nil
						case "foreign item":
							item["_id"] = strings.Repeat("f", 64)
						case "missing sequence":
							delete(item, "_seq_no")
						case "unknown item status":
							item["status"] = 202
						case "known conflict", "unknown conflict", "inconsistent errors", "standard conflict metadata", "foreign embedded conflict index":
							hasError = true
							item = map[string]any{"_index": target, "_id": ids[0], "status": 409, "error": map[string]string{"type": "version_conflict_engine_exception", "reason": "private conflict"}}
							if outcome == "standard conflict metadata" || outcome == "foreign embedded conflict index" {
								metadata := map[string]any{"type": "version_conflict_engine_exception", "reason": "private conflict", "index": target, "index_uuid": "fixture-index-uuid", "shard": "0"}
								if outcome == "foreign embedded conflict index" {
									metadata["index"] = "foreign-index"
								}
								item["error"] = metadata
							}
							if outcome == "unknown conflict" {
								item["error"] = map[string]string{"type": "unrecognized_exception", "reason": "private"}
							}
							if outcome == "inconsistent errors" {
								hasError = false
							}
						}
						body, _ = json.Marshal(map[string]any{"errors": hasError, "took": 1, "items": []any{map[string]any{"create": item}}})
						if outcome == "duplicate keys" {
							body = []byte(strings.Replace(string(body), `"errors":false`, `"errors":true,"errors":false`, 1))
						}
						return jsonResponse(200, string(body)), nil
					case strings.HasSuffix(request.URL.Path, "/_mget"):
						reads++
						docs := make([]map[string]any, len(ids))
						for i, id := range ids {
							docs[i] = map[string]any{"_index": target, "_id": id, "_version": 1, "_seq_no": 0, "_primary_term": 1, "found": true, "_source": captured[i]}
						}
						body, _ := json.Marshal(map[string]any{"docs": docs})
						return jsonResponse(200, string(body)), nil
					case strings.HasSuffix(request.URL.Path, "/_refresh"):
						refreshes++
						return jsonResponse(200, `{"_shards":{"total":1,"successful":1,"failed":0}}`), nil
					default:
						t.Fatal("unexpected actual write flow operation")
						return nil, nil
					}
				})
				var err error
				var returnedIDs []string
				if family == "raw" {
					store, buildErr := runtimeindex.NewRetained(testDriver(t, doer), runtimeindex.Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000}, gate)
					if buildErr != nil {
						t.Fatal(buildErr)
					}
					result, applyErr := store.Apply(context.Background(), runtimeindex.Batch{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, InputDigest: sha256.Sum256(archive), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", Body: archive})
					err, returnedIDs = applyErr, result.DocumentIDs
				} else {
					session = &SessionIndex{transport: testDriver(t, doer), sandboxV2: family == "session-v2", retentionWrite: gate}
					result, applyErr := session.Apply(context.Background(), binding, receipt, archive)
					err, returnedIDs = applyErr, result.DocumentIDs
				}
				known := outcome == "created" || outcome == "underreplicated created" || outcome == "known conflict" || outcome == "standard conflict metadata"
				if known {
					if err != nil || len(returnedIDs) != 1 || gate.partitions != 1 || gate.admissions != 2 || writes != 1 {
						t.Fatalf("known terminal response lost full retained receipt: err=%v writes=%d partitions=%d", err, writes, gate.partitions)
					}
					if family != "raw" && (reads != 1 || refreshes != 1) {
						t.Fatal("session terminal response skipped readback/refresh")
					}
					if (outcome == "known conflict" || outcome == "standard conflict metadata") && reads != 1 {
						t.Fatal("known conflict not reconciled")
					}

				} else if outcome == "reserve failure" || outcome == "unknown claim" || outcome == "replay claim" {
					if !errors.Is(err, runtimeindex.ErrUnknownOutcome) || returnedIDs != nil || writes != 0 || reads != 0 || refreshes != 0 || gate.partitions != 0 {
						t.Fatal("unconfirmed claim crossed actual HTTP boundary")
					}
				} else if !errors.Is(err, runtimeindex.ErrUnknownOutcome) || returnedIDs != nil || gate.partitions != 0 || gate.admissions != 1 || writes != 1 || reads != 0 || refreshes != 0 {
					t.Fatalf("ambiguous mutation discharged admission through readback: err=%v writes=%d reads=%d refreshes=%d admissions=%d partitions=%d", err, writes, reads, refreshes, gate.admissions, gate.partitions)
				}
				if gate.begun != 1 || gate.reserved != 1 || (outcome != "reserve failure" && gate.claimed != 1) || (outcome == "reserve failure" && gate.claimed != 0) {
					t.Fatal("actual retained bulk bypassed committed execution/request/send journal")
				}
				if outcome == "created" || outcome == "known conflict" || outcome == "append failure" {
					if gate.appended != 1 {
						t.Fatal("strict actual terminal was not journaled")
					}
				} else if gate.appended != 0 {
					t.Fatal("ambiguous response became terminal evidence")
				}
			})
		}
	}
}
