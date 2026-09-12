package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

func TestSandboxIndexClockMustBeUTCBeforeSigning(t *testing.T) {
	for _, utc := range []bool{false, true} {
		calls := 0
		index := &SessionIndex{sandboxV2: true, transport: testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(404, `{"error":"missing"}`), nil
		}))}
		index.transport.clock = func() time.Time {
			now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.FixedZone("fixture-local", -7*60*60))
			if utc {
				return now.UTC()
			}
			return now
		}
		err := index.Ready(context.Background())
		if utc {
			if !errors.Is(err, runtimeindex.ErrRejected) || calls != 1 {
				t.Fatal("UTC clock did not reach provider", err, calls)
			}
		} else if !errors.Is(err, runtimeindex.ErrDenied) || calls != 0 {
			t.Fatal("local clock bypassed signing guard", err, calls)
		}
	}
}

func sandboxSessionWriteFixture(t *testing.T) (sessionsearch.ReceiptBinding, []byte, []byte) {
	t.Helper()
	binding, body, archive := sessionWriteFixture(t)
	receipt, err := runtimeprojection.DecodeReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	item := receipt.Items[0]
	correlation := runtimecorrelation.Result{EventID: item.EventID, AgentID: testProductID(t, 5), SessionID: testProductID(t, 6), Confidence: domain.EvidenceConfidenceStrong, SandboxID: "sandbox-a", SandboxSourceSensorID: testProductID(t, 7)}
	projected, err := runtimeprojection.ProjectSandbox(runtimeprojection.Batch{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: archive, Correlations: []runtimecorrelation.Result{correlation}})
	if err != nil {
		t.Fatal(err)
	}
	receipt.ImplementationVersion, receipt.Items, receipt.EffectDigest = "runtime-projection-v2", projected.Items, projected.ContentDigest
	body, binding.ReceiptDigest, _, err = runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return binding, body, archive
}

func TestLegacySessionIndexRejectsSandboxReceiptBeforeNetwork(t *testing.T) {
	binding, receipt, archive := sandboxSessionWriteFixture(t)
	calls := 0
	index := &SessionIndex{transport: testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected provider call")
	}))}
	if _, err := index.Apply(context.Background(), binding, receipt, archive); !errors.Is(err, runtimeindex.ErrRejected) || calls != 0 {
		t.Fatal("sandbox work reached legacy index", err, calls)
	}
}

func TestSandboxSessionIndexCreatesSeparateSchemaAndRetainsBothVersions(t *testing.T) {
	for _, profile := range []string{"sandbox", "historical-backfill", "precise"} {
		t.Run(profile, func(t *testing.T) {
			legacy := profile == "historical-backfill"
			binding, receipt, archive := sandboxSessionWriteFixture(t)
			if legacy {
				binding, receipt, archive = sessionWriteFixture(t)
			}
			if profile == "precise" {
				decoded, err := runtimeprojection.DecodeReceipt(receipt)
				if err != nil {
					t.Fatal(err)
				}
				archive = append([]byte(`{"version":"runtime-archive-v2",`), archive[1:]...)
				decoded.ArchiveDigest = sha256.Sum256(archive)
				item := decoded.Items[0]
				projected, err := runtimeprojection.ProjectPrecise(runtimeprojection.Batch{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ArchiveReference: decoded.ArchiveReference, ArchiveVersionID: decoded.ArchiveVersionID, ArchiveDigest: decoded.ArchiveDigest, Body: archive, Correlations: []runtimecorrelation.Result{{EventID: item.EventID, AgentID: item.AgentID, SessionID: item.SessionID, Confidence: item.Confidence, SandboxID: item.SandboxID, SandboxSourceSensorID: item.SandboxSourceSensorID}}})
				if err != nil {
					t.Fatal(err)
				}
				decoded.ImplementationVersion, decoded.Items, decoded.EffectDigest = "runtime-projection-v3", projected.Items, projected.ContentDigest
				receipt, binding.ReceiptDigest, _, err = runtimeprojection.EncodePreciseReceipt(decoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			var mapping, marker, stored json.RawMessage
			if profile == "precise" {
				deniedTransport := testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("precise bytes reached unsupported writer")
					return nil, nil
				}))
				legacyIndex := &SessionIndex{transport: deniedTransport}
				if _, err := legacyIndex.ApplyPrecise(context.Background(), binding, receipt, archive); !errors.Is(err, runtimeindex.ErrRejected) {
					t.Fatal("legacy target accepted precise write", err)
				}
				olderV2 := &SessionIndex{transport: deniedTransport, sandboxV2: true}
				if _, err := olderV2.Apply(context.Background(), binding, receipt, archive); !errors.Is(err, runtimeindex.ErrRejected) {
					t.Fatal("legacy method accepted precise bytes", err)
				}
			}
			var storedID string
			mappingWrites, markerWrites, writes, refreshes := 0, 0, 0, 0
			transport := testDriver(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				if !strings.HasPrefix(request.URL.Path, "/zasp-runtime-sessions-v2") {
					t.Fatalf("sandbox index touched old namespace: %s", request.URL.Path)
				}
				switch request.Method + " " + request.URL.Path {
				case "GET /zasp-runtime-sessions-v2/_mapping":
					if mapping == nil {
						return jsonResponse(404, `{"error":"missing"}`), nil
					}
					return jsonResponse(200, `{"zasp-runtime-sessions-v2":`+string(mapping)+`}`), nil
				case "PUT /zasp-runtime-sessions-v2":
					mappingWrites++
					mapping, _ = io.ReadAll(request.Body)
					var schema struct {
						Mappings struct {
							Dynamic    string                       `json:"dynamic"`
							Properties map[string]map[string]string `json:"properties"`
						} `json:"mappings"`
					}
					if json.Unmarshal(mapping, &schema) != nil || schema.Mappings.Dynamic != "strict" || schema.Mappings.Properties["sandbox_id"]["type"] != "keyword" || schema.Mappings.Properties["sandbox_source_sensor_id"]["type"] != "keyword" {
						t.Fatal("sandbox schema lacks exact binding", string(mapping))
					}
					return jsonResponse(200, `{"acknowledged":true}`), nil
				case "GET /zasp-runtime-sessions-v2/_doc/_zasp_session_schema_v2":
					if marker == nil {
						return jsonResponse(404, `{"found":false}`), nil
					}
					return jsonResponse(200, `{"_index":"zasp-runtime-sessions-v2","_id":"_zasp_session_schema_v2","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(marker)+`}`), nil
				case "PUT /zasp-runtime-sessions-v2/_doc/_zasp_session_schema_v2":
					markerWrites++
					marker, _ = io.ReadAll(request.Body)
					if request.URL.Query().Get("op_type") != "create" {
						t.Fatal("mutable marker write")
					}
					return jsonResponse(201, `{"result":"created"}`), nil
				case "POST /zasp-runtime-sessions-v2/_bulk":
					writes++
					body, _ := io.ReadAll(request.Body)
					lines := bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n"))
					if len(lines) != 2 {
						t.Fatal("unexpected bulk size")
					}
					var action bulkAction
					var document map[string]any
					if json.Unmarshal(lines[0], &action) != nil || action.Create.Index != "zasp-runtime-sessions-v2" || json.Unmarshal(lines[1], &document) != nil {
						t.Fatal("invalid bulk contract")
					}
					if !legacy && (document["sandbox_id"] != "sandbox-a" || document["sandbox_source_sensor_id"] != testProductID(t, 7).String() || document["confidence"] != "strong") {
						t.Fatal("sandbox identity lost")
					}
					if legacy && document["sandbox_id"] != nil {
						t.Fatal("invented historical binding")
					}
					if stored != nil && (!bytes.Equal(stored, lines[1]) || storedID != action.Create.ID) {
						t.Fatal("immutable replay changed")
					}
					stored, storedID = bytes.Clone(lines[1]), action.Create.ID
					return nil, errors.New("lost acknowledgement")
				case "POST /zasp-runtime-sessions-v2/_mget":
					return jsonResponse(200, `{"docs":[{"_index":"zasp-runtime-sessions-v2","_id":"`+storedID+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(stored)+`}]}`), nil
				case "POST /zasp-runtime-sessions-v2/_refresh":
					refreshes++
					return jsonResponse(200, `{"_shards":{"total":1,"successful":1,"failed":0}}`), nil
				case "POST /zasp-runtime-sessions-v2/_search":
					return jsonResponse(200, sessionSearchResponse("unattributed")), nil
				default:
					t.Fatalf("unexpected sandbox index request %s %s", request.Method, request.URL)
					return nil, nil
				}
			}))
			index, err := NewSandboxSessionIndex(transport.config, transport.credentials, transport.signer, transport.clock)
			if err != nil {
				t.Fatal(err)
			}
			defer index.Close()
			index.transport.client = transport.client
			apply := index.Apply
			if profile == "precise" {
				apply = index.ApplyPrecise
			}
			for i := 0; i < 2; i++ {
				if err := index.InitializeSchema(context.Background()); err != nil {
					t.Fatal(err)
				}
				result, err := apply(context.Background(), binding, receipt, archive)
				if err != nil || len(result.DocumentIDs) != 1 || result.DocumentIDs[0] != storedID || result.ReceiptDigest != binding.ReceiptDigest {
					t.Fatal("sandbox write not reconciled", err)
				}
			}
			page, err := index.Search(context.Background(), binding.Scope, sessionsearch.Filters{}, "", 25)
			if err != nil || len(page.InvestigationIDs) != 1 || page.InvestigationIDs[0] != "unattributed" {
				t.Fatal("v2 search unavailable", err)
			}
			if mappingWrites != 1 || markerWrites != 1 || writes != 2 || refreshes != 2 {
				t.Fatal("schema overwritten or write not refreshed")
			}
		})
	}
}

func TestSandboxSessionIndexRejectsDriftWithoutFalseCompletion(t *testing.T) {
	for _, fault := range []string{"mapping", "marker", "sandbox", "source", "missing-source", "foreign-index", "refresh"} {
		t.Run(fault, func(t *testing.T) {
			binding, receipt, archive := sandboxSessionWriteFixture(t)
			var stored json.RawMessage
			var storedID string
			writes, refreshes := 0, 0
			index := &SessionIndex{sandboxV2: true}
			index.transport = testDriver(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				if !strings.HasPrefix(request.URL.Path, "/zasp-runtime-sessions-v2/") {
					t.Fatal("wrong index namespace")
				}
				switch request.URL.Path {
				case "/zasp-runtime-sessions-v2/_mapping":
					mapping := index.schemaJSON()
					if fault == "mapping" {
						mapping = strings.Replace(mapping, `"sandbox_id":{"type":"keyword"}`, `"sandbox_id":{"type":"text"}`, 1)
					}
					return jsonResponse(200, `{"zasp-runtime-sessions-v2":`+mapping+`}`), nil
				case "/zasp-runtime-sessions-v2/_doc/_zasp_session_schema_v2":
					marker := index.expectedMarker()
					if fault == "marker" {
						marker = expectedSessionSchemaMarker()
					}
					body, _ := json.Marshal(marker)
					return jsonResponse(200, `{"_index":"zasp-runtime-sessions-v2","_id":"_zasp_session_schema_v2","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(body)+`}`), nil
				case "/zasp-runtime-sessions-v2/_bulk":
					writes++
					body, _ := io.ReadAll(request.Body)
					lines := bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n"))
					if len(lines) != 2 {
						t.Fatal("unexpected bulk size")
					}
					var action bulkAction
					if json.Unmarshal(lines[0], &action) != nil {
						t.Fatal("invalid action")
					}
					stored, storedID = bytes.Clone(lines[1]), action.Create.ID
					return jsonResponse(200, `{"errors":false}`), nil
				case "/zasp-runtime-sessions-v2/_mget":
					var document map[string]any
					if json.Unmarshal(stored, &document) != nil {
						t.Fatal("readback without write")
					}
					switch fault {
					case "sandbox":
						document["sandbox_id"] = "sandbox-b"
					case "source":
						document["sandbox_source_sensor_id"] = testProductID(t, 8).String()
					case "missing-source":
						delete(document, "sandbox_source_sensor_id")
					}
					name := "zasp-runtime-sessions-v2"
					if fault == "foreign-index" {
						name = "zasp-runtime-sessions-v1"
					}
					body, _ := json.Marshal(map[string]any{"docs": []any{map[string]any{"_index": name, "_id": storedID, "_version": 1, "_seq_no": 0, "_primary_term": 1, "found": true, "_source": document}}})
					return jsonResponse(200, string(body)), nil
				case "/zasp-runtime-sessions-v2/_refresh":
					refreshes++
					return jsonResponse(200, `{"_shards":{"total":1,"successful":0,"failed":1}}`), nil
				default:
					t.Fatal("unexpected request")
					return nil, nil
				}
			}))
			result, err := index.Apply(context.Background(), binding, receipt, archive)
			if err == nil || result.DocumentIDs != nil {
				t.Fatal("corrupt search state reported completion")
			}
			wantWrites, wantRefresh := 1, 0
			if fault == "mapping" || fault == "marker" {
				wantWrites = 0
			}
			if fault == "refresh" {
				wantRefresh = 1
			}
			if writes != wantWrites || refreshes != wantRefresh {
				t.Fatal("crossed failed search boundary", writes, refreshes)
			}
		})
	}
}
