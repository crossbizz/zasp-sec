package opensearchdriver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

func sessionWriteFixture(t *testing.T) (sessionsearch.ReceiptBinding, []byte, []byte) {
	t.Helper()
	scope := testDriverBatch(t).Scope
	archive := []byte(`{"source":"tetragon","events":[{"event_id":"session-search-write-1","class":"file","action":"read","workload_id":"runtime-a","event_time":"2026-09-09T10:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008"}]}`)
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, archive)
	if err != nil {
		t.Fatal(err)
	}
	batchID := testProductID(t, 9)
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: scope, BatchID: batchID, Generation: 1, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(archive), Body: archive, Correlations: []runtimecorrelation.Result{{EventID: decoded.Records[0].ID, Confidence: domain.EvidenceConfidenceUnattributed}}})
	if err != nil {
		t.Fatal(err)
	}
	receipt := runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v1", Scope: scope, BatchID: batchID, Generation: 1, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-v1", InputDigest: sha256.Sum256([]byte("correlation")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(archive), EffectDigest: projected.ContentDigest, Items: projected.Items}
	body, digest, _, err := runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return sessionsearch.ReceiptBinding{Scope: scope, BatchID: batchID, Generation: 1, ReceiptDigest: digest}, body, archive
}

func sessionGetResponse(t *testing.T, document sessionsearch.Document) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"docs": []any{map[string]any{"_index": sessionIndexName, "_id": document.DocumentID, "_version": 1, "_seq_no": 0, "_primary_term": 1, "found": true, "_source": document}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestSessionIndexWriteReconcilesExactDocumentsBeforeSearchableReceipt(t *testing.T) {
	binding, receipt, archive := sessionWriteFixture(t)
	documents, err := sessionsearch.BuildDocuments(binding, receipt, archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, lost := range []bool{false, true} {
		writes, reads, refreshes := 0, 0, 0
		index := sessionIndexFixture(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
			switch request.Method + " " + request.URL.Path {
			case "POST /zasp-runtime-sessions-v1/_bulk":
				writes++
				body, _ := io.ReadAll(request.Body)
				lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
				if len(lines) != 2 || !strings.HasSuffix(string(body), "\n") || request.Header.Get("Content-Type") != "application/x-ndjson" || !strings.Contains(lines[0], `"create"`) || strings.Contains(lines[0], `"index":`) {
					t.Fatal("not bounded immutable bulk create")
				}
				var stored sessionsearch.Document
				if json.Unmarshal([]byte(lines[1]), &stored) != nil || stored != documents[0] {
					t.Fatal("unbound document write")
				}
				if lost {
					return nil, errors.New("provider-secret lost acknowledgement")
				}
				return jsonResponse(200, `{"errors":false,"took":1,"items":[]}`), nil
			case "POST /zasp-runtime-sessions-v1/_mget":
				reads++
				return jsonResponse(200, sessionGetResponse(t, documents[0])), nil
			case "POST /zasp-runtime-sessions-v1/_refresh":
				if reads != 1 {
					t.Fatal("refresh before exact readback")
				}
				refreshes++
				return jsonResponse(200, `{"_shards":{"total":1,"successful":1,"failed":0}}`), nil
			default:
				t.Fatalf("unexpected write operation %s %s", request.Method, request.URL)
				return nil, nil
			}
		}))
		result, err := index.Apply(context.Background(), binding, receipt, archive)
		if err != nil || result.ReceiptDigest != binding.ReceiptDigest || result.BatchID != binding.BatchID || result.Generation != binding.Generation || len(result.DocumentIDs) != 1 || result.DocumentIDs[0] != documents[0].DocumentID || writes != 1 || reads != 1 || refreshes != 1 {
			t.Fatalf("write result=%#v error=%v", result, err)
		}
	}
}

func TestSessionIndexWriteRejectsDriftMissingAndUnrefreshedDocuments(t *testing.T) {
	binding, receipt, archive := sessionWriteFixture(t)
	documents, _ := sessionsearch.BuildDocuments(binding, receipt, archive)
	for _, fault := range []string{"missing", "foreign", "version", "missing-metadata-version", "refresh", "refresh-denied"} {
		t.Run(fault, func(t *testing.T) {
			index := sessionIndexFixture(t, httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/zasp-runtime-sessions-v1/_bulk":
					return jsonResponse(200, `{"errors":true,"items":[]}`), nil
				case "/zasp-runtime-sessions-v1/_mget":
					body := sessionGetResponse(t, documents[0])
					switch fault {
					case "missing":
						body = strings.Replace(body, `"found":true`, `"found":false`, 1)
					case "foreign":
						body = strings.Replace(body, binding.Scope.OrganizationID().String(), testProductID(t, 99).String(), 1)
					case "version":
						body = strings.Replace(body, `"_version":1`, `"_version":2`, 1)
					case "missing-metadata-version":
						body = strings.Replace(body, `,"metadata_version":0`, ``, 1)
					}
					return jsonResponse(200, body), nil
				case "/zasp-runtime-sessions-v1/_refresh":
					if fault == "refresh-denied" {
						return jsonResponse(403, `{"error":"provider-secret"}`), nil
					}
					if fault != "refresh" {
						return jsonResponse(200, `{"_shards":{"total":1,"successful":1,"failed":0}}`), nil
					}
					return jsonResponse(200, `{"_shards":{"total":1,"successful":0,"failed":1}}`), nil
				default:
					t.Fatal("unexpected request")
					return nil, nil
				}
			}))
			if result, err := index.Apply(context.Background(), binding, receipt, archive); err == nil || result.DocumentIDs != nil || strings.Contains(err.Error(), "provider-secret") {
				t.Fatalf("false successful receipt: %#v %v", result, err)
			}
		})
	}
	index := &SessionIndex{transport: testDriver(t, httpDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unbound receipt made network call")
		return nil, nil
	}))}
	if _, err := index.Apply(context.Background(), binding, receipt, []byte("tampered")); !errors.Is(err, runtimeindex.ErrRejected) {
		t.Fatal(err)
	}
}
