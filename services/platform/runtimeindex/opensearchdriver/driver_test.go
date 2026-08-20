package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
)

func TestDriverAppliesProductionBulkCreateExactly(t *testing.T) {
	input := testDriverBatch(t)
	doer := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/zasp-runtime-events-v1/_bulk" || request.URL.Query().Get("refresh") != "wait_for" || request.URL.Query().Get("timeout") != "5s" || request.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Fatalf("request=%s %s headers=%v", request.Method, request.URL.String(), request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		if !bytes.HasSuffix(body, []byte("\n")) || !bytes.Contains(body, []byte(`{"create":{"_index":"zasp-runtime-events-v1","_id":"evt_`)) || !bytes.Contains(body, []byte(`"archive_version_id":"version-1"`)) {
			t.Fatalf("body=%s", body)
		}
		return jsonResponse(http.StatusOK, `{"errors":false,"took":1,"items":[{"create":{"_index":"zasp-runtime-events-v1","_id":"`+input.Documents[0].DocumentID+`","_version":1,"result":"created","status":201,"_seq_no":0,"_primary_term":1,"_shards":{"total":2,"successful":2,"failed":0}}}]}`), nil
	})
	driver := testDriver(t, doer)
	result, err := driver.Apply(context.Background(), input)
	if err != nil || result.BatchID != input.BatchID || result.Generation != input.Generation || result.InputDigest != input.InputDigest || result.ContentDigest != input.ContentDigest || len(result.DocumentIDs) != 1 || result.DocumentIDs[0] != input.Documents[0].DocumentID || result.Replayed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestDriverReconcilesLostBulkAcknowledgementWithoutReissue(t *testing.T) {
	input := testDriverBatch(t)
	calls := 0
	doer := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("secret transport body")
		}
		if request.URL.Path != "/zasp-runtime-events-v1/_mget" {
			t.Fatalf("path=%s", request.URL.Path)
		}
		source := expectedStoredDocument(input, input.Documents[0])
		encoded, _ := json.Marshal(source)
		return jsonResponse(http.StatusOK, `{"docs":[{"_index":"zasp-runtime-events-v1","_id":"`+input.Documents[0].DocumentID+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(encoded)+`} ]}`), nil
	})
	driver := testDriver(t, doer)
	result, err := driver.Apply(context.Background(), input)
	if err != nil || !result.Replayed || calls != 2 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, calls)
	}
}

func TestDriverRejectsDriftAndRedactsProviderFailures(t *testing.T) {
	input := testDriverBatch(t)
	for _, test := range []struct {
		name string
		doer HTTPDoer
		want error
	}{
		{name: "denied", doer: httpDoerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusForbidden, `{"message":"secret"}`), nil
		}), want: runtimeindex.ErrDenied},
		{name: "retryable", doer: httpDoerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusTooManyRequests, `{"message":"secret"}`), nil
		}), want: runtimeindex.ErrRetryable},
		{name: "drift", doer: httpDoerFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/zasp-runtime-events-v1/_bulk" {
				return jsonResponse(http.StatusOK, `{"errors":true,"took":1,"items":[{"create":{"_index":"zasp-runtime-events-v1","_id":"`+input.Documents[0].DocumentID+`","status":409,"error":{"type":"version_conflict_engine_exception","reason":"secret"}}}]}`), nil
			}
			source := expectedStoredDocument(input, input.Documents[0])
			source.ArchiveVersionID = "drift"
			encoded, _ := json.Marshal(source)
			return jsonResponse(http.StatusOK, `{"docs":[{"_index":"zasp-runtime-events-v1","_id":"`+input.Documents[0].DocumentID+`","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(encoded)+`}]}`), nil
		}), want: runtimeindex.ErrDrift},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := testDriver(t, test.doer)
			result, err := driver.Apply(context.Background(), input)
			if !errors.Is(err, test.want) || result.BatchID != "" || result.DocumentIDs != nil || strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestDriverReadinessRequiresExactMappingAndImmutableMarker(t *testing.T) {
	requests := 0
	doer := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Path {
		case "/zasp-runtime-events-v1/_mapping":
			return jsonResponse(http.StatusOK, `{"zasp-runtime-events-v1":`+indexSchemaJSON+`}`), nil
		case "/zasp-runtime-events-v1/_doc/_zasp_schema_v1":
			marker, _ := json.Marshal(expectedSchemaMarker())
			return jsonResponse(http.StatusOK, `{"_index":"zasp-runtime-events-v1","_id":"_zasp_schema_v1","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":`+string(marker)+`}`), nil
		default:
			t.Fatalf("path=%s", request.URL.Path)
			return nil, nil
		}
	})
	if err := testDriver(t, doer).Ready(context.Background()); err != nil || requests != 2 {
		t.Fatalf("err=%v requests=%d", err, requests)
	}

	drift := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/zasp-runtime-events-v1/_mapping" {
			return jsonResponse(http.StatusOK, `{"zasp-runtime-events-v1":{"mappings":{"dynamic":true}}}`), nil
		}
		return nil, errors.New("unexpected")
	})
	if err := testDriver(t, drift).Ready(context.Background()); !errors.Is(err, runtimeindex.ErrDrift) {
		t.Fatalf("err=%v", err)
	}
}

func testDriver(t *testing.T, doer HTTPDoer) *Driver {
	t.Helper()
	driver, err := newWithClient(Config{Endpoint: "https://search-runtime.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 1 << 20, MaximumResponseBytes: 1 << 20}, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret", SessionToken: "token"}, nil
	}), signerStub{}, doer, func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func testDriverBatch(t *testing.T) runtimeindex.DriverBatch {
	t.Helper()
	scope, _ := domain.NewScope(testProductID(t, 1), testProductID(t, 2), testProductID(t, 3))
	inputDigest := sha256.Sum256([]byte("input"))
	contentDigest := sha256.Sum256([]byte("content"))
	document := runtimeindex.DriverDocument{RecordType: "runtime_event", DocumentID: "evt_" + strings.Repeat("a", 64), EventID: testProductID(t, 7).String(), Source: "tetragon", SourceEventID: "event-1", EventClass: "process", Action: "exec", WorkloadID: "runtime-a", TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), EventTime: "2026-08-20T12:00:00.000Z", EvidenceID: testProductID(t, 8).String(), ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "version-1"}
	return runtimeindex.DriverBatch{Scope: scope, BatchID: testProductID(t, 9).String(), Generation: 3, InputDigest: inputDigest, ContentDigest: contentDigest, ArchiveReference: document.ArchiveReference, ArchiveVersionID: document.ArchiveVersionID, Documents: []runtimeindex.DriverDocument{document}}
}

func testProductID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (function httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type signerStub struct{}

func (signerStub) SignHTTP(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) error {
	return nil
}
