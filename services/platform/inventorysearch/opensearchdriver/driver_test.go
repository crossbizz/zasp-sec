package opensearchdriver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

type credentialProvider struct {
	calls atomic.Int32
	err   error
}

func (provider *credentialProvider) Retrieve(context.Context) (aws.Credentials, error) {
	provider.calls.Add(1)
	if provider.err != nil {
		return aws.Credentials{}, provider.err
	}
	return aws.Credentials{AccessKeyID: "AKIDEXPLICIT", SecretAccessKey: "secret-must-not-escape", SessionToken: "session-token", Source: "explicit-test-authority"}, nil
}

type recordingSigner struct {
	calls atomic.Int32
	err   error
	check func(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time)
}

func (signer *recordingSigner) SignHTTP(ctx context.Context, credentials aws.Credentials, request *http.Request, payloadHash, service, region string, signingTime time.Time, _ ...func(*v4.SignerOptions)) error {
	signer.calls.Add(1)
	if signer.check != nil {
		signer.check(ctx, credentials, request, payloadHash, service, region, signingTime)
	}
	if signer.err != nil {
		return signer.err
	}
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 signed-test-request")
	return nil
}

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) { return function(request) }

type panicCredentialProvider struct{}

func (panicCredentialProvider) Retrieve(context.Context) (aws.Credentials, error) {
	panic("credential secret panic")
}

type errorReadCloser struct {
	read func()
}

func (reader *errorReadCloser) Read([]byte) (int, error) {
	if reader.read != nil {
		reader.read()
		reader.read = nil
	}
	return 0, errors.New("response detail must not escape")
}

func (*errorReadCloser) Close() error { return nil }

func TestNewRequiresExplicitAWSAuthorityAndBuildsStrictTLSClient(t *testing.T) {
	t.Parallel()

	config := validConfig()
	credentials := &credentialProvider{}
	signer := &recordingSigner{}
	clock := fixedClock
	if _, err := New(config, nil, signer, clock); !errors.Is(err, inventorysearch.ErrConfiguration) {
		t.Fatalf("New(nil credentials) error = %v", err)
	}
	if _, err := New(config, credentials, nil, clock); !errors.Is(err, inventorysearch.ErrConfiguration) {
		t.Fatalf("New(nil signer) error = %v", err)
	}
	if _, err := New(config, credentials, signer, nil); !errors.Is(err, inventorysearch.ErrConfiguration) {
		t.Fatalf("New(nil clock) error = %v", err)
	}
	for _, endpoint := range []string{"http://search-zasp-abc.us-west-2.es.amazonaws.com", "https://localhost:9200", "https://example.com", "https://" + "user:secret@" + "search-zasp-abc.us-west-2.es.amazonaws.com", "https://search-zasp-abc.us-west-2.es.amazonaws.com/path", "https://search-zasp-abc.us-east-1.es.amazonaws.com"} {
		invalid := config
		invalid.Endpoint = endpoint
		if _, err := New(invalid, credentials, signer, clock); !errors.Is(err, inventorysearch.ErrConfiguration) {
			t.Fatalf("New(%q) error = %v", endpoint, err)
		}
	}
	driver, err := New(config, credentials, signer, clock)
	if err != nil {
		t.Fatalf("New(valid) error = %v", err)
	}
	client, ok := driver.client.(*http.Client)
	if !ok || client.Timeout != config.RequestTimeout || client.CheckRedirect == nil {
		t.Fatalf("client = %#v", driver.client)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < 0x0303 || transport.TLSClientConfig.ServerName != "search-zasp-abc.us-west-2.es.amazonaws.com" || !transport.ForceAttemptHTTP2 {
		t.Fatalf("transport = %#v", client.Transport)
	}
}

func TestReadyChecksExactSignedInventoryIndex(t *testing.T) {
	t.Parallel()
	credentials := &credentialProvider{}
	emptyDigest := sha256.Sum256(nil)
	signer := &recordingSigner{check: func(_ context.Context, _ aws.Credentials, request *http.Request, payloadHash, service, region string, _ time.Time) {
		if request.Method != http.MethodGet || request.URL.Path != "/"+indexName+"/_mapping" && request.URL.Path != "/"+indexName+"/_doc/"+schemaMarkerID || request.URL.RawQuery != "" || payloadHash != hex.EncodeToString(emptyDigest[:]) || service != "es" || region != "us-west-2" {
			t.Fatalf("readiness request = %s %s?%s digest=%q service=%q region=%q", request.Method, request.URL.Path, request.URL.RawQuery, payloadHash, service, region)
		}
	}}
	calls := 0
	driver, err := newWithClient(validConfig(), credentials, signer, doerFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		body := exactSchemaMappingResponse()
		if strings.Contains(request.URL.Path, "/_doc/") {
			body = exactSchemaMarkerResponse()
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}), fixedClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Ready(context.Background()); err != nil || calls != 2 || credentials.calls.Load() != 2 || signer.calls.Load() != 2 {
		t.Fatalf("Ready() error=%v calls=%d credentials=%d signer=%d", err, calls, credentials.calls.Load(), signer.calls.Load())
	}

	driver.client = doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("provider detail must not escape"))}, nil
	})
	if err := driver.Ready(context.Background()); !errors.Is(err, inventorysearch.ErrUnavailable) || strings.Contains(err.Error(), "provider detail") {
		t.Fatalf("Ready(missing index) error = %v", err)
	}
	driver.client = doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"zasp-inventory-v1":{"mappings":{"dynamic":true,"properties":{}}}}`))}, nil
	})
	if err := driver.Ready(context.Background()); !errors.Is(err, inventorysearch.ErrDrift) {
		t.Fatalf("Ready(mapping drift) error = %v", err)
	}
	readinessCall := 0
	driver.client = doerFunc(func(*http.Request) (*http.Response, error) {
		readinessCall++
		body := exactSchemaMappingResponse()
		if readinessCall == 2 {
			body = strings.Replace(exactSchemaMarkerResponse(), expectedSchemaMarker().MappingDigest, "sha256:"+strings.Repeat("0", 64), 1)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err := driver.Ready(context.Background()); !errors.Is(err, inventorysearch.ErrDrift) {
		t.Fatalf("Ready(marker drift) error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	before := credentials.calls.Load()
	if err := driver.Ready(canceled); !errors.Is(err, inventorysearch.ErrCanceled) || credentials.calls.Load() != before {
		t.Fatalf("Ready(canceled) error=%v credential calls=%d", err, credentials.calls.Load())
	}
}

func TestInitializeSchemaCreatesExactMappingAndImmutableMarkerThenReplays(t *testing.T) {
	t.Parallel()
	requests := []*http.Request{}
	responses := []string{`{"error":{"type":"index_not_found_exception"},"status":404}`, `{"acknowledged":true,"shards_acknowledged":true,"index":"zasp-inventory-v1"}`, `{"_index":"zasp-inventory-v1","_id":"_zasp_schema_v1","found":false}`, `{"_index":"zasp-inventory-v1","_id":"_zasp_schema_v1","_version":1,"result":"created","_shards":{"total":2,"successful":2,"failed":0},"_seq_no":0,"_primary_term":1}`}
	statuses := []int{404, 200, 404, 201}
	driver, err := newWithClient(validConfig(), &credentialProvider{}, &recordingSigner{}, doerFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Clone(request.Context()))
		index := len(requests) - 1
		return &http.Response{StatusCode: statuses[index], Body: io.NopCloser(strings.NewReader(responses[index]))}, nil
	}), fixedClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.InitializeSchema(context.Background()); err != nil {
		t.Fatalf("InitializeSchema() error = %v", err)
	}
	if len(requests) != 4 || requests[0].Method != http.MethodGet || requests[0].URL.Path != "/"+indexName+"/_mapping" || requests[1].Method != http.MethodPut || requests[1].URL.Path != "/"+indexName || requests[2].Method != http.MethodGet || requests[3].Method != http.MethodPut || requests[3].URL.Path != "/"+indexName+"/_doc/"+schemaMarkerID {
		t.Fatalf("schema requests = %#v", requests)
	}
}

func exactSchemaMappingResponse() string {
	var definition indexSchemaDefinition
	_ = json.Unmarshal([]byte(indexSchemaJSON), &definition)
	payload, _ := json.Marshal(map[string]indexSchemaDefinition{indexName: definition})
	return string(payload)
}

func exactSchemaMarkerResponse() string {
	payload, _ := json.Marshal(schemaMarkerRecord{Index: indexName, ID: schemaMarkerID, Version: 1, Sequence: 0, PrimaryTerm: 1, Found: true, Source: expectedSchemaMarker()})
	return string(payload)
}

func TestStageCreatesExactSignedImmutableDocumentsAndAcceptsEmpty(t *testing.T) {
	t.Parallel()

	input := fixtureStage()
	credentials := &credentialProvider{}
	signer := &recordingSigner{check: func(ctx context.Context, value aws.Credentials, request *http.Request, payloadHash, service, region string, signingTime time.Time) {
		if ctx == nil || !value.HasKeys() || value.Source != "explicit-test-authority" || service != "es" || region != "us-west-2" || !signingTime.Equal(fixedClock()) {
			t.Fatalf("signing authority = %#v service=%q region=%q time=%v", value, service, region, signingTime)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read signing body: %v", err)
		}
		request.Body = io.NopCloser(strings.NewReader(string(body)))
		digest := sha256.Sum256(body)
		if payloadHash != hex.EncodeToString(digest[:]) {
			t.Fatalf("payload hash = %q", payloadHash)
		}
	}}
	doerCalls := 0
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		doerCalls++
		if request.Method != http.MethodPost || request.URL.String() != validConfig().Endpoint+"/zasp-inventory-v1/_bulk?refresh=wait_for&timeout=5s" || request.Header.Get("Content-Type") != "application/x-ndjson" || request.Header.Get("Authorization") == "" {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL, request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != expectedBulkBody(input) || strings.Contains(string(body), "session-token") || strings.Contains(string(body), "secret-must-not-escape") {
			t.Fatalf("bulk body = %s", body)
		}
		return httpResponse(http.StatusOK, bulkCreateResponse(input)), nil
	})
	driver := mustTestDriver(t, credentials, signer, doer, fixedClock)
	result, err := driver.Stage(context.Background(), input)
	if err != nil || result.Snapshot != input.Snapshot || result.Replayed || !reflect.DeepEqual(result.DocumentIDs, documentIDs(input.Documents)) || credentials.calls.Load() != 1 || signer.calls.Load() != 1 {
		t.Fatalf("Stage() = %#v, %v, authority=%d/%d", result, err, credentials.calls.Load(), signer.calls.Load())
	}
	empty := input
	empty.Documents = []inventorysearch.DriverDocument{}
	result, err = driver.Stage(context.Background(), empty)
	if err != nil || len(result.DocumentIDs) != 0 || doerCalls != 1 {
		t.Fatalf("Stage(empty) = %#v, %v, HTTP=%d", result, err, doerCalls)
	}
}

func TestStageLostAcknowledgementReconcilesExactContentAndRejectsDrift(t *testing.T) {
	t.Parallel()

	input := fixtureStage()
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		nil, errors.New("Authorization=must-not-escape: reset after write"),
		httpResponse(http.StatusOK, exactMGetResponse(input)), nil,
	), fixedClock)
	result, err := driver.Stage(context.Background(), input)
	if err != nil || !result.Replayed {
		t.Fatalf("Stage(lost ACK) = %#v, %v", result, err)
	}

	drifted := input.Documents[0]
	drifted.Snapshot.ContentDigest[0] ^= 0xff
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, conflictBulkResponse(input)), nil,
		httpResponse(http.StatusOK, mgetResponse([]inventorysearch.DriverDocument{drifted, input.Documents[1]})), nil,
	), fixedClock)
	if _, err := driver.Stage(context.Background(), input); !errors.Is(err, inventorysearch.ErrDrift) || strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("Stage(drift) error = %q", err)
	}
}

func TestProductionBulkAndMultiGetMetadataDecodeStrictly(t *testing.T) {
	t.Parallel()

	input := fixtureStage()
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, bulkCreateResponse(input)), nil,
	), fixedClock)
	if result, err := driver.Stage(context.Background(), input); err != nil || result.Replayed {
		t.Fatalf("Stage(production metadata) = %#v, %v", result, err)
	}

	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		nil, errors.New("lost bulk acknowledgement"),
		httpResponse(http.StatusOK, exactMGetResponse(input)), nil,
	), fixedClock)
	if result, err := driver.Stage(context.Background(), input); err != nil || !result.Replayed {
		t.Fatalf("Stage(production mget metadata) = %#v, %v", result, err)
	}
}

func TestStageRejectsSecretAndNestedAttributesBeforeAWSOrHTTP(t *testing.T) {
	t.Parallel()

	for _, attribute := range []inventorysearch.Attribute{{Name: "access_token", Value: "plaintext"}, {Name: "engine", Value: `{"token":"plaintext"}`}} {
		input := fixtureStage()
		input.Documents[0].Attributes = []inventorysearch.Attribute{attribute}
		credentials := &credentialProvider{}
		signer := &recordingSigner{}
		driver := mustTestDriver(t, credentials, signer, doerFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("HTTP called for hostile input")
			return nil, nil
		}), fixedClock)
		if _, err := driver.Stage(context.Background(), input); !errors.Is(err, inventorysearch.ErrRejected) || credentials.calls.Load() != 0 || signer.calls.Load() != 0 {
			t.Fatalf("Stage(%#v) error=%v authority=%d/%d", attribute, err, credentials.calls.Load(), signer.calls.Load())
		}
	}
}

func TestActivateGenerationFencesInitialReplayStaleAndLostAcknowledgement(t *testing.T) {
	t.Parallel()

	input := fixtureActivation()
	t.Run("initial", func(t *testing.T) {
		driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
			httpResponse(http.StatusNotFound, `{"found":false}`), nil,
			httpResponse(http.StatusCreated, indexWriteResponse(input.Snapshot, "created")), nil,
		), fixedClock)
		result, err := driver.Activate(context.Background(), input)
		if err != nil || result.ActiveSnapshot != input.Snapshot || result.Replayed || !reflect.DeepEqual(result.ActiveDocumentIDs, input.DocumentIDs) {
			t.Fatalf("Activate(initial) = %#v, %v", result, err)
		}
	})
	t.Run("exact replay", func(t *testing.T) {
		driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t, httpResponse(http.StatusOK, markerResponse(input)), nil), fixedClock)
		result, err := driver.Activate(context.Background(), input)
		if err != nil || !result.Replayed || result.ActiveSnapshot != input.Snapshot {
			t.Fatalf("Activate(replay) = %#v, %v", result, err)
		}
	})
	t.Run("hostile marker identity", func(t *testing.T) {
		body := strings.Replace(markerResponse(input), markerID(input.Snapshot), "active_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
		driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t, httpResponse(http.StatusOK, body), nil), fixedClock)
		if _, err := driver.Activate(context.Background(), input); !errors.Is(err, inventorysearch.ErrDrift) {
			t.Fatalf("Activate(hostile marker) error = %v", err)
		}
	})
	t.Run("stale returns exact active binding", func(t *testing.T) {
		active := newerActivation(input)
		driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t, httpResponse(http.StatusOK, markerResponse(active)), nil), fixedClock)
		result, err := driver.Activate(context.Background(), input)
		if !errors.Is(err, inventorysearch.ErrStale) || result.ActiveSnapshot != active.Snapshot || !reflect.DeepEqual(result.ActiveDocumentIDs, active.DocumentIDs) {
			t.Fatalf("Activate(stale) = %#v, %v", result, err)
		}
	})
	t.Run("lost acknowledgement", func(t *testing.T) {
		driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
			httpResponse(http.StatusNotFound, `{"found":false}`), nil,
			nil, errors.New("connection reset after write"),
			httpResponse(http.StatusOK, markerResponse(input)), nil,
		), fixedClock)
		result, err := driver.Activate(context.Background(), input)
		if err != nil || !result.Replayed {
			t.Fatalf("Activate(lost ACK) = %#v, %v", result, err)
		}
	})
	t.Run("lost acknowledgement never reissues mutation", func(t *testing.T) {
		older := input
		older.Snapshot.Generation--
		older.Snapshot.SnapshotID = "pid_60000000-0000-4000-8000-000000000005"
		older.Snapshot.InputDigest = sha256.Sum256([]byte("older-input"))
		older.Snapshot.ContentDigest = sha256.Sum256([]byte("older-content"))
		driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
			httpResponse(http.StatusOK, markerResponse(older)), nil,
			nil, errors.New("connection reset after write"),
			httpResponse(http.StatusOK, markerResponse(older)), nil,
		), fixedClock)
		if _, err := driver.Activate(context.Background(), input); !errors.Is(err, inventorysearch.ErrUnknownOutcome) {
			t.Fatalf("Activate(unresolved lost ACK) error = %v", err)
		}
	})
}

func TestDiscardStageIsCurrentFencedAndPreservesActiveIDs(t *testing.T) {
	t.Parallel()

	candidate := fixtureActivation()
	active := newerActivation(candidate)
	input := inventorysearch.DriverDiscard{CandidateSnapshot: candidate.Snapshot, CandidateDocumentIDs: append([]string(nil), candidate.DocumentIDs...), ExpectedActiveSnapshot: active.Snapshot, ExpectedActiveDocumentIDs: append([]string(nil), active.DocumentIDs...)}
	requests := 0
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, doerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			return httpResponse(http.StatusOK, markerResponse(active)), nil
		case 2:
			if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/_mget") {
				t.Fatalf("candidate binding request = %s %s", request.Method, request.URL)
			}
			return httpResponse(http.StatusOK, exactMGetResponse(fixtureStage())), nil
		case 3:
			return httpResponse(http.StatusOK, markerResponse(active)), nil
		case 4:
			body, _ := io.ReadAll(request.Body)
			if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/_bulk") || strings.Contains(string(body), active.DocumentIDs[0]) {
				t.Fatalf("discard request = %s %s body=%s", request.Method, request.URL, body)
			}
			return httpResponse(http.StatusOK, bulkDeleteResponseBody(candidate.DocumentIDs)), nil
		case 5:
			return httpResponse(http.StatusOK, markerResponse(active)), nil
		default:
			t.Fatalf("unexpected request %d", requests)
			return nil, nil
		}
	}), fixedClock)
	result, err := driver.DiscardStage(context.Background(), input)
	if err != nil || result.CandidateSnapshot != candidate.Snapshot || result.ActiveSnapshot != active.Snapshot || result.Removed != len(candidate.DocumentIDs) || !reflect.DeepEqual(result.ActiveDocumentIDs, active.DocumentIDs) {
		t.Fatalf("DiscardStage() = %#v, %v", result, err)
	}

	changed := newerActivation(active)
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t, httpResponse(http.StatusOK, markerResponse(changed)), nil), fixedClock)
	if _, err := driver.DiscardStage(context.Background(), input); !errors.Is(err, inventorysearch.ErrStale) {
		t.Fatalf("DiscardStage(changed active) error = %v", err)
	}
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, markerResponse(active)), nil,
		httpResponse(http.StatusOK, exactMGetResponse(fixtureStage())), nil,
		httpResponse(http.StatusOK, markerResponse(active)), nil,
		httpResponse(http.StatusOK, bulkDeleteResponseBody(candidate.DocumentIDs)), nil,
		httpResponse(http.StatusOK, markerResponse(changed)), nil,
	), fixedClock)
	if _, err := driver.DiscardStage(context.Background(), input); !errors.Is(err, inventorysearch.ErrStale) {
		t.Fatalf("DiscardStage(active advanced after delete) error = %v", err)
	}
}

func TestDiscardStageBindsCandidateDocumentsAndReconcilesMissingReplay(t *testing.T) {
	t.Parallel()

	candidate := fixtureActivation()
	active := newerActivation(candidate)
	input := inventorysearch.DriverDiscard{CandidateSnapshot: candidate.Snapshot, CandidateDocumentIDs: append([]string(nil), candidate.DocumentIDs...), ExpectedActiveSnapshot: active.Snapshot, ExpectedActiveDocumentIDs: append([]string(nil), active.DocumentIDs...)}
	foreignStage := fixtureStage()
	foreignStage.Snapshot = active.Snapshot
	for index := range foreignStage.Documents {
		foreignStage.Documents[index].Snapshot = active.Snapshot
	}
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, markerResponse(active)), nil,
		httpResponse(http.StatusOK, mgetResponse(foreignStage.Documents)), nil,
	), fixedClock)
	if result, err := driver.DiscardStage(context.Background(), input); !errors.Is(err, inventorysearch.ErrDrift) || !reflect.DeepEqual(result, inventorysearch.DriverDiscarded{}) {
		t.Fatalf("DiscardStage(foreign candidate) = %#v, %v", result, err)
	}

	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, markerResponse(active)), nil,
		httpResponse(http.StatusOK, missingMGetResponse(candidate.DocumentIDs)), nil,
		httpResponse(http.StatusOK, markerResponse(active)), nil,
	), fixedClock)
	result, err := driver.DiscardStage(context.Background(), input)
	if err != nil || result.Removed != 0 || !result.Replayed || result.CandidateSnapshot != candidate.Snapshot || result.ActiveSnapshot != active.Snapshot {
		t.Fatalf("DiscardStage(missing replay) = %#v, %v", result, err)
	}
}

func TestRemoveStaleRechecksActiveFenceAndDeletesOnlyOlderGenerations(t *testing.T) {
	t.Parallel()

	active := newerActivation(fixtureActivation())
	requests := 0
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, doerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 || requests == 3 {
			return httpResponse(http.StatusOK, markerResponse(active)), nil
		}
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/_delete_by_query") || !strings.Contains(string(body), fmt.Sprintf(`"lt":%d`, active.Snapshot.Generation)) || strings.Contains(string(body), `"must_not"`) {
			t.Fatalf("cleanup request = %s %s body=%s", request.Method, request.URL, body)
		}
		return httpResponse(http.StatusOK, `{"took":3,"timed_out":false,"total":4,"deleted":4,"batches":1,"version_conflicts":0,"noops":0,"retries":{"bulk":0,"search":0},"throttled_millis":0,"requests_per_second":-1,"throttled_until_millis":0,"failures":[]}`), nil
	}), fixedClock)
	result, err := driver.RemoveStale(context.Background(), inventorysearch.DriverCleanup{ActiveSnapshot: active.Snapshot})
	if err != nil || result.ActiveSnapshot != active.Snapshot || result.Removed != 4 {
		t.Fatalf("RemoveStale() = %#v, %v", result, err)
	}

	older := fixtureActivation()
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t, httpResponse(http.StatusOK, markerResponse(active)), nil), fixedClock)
	if _, err := driver.RemoveStale(context.Background(), inventorysearch.DriverCleanup{ActiveSnapshot: older.Snapshot}); !errors.Is(err, inventorysearch.ErrStale) {
		t.Fatalf("RemoveStale(delayed old) error = %v", err)
	}
	newer := newerActivation(active)
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, markerResponse(active)), nil,
		httpResponse(http.StatusOK, `{"took":1,"timed_out":false,"total":0,"deleted":0,"batches":0,"version_conflicts":0,"noops":0,"retries":{"bulk":0,"search":0},"throttled_millis":0,"requests_per_second":-1,"throttled_until_millis":0,"failures":[]}`), nil,
		httpResponse(http.StatusOK, markerResponse(newer)), nil,
	), fixedClock)
	if _, err := driver.RemoveStale(context.Background(), inventorysearch.DriverCleanup{ActiveSnapshot: active.Snapshot}); !errors.Is(err, inventorysearch.ErrStale) {
		t.Fatalf("RemoveStale(active advanced after delete) error = %v", err)
	}
}

func TestSearchRequiresExactActiveSnapshotAndRejectsForeignRequestedKind(t *testing.T) {
	t.Parallel()

	stage := fixtureStage()
	activation := fixtureActivation()
	query := fixtureQuery(stage.Snapshot)
	requests := 0
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, doerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 || requests == 3 {
			return httpResponse(http.StatusOK, markerResponse(activation)), nil
		}
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != "/zasp-inventory-v1/_search" || !strings.Contains(string(body), hex.EncodeToString(query.ContentDigest[:])) || !strings.Contains(string(body), `"attributes.value"`) {
			t.Fatalf("search request = %s %s body=%s", request.Method, request.URL, body)
		}
		return httpResponse(http.StatusOK, searchResponseBody(stage.Documents)), nil
	}), fixedClock)
	result, err := driver.Search(context.Background(), query)
	if err != nil || len(result.Hits) != 2 || !reflect.DeepEqual(result.Hits, stage.Documents) || result.NextEntityID != stage.Documents[1].EntityID {
		t.Fatalf("Search() = %#v, %v", result, err)
	}

	foreign := stage.Documents[0]
	foreign.Kind = "github_repository"
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, markerResponse(activation)), nil,
		httpResponse(http.StatusOK, searchResponseBody([]inventorysearch.DriverDocument{foreign})), nil,
	), fixedClock)
	query.Kinds = []string{"database"}
	query.Limit = 1
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrDrift) {
		t.Fatalf("Search(foreign kind) error = %v", err)
	}
	newer := newerActivation(activation)
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, sequenceDoer(t,
		httpResponse(http.StatusOK, markerResponse(activation)), nil,
		httpResponse(http.StatusOK, searchResponseBody(stage.Documents)), nil,
		httpResponse(http.StatusOK, markerResponse(newer)), nil,
	), fixedClock)
	query.Kinds = []string{"aws_instance", "database"}
	query.Limit = 2
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrStale) {
		t.Fatalf("Search(active advanced after query) error = %v", err)
	}
}

func TestDriverBoundsCancellationAndAuthorityFailuresAreStableAndDoNotRetry(t *testing.T) {
	t.Parallel()

	query := fixtureQuery(fixtureStage().Snapshot)
	requests := 0
	driver := mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, doerFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return httpResponse(http.StatusTooManyRequests, `{"message":"provider secret detail"}`), nil
	}), fixedClock)
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrRetryable) || strings.Contains(err.Error(), "provider") || requests != 1 {
		t.Fatalf("Search(429) error=%q requests=%d", err, requests)
	}

	credentials := &credentialProvider{}
	signer := &recordingSigner{}
	doerCalls := 0
	driver = mustTestDriver(t, credentials, signer, doerFunc(func(*http.Request) (*http.Response, error) { doerCalls++; return nil, nil }), fixedClock)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := driver.Search(canceled, query); !errors.Is(err, inventorysearch.ErrCanceled) || credentials.calls.Load() != 0 || signer.calls.Load() != 0 || doerCalls != 0 {
		t.Fatalf("Search(canceled) error=%v authority=%d/%d doer=%d", err, credentials.calls.Load(), signer.calls.Load(), doerCalls)
	}

	signingContext, cancelSigning := context.WithCancel(context.Background())
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{check: func(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time) {
		cancelSigning()
	}}, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP after signing cancellation")
		return nil, nil
	}), fixedClock)
	if _, err := driver.Search(signingContext, query); !errors.Is(err, inventorysearch.ErrCanceled) {
		t.Fatalf("Search(signing canceled) error = %v", err)
	}

	readContext, cancelRead := context.WithCancel(context.Background())
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &errorReadCloser{read: cancelRead}}, nil
	}), fixedClock)
	if _, err := driver.Search(readContext, query); !errors.Is(err, inventorysearch.ErrCanceled) {
		t.Fatalf("Search(response read canceled) error = %v", err)
	}

	denied := &credentialProvider{err: errors.New("SecretAccessKey=must-not-escape")}
	driver = mustTestDriver(t, denied, &recordingSigner{}, doerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("HTTP after credential denial"); return nil, nil }), fixedClock)
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrDenied) || strings.Contains(err.Error(), "SecretAccessKey") {
		t.Fatalf("Search(denied) error = %q", err)
	}
	driver = mustTestDriver(t, panicCredentialProvider{}, &recordingSigner{}, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP after credential panic")
		return nil, nil
	}), fixedClock)
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrDenied) || strings.Contains(err.Error(), "panic") {
		t.Fatalf("Search(credential panic) error = %q", err)
	}
	driver = mustTestDriver(t, &credentialProvider{}, &recordingSigner{}, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP after clock panic")
		return nil, nil
	}), func() time.Time { panic("clock secret panic") })
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrDenied) || strings.Contains(err.Error(), "panic") {
		t.Fatalf("Search(clock panic) error = %q", err)
	}

	bounded := validConfig()
	bounded.MaximumResponseBytes = 32
	driver, err := newWithClient(bounded, &credentialProvider{}, &recordingSigner{}, doerFunc(func(*http.Request) (*http.Response, error) {
		return httpResponse(http.StatusOK, strings.Repeat("x", 33)), nil
	}), fixedClock)
	if err != nil {
		t.Fatalf("newWithClient(bounded) error = %v", err)
	}
	if _, err := driver.Search(context.Background(), query); !errors.Is(err, inventorysearch.ErrRetryable) {
		t.Fatalf("Search(oversized) error = %v", err)
	}
}

func validConfig() Config {
	return Config{Endpoint: "https://search-zasp-abc.us-west-2.es.amazonaws.com", Region: "us-west-2", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 4 << 20}
}

func fixedClock() time.Time { return time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC) }

func mustTestDriver(t *testing.T, credentials aws.CredentialsProvider, signer HTTPSigner, doer HTTPDoer, clock func() time.Time) *Driver {
	t.Helper()
	driver, err := newWithClient(validConfig(), credentials, signer, doer, clock)
	if err != nil {
		t.Fatalf("newWithClient() error = %v", err)
	}
	return driver
}

func fixtureStage() inventorysearch.DriverStage {
	inputDigest := sha256.Sum256([]byte("snapshot-7-input"))
	contentDigest := sha256.Sum256([]byte("snapshot-7-content"))
	snapshot := inventorysearch.DriverSnapshot{OrganizationID: "pid_10000000-0000-4000-8000-000000000001", WorkspaceID: "pid_20000000-0000-4000-8000-000000000002", EnvironmentID: "pid_30000000-0000-4000-8000-000000000003", IntegrationID: "pid_60000000-0000-4000-8000-000000000006", SnapshotID: "pid_70000000-0000-4000-8000-000000000007", Generation: 7, InputDigest: inputDigest, ContentDigest: contentDigest}
	return inventorysearch.DriverStage{Snapshot: snapshot, Documents: []inventorysearch.DriverDocument{
		{Snapshot: snapshot, DocumentID: "inv_4bea8b2f1c3c4ab4bc8b82ca513b04fdaca49dca4d1912070bea54c3fcfcb30b", EntityID: "pid_40000000-0000-4000-8000-000000000004", Kind: "aws_instance", DisplayName: "worker-a", Attributes: []inventorysearch.Attribute{{Name: "instance_type", Value: "m7g.large"}, {Name: "region", Value: "us-west-2"}}},
		{Snapshot: snapshot, DocumentID: "inv_8235a7b22be7a82bba80b9d9e18d3ef8f0da9c9b714e6415df40c1f5cb68cffb", EntityID: "pid_50000000-0000-4000-8000-000000000005", Kind: "database", DisplayName: "payments-db", Attributes: []inventorysearch.Attribute{{Name: "engine", Value: "postgres"}, {Name: "region", Value: "us-west-2"}}},
	}}
}

func fixtureActivation() inventorysearch.DriverActivation {
	stage := fixtureStage()
	return inventorysearch.DriverActivation{Snapshot: stage.Snapshot, DocumentIDs: documentIDs(stage.Documents)}
}

func newerActivation(previous inventorysearch.DriverActivation) inventorysearch.DriverActivation {
	next := previous
	next.Snapshot.SnapshotID = fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", next.Snapshot.Generation+1, next.Snapshot.Generation+1)
	next.Snapshot.Generation++
	next.Snapshot.InputDigest = sha256.Sum256([]byte(fmt.Sprintf("input-%d", next.Snapshot.Generation)))
	next.Snapshot.ContentDigest = sha256.Sum256([]byte(fmt.Sprintf("content-%d", next.Snapshot.Generation)))
	next.DocumentIDs = []string{"inv_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	return next
}

func fixtureQuery(snapshot inventorysearch.DriverSnapshot) inventorysearch.DriverQuery {
	return inventorysearch.DriverQuery{OrganizationID: snapshot.OrganizationID, WorkspaceID: snapshot.WorkspaceID, EnvironmentID: snapshot.EnvironmentID, IntegrationID: snapshot.IntegrationID, SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, ContentDigest: snapshot.ContentDigest, Text: "database", Kinds: []string{"aws_instance", "database"}, Limit: 2, Sort: []string{"entity_id"}}
}

func expectedBulkBody(input inventorysearch.DriverStage) string {
	var body strings.Builder
	for _, document := range input.Documents {
		action := []byte(fmt.Sprintf(`{"create":{"_index":%q,"_id":%q}}`, indexName, document.DocumentID))
		source, _ := json.Marshal(storedFromDriver(document))
		body.Write(action)
		body.WriteByte('\n')
		body.Write(source)
		body.WriteByte('\n')
	}
	return body.String()
}

func bulkCreateResponse(input inventorysearch.DriverStage) string {
	items := make([]string, len(input.Documents))
	for index, document := range input.Documents {
		items[index] = fmt.Sprintf(`{"create":{"_index":%q,"_id":%q,"_version":1,"result":"created","_shards":{"total":2,"successful":2,"failed":0},"_seq_no":%d,"_primary_term":1,"status":201,"forced_refresh":true}}`, indexName, document.DocumentID, index)
	}
	return fmt.Sprintf(`{"errors":false,"took":3,"items":[%s]}`, strings.Join(items, ","))
}

func conflictBulkResponse(input inventorysearch.DriverStage) string {
	items := make([]string, len(input.Documents))
	for index, document := range input.Documents {
		items[index] = fmt.Sprintf(`{"create":{"_index":%q,"_id":%q,"status":409,"error":{"type":"version_conflict_engine_exception","reason":"provider detail"}}}`, indexName, document.DocumentID)
	}
	return fmt.Sprintf(`{"errors":true,"took":2,"items":[%s]}`, strings.Join(items, ","))
}

func exactMGetResponse(input inventorysearch.DriverStage) string {
	return mgetResponse(input.Documents)
}

func mgetResponse(documents []inventorysearch.DriverDocument) string {
	items := make([]string, len(documents))
	for index, document := range documents {
		source, _ := json.Marshal(storedFromDriver(document))
		items[index] = fmt.Sprintf(`{"_index":%q,"_id":%q,"_version":1,"_seq_no":%d,"_primary_term":1,"found":true,"_source":%s}`, indexName, document.DocumentID, index, source)
	}
	return fmt.Sprintf(`{"docs":[%s]}`, strings.Join(items, ","))
}

func missingMGetResponse(ids []string) string {
	items := make([]string, len(ids))
	for index, id := range ids {
		items[index] = fmt.Sprintf(`{"_index":%q,"_id":%q,"found":false}`, indexName, id)
	}
	return fmt.Sprintf(`{"docs":[%s]}`, strings.Join(items, ","))
}

func markerResponse(input inventorysearch.DriverActivation) string {
	source, _ := json.Marshal(markerFromActivation(input))
	return fmt.Sprintf(`{"_index":%q,"_id":%q,"_version":1,"_seq_no":4,"_primary_term":1,"found":true,"_source":%s}`, indexName, markerID(input.Snapshot), source)
}

func indexWriteResponse(snapshot inventorysearch.DriverSnapshot, result string) string {
	return fmt.Sprintf(`{"_index":%q,"_id":%q,"_version":1,"result":%q,"_seq_no":4,"_primary_term":1,"_shards":{"total":2,"successful":2,"failed":0}}`, indexName, markerID(snapshot), result)
}

func bulkDeleteResponseBody(ids []string) string {
	items := make([]string, len(ids))
	for index, id := range ids {
		items[index] = fmt.Sprintf(`{"delete":{"_index":%q,"_id":%q,"_version":2,"result":"deleted","_shards":{"total":2,"successful":2,"failed":0},"_seq_no":%d,"_primary_term":1,"status":200,"forced_refresh":false}}`, indexName, id, index+10)
	}
	return fmt.Sprintf(`{"errors":false,"took":2,"items":[%s]}`, strings.Join(items, ","))
}

func searchResponseBody(documents []inventorysearch.DriverDocument) string {
	hits := make([]string, len(documents))
	for index, document := range documents {
		source, _ := json.Marshal(storedFromDriver(document))
		hits[index] = fmt.Sprintf(`{"_index":%q,"_id":%q,"_score":null,"_source":%s,"sort":[%q]}`, indexName, document.DocumentID, source, document.EntityID)
	}
	return fmt.Sprintf(`{"took":2,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":%d,"relation":"eq"},"max_score":null,"hits":[%s]}}`, len(documents), strings.Join(hits, ","))
}

func httpResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func sequenceDoer(t *testing.T, values ...any) HTTPDoer {
	t.Helper()
	index := 0
	return doerFunc(func(*http.Request) (*http.Response, error) {
		if index+1 >= len(values) {
			t.Fatalf("unexpected HTTP request %d", index/2+1)
		}
		response, _ := values[index].(*http.Response)
		err, _ := values[index+1].(error)
		index += 2
		return response, err
	})
}
