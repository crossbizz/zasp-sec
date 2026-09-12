package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestRuntimePrecisionProofRequiresAllExplicitFlags(t *testing.T) {
	for _, item := range []struct {
		only, sandbox, precise string
		want                   bool
	}{
		{"", "", "", false}, {"true", "true", "", false}, {"true", "", "true", false}, {"", "true", "true", false}, {"true", "true", "TRUE", false}, {"true", "true", "true", true},
	} {
		t.Run(item.only+"/"+item.sandbox+"/"+item.precise, func(t *testing.T) {
			t.Setenv("ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY", item.only)
			t.Setenv("ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH", item.sandbox)
			t.Setenv("ZASP_COMBINED_E2E_RUNTIME_PRECISION", item.precise)
			if got := runtimePrecisionProofEnabled(); got != item.want {
				t.Fatalf("precision enabled=%t want=%t", got, item.want)
			}
		})
	}
}

func runtimePrecisionProofEnabled() bool {
	return runtimeSandboxSearchCutoverEnabled() && os.Getenv("ZASP_COMBINED_E2E_RUNTIME_PRECISION") == "true"
}

func TestRuntimePrecisionBrowserCheckpointClient(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, body := range []string{`{"released":true}`, `{"released":false}`, `{"released":true,"extra":1}`, `{"released":true}{}`, `{"released":true,"released":false}`, strings.Repeat("x", 1025)} {
		t.Run(body[:min(len(body), 40)], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/checkpoint" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Content-Type") != "application/json" {
					t.Error("checkpoint caller changed authority")
				}
				var received runtimePrecisionBrowserMetadata
				if err := json.NewDecoder(r.Body).Decode(&received); err != nil || received.Schema != "runtime-precision-browser-checkpoint-v1" || received.DeadlineUnixMS <= time.Now().UnixMilli() {
					t.Error("checkpoint omitted inherited deadline", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := awaitRuntimePrecisionBrowserCheckpoint(ctx, server.URL+"/checkpoint", token, runtimePrecisionBrowserMetadata{})
			if (err == nil) != (body == `{"released":true}`) {
				t.Fatalf("release body %q: %v", body, err)
			}
		})
	}
}

func TestRuntimePrecisionBrowserCheckpointRejectsUnownedAuthority(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	redirected := make(chan struct{}, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected <- struct{}{} }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, endpoint := range []string{"https://127.0.0.1:1234/checkpoint", "http://localhost:1234/checkpoint", "http://192.0.2.1:1234/checkpoint", "http://127.0.0.1:1234/other", "http://user@127.0.0.1:1234/checkpoint", redirect.URL + "/checkpoint", redirect.URL + "/checkpoint?x=1", redirect.URL + "/checkpoint#x"} {
		if err := awaitRuntimePrecisionBrowserCheckpoint(ctx, endpoint, token, runtimePrecisionBrowserMetadata{}); err == nil {
			t.Fatal("unowned/redirected checkpoint accepted", endpoint)
		}
	}
	select {
	case <-redirected:
		t.Fatal("checkpoint forwarded bearer to redirect")
	default:
	}
	if err := awaitRuntimePrecisionBrowserCheckpoint(ctx, redirect.URL+"/checkpoint", "wrong", runtimePrecisionBrowserMetadata{}); err == nil {
		t.Fatal("invalid bearer accepted")
	}
}

func TestRuntimePrecisionBrowserCheckpointInheritedDeadline(t *testing.T) {
	stop := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	defer server.Close()
	defer close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := awaitRuntimePrecisionBrowserCheckpoint(ctx, server.URL+"/checkpoint", strings.Repeat("a", 64), runtimePrecisionBrowserMetadata{}); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("checkpoint ignored inherited deadline", err)
	}
}

type runtimePrecisionBrowserMetadata struct {
	Schema                string                       `json:"schema"`
	DeadlineUnixMS        int64                        `json:"deadline_unix_ms"`
	Scope                 runtimePrecisionBrowserScope `json:"scope"`
	BatchID               string                       `json:"batch_id"`
	AgentID               string                       `json:"agent_id"`
	SessionID             string                       `json:"session_id"`
	SandboxID             string                       `json:"sandbox_id"`
	SandboxSourceSensorID string                       `json:"sandbox_source_sensor_id"`
	BoundEvent            runtimePrecisionBrowserEvent `json:"bound_event"`
	UnknownEvent          runtimePrecisionBrowserEvent `json:"unknown_event"`
	ProcessStartTimes     []string                     `json:"process_start_times"`
	SourceEventTimes      []string                     `json:"source_event_times"`
}

type runtimePrecisionBrowserScope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
}

type runtimePrecisionBrowserEvent struct {
	EventID    string `json:"event_id"`
	EvidenceID string `json:"evidence_id"`
	At         string `json:"at"`
}

func awaitRuntimePrecisionBrowserCheckpoint(ctx context.Context, endpoint, token string, metadata runtimePrecisionBrowserMetadata) error {
	address, err := url.Parse(endpoint)
	if err != nil || address.Scheme != "http" || address.Hostname() != "127.0.0.1" || address.User != nil || address.Path != "/checkpoint" || address.RawPath != "" || address.RawQuery != "" || address.ForceQuery || address.Fragment != "" || address.Opaque != "" {
		return errors.New("precision browser checkpoint endpoint rejected")
	}
	port, err := strconv.Atoi(address.Port())
	decodedToken, tokenErr := hex.DecodeString(token)
	if err != nil || port < 1 || port > 65535 || tokenErr != nil || len(decodedToken) != 32 || token != strings.ToLower(token) {
		return errors.New("precision browser checkpoint authority rejected")
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return errors.New("precision browser checkpoint requires inherited deadline")
	}
	metadata.Schema = "runtime-precision-browser-checkpoint-v1"
	metadata.DeadlineUnixMS = deadline.UnixMilli()
	body, err := json.Marshal(metadata)
	if err != nil || len(body) > 16384 {
		return errors.New("precision browser checkpoint metadata rejected")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 90 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("precision browser checkpoint failed: %w", err)
	}
	defer response.Body.Close()
	release, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || !bytes.Equal(release, []byte(`{"released":true}`)) {
		return errors.New("precision browser checkpoint release rejected")
	}
	return nil
}

type runtimePrecisionProofFixture struct {
	admin             *pgx.Conn
	runner            *migrations.Runner
	database          func(string) apiserver.JSONDatabase
	scope             domain.Scope
	raw               runtimeevent.RawArtifactAuthority
	archive           *runtimeArchiveExecutor
	index             *runtimeindex.Store
	receipts          artifactstore.ObjectReferencingArtifactStore
	graph             *graphstore.Store
	queue             *jobqueue.Queue
	endpoint          string
	credentials       aws.CredentialsProvider
	assertQueuesEmpty func()
}

type precisionProofCandidateDatabase struct {
	apiserver.JSONDatabase
	test *testing.T
}

func (database *precisionProofCandidateDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	body, err := database.JSONDatabase.QueryJSON(ctx, statement, args...)
	if strings.Contains(statement, "freeze_") {
		database.test.Logf("precision candidate freeze query=%s response_bytes=%d err=%v", statement, len(body), err)
	}
	return body, err
}

func proveRuntimePrecisionPipeline(t *testing.T, ctx context.Context, f runtimePrecisionProofFixture) {
	t.Helper()
	if !runtimePrecisionProofEnabled() {
		t.Fatal("precision proof requires all explicit flags")
	}
	var historical []string
	if err := f.admin.QueryRow(ctx, `SELECT array_agg(batch_id ORDER BY batch_id) FROM zasp_runtime_batch_authorities`).Scan(&historical); err != nil {
		t.Fatal(err)
	}
	snapshot := func(batches []string) string {
		var body string
		if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_array(
		 (SELECT jsonb_agg(to_jsonb(b) ORDER BY batch_id) FROM zasp_runtime_batch_authorities b WHERE batch_id=ANY($1)),
		 (SELECT jsonb_agg(to_jsonb(w) ORDER BY batch_id,stage) FROM zasp_runtime_stage_work w WHERE batch_id=ANY($1)),
		 (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.organization_id,e.workspace_id,e.environment_id,e.event_id) FROM zasp_runtime_session_events e WHERE EXISTS(SELECT 1 FROM zasp_runtime_session_projection_receipts r WHERE r.batch_id=ANY($1) AND (r.organization_id,r.workspace_id,r.environment_id)=(e.organization_id,e.workspace_id,e.environment_id) AND e.event_id=ANY(r.event_ids))),
		 (SELECT jsonb_agg(to_jsonb(r) ORDER BY batch_id) FROM zasp_runtime_session_projection_receipts r WHERE batch_id=ANY($1)),
		 (SELECT jsonb_agg(to_jsonb(q) ORDER BY batch_id) FROM zasp_runtime_sandbox_search_outbox q WHERE batch_id=ANY($1)),
		 (SELECT jsonb_agg(to_jsonb(q) ORDER BY batch_id) FROM zasp_runtime_session_search_outbox q WHERE batch_id=ANY($1)))::text`, batches).Scan(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	historicalBefore := snapshot(historical)
	historyRequest := sandboxCutoverProviderRequest(t, ctx, f.endpoint)
	historicalProviderSnapshot := func() []byte {
		query, _ := json.Marshal(map[string]any{"size": 1000, "track_total_hits": true, "version": true, "seq_no_primary_term": true, "sort": []any{map[string]string{"document_id": "asc"}}, "query": map[string]any{"terms": map[string][]string{"batch_id": historical}}})
		body := historyRequest(http.MethodPost, "/zasp-runtime-sessions-v2/_search", query)
		var result struct {
			TimedOut bool `json:"timed_out"`
			Shards   struct {
				Failed int `json:"failed"`
			} `json:"_shards"`
			Hits struct {
				Total struct {
					Value    int    `json:"value"`
					Relation string `json:"relation"`
				} `json:"total"`
				Items []json.RawMessage `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(body, &result) != nil || result.TimedOut || result.Shards.Failed != 0 || result.Hits.Total.Relation != "eq" || result.Hits.Total.Value == 0 || result.Hits.Total.Value != len(result.Hits.Items) {
			t.Fatal("historical target2 snapshot incomplete", string(body))
		}
		canonical, _ := json.Marshal(result.Hits.Items)
		return canonical
	}
	historicalProviderBefore := historicalProviderSnapshot()
	if err := f.runner.UpProductionRuntimePrecision(ctx); err != nil {
		t.Fatal("registered51 install", err)
	}
	if version, err := f.runner.Version(ctx); err != nil || version != 51 {
		t.Fatal("missing registered51", version, err)
	}
	org, workspace, environment := f.scope.OrganizationID().String(), f.scope.WorkspaceID().String(), f.scope.EnvironmentID().String()
	const anchor, semantic = "pid_78991001-0000-4000-8000-000000000001", "pid_78991002-0000-4000-8000-000000000002"
	wires := map[string]string{}
	for i, source := range []struct{ id, kind string }{{anchor, "tetragon"}, {semantic, "otlp"}} {
		// Enrollment is an explicit active identity fixture, matching the
		// historical harness. This does not prove sensor heartbeat activation.
		if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Precision provider proof',$5,'active')`, org, workspace, environment, source.id, source.kind); err != nil {
			t.Fatal(err)
		}
		credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{byte(0xb1 + i)}, 16), bytes.Repeat([]byte{byte(0xc1 + i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		defer credential.Destroy()
		locator, err := credential.LocatorDigest()
		if err != nil {
			t.Fatal(err)
		}
		token := workerID(t, fmt.Sprintf("pid_78991003-0000-4000-8000-%012d", i+1))
		salt := bytes.Repeat([]byte{byte(0xd1 + i)}, 32)
		hash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, token, 1, salt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, org, workspace, environment, source.id, token.String(), locator[:], salt, hash[:]); err != nil {
			t.Fatal(err)
		}
		wires[source.kind], err = credential.Wire()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES($1,$2,$3,$4,$5)`, org, workspace, environment, semantic, anchor); err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresPreciseProductionIngestRepository(f.database("zasp_e2e_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	handler, err := runtimeevent.NewPreciseProductionIngestHandler(runtimeevent.ProductionIngestConfig{Repository: repository, Artifacts: f.raw, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sensor.EnrollmentBinding(f.scope, workerID(t, anchor))
	if err != nil {
		t.Fatal(err)
	}
	source := sensoradapter.LineageSource{Profile: "tetragon-local-stream-v3", GenerationID: "78991101-0000-4000-8000-000000000001", EnrollmentBinding: binding, NodeName: "precision-node", ClusterUID: "78991102-0000-4000-8000-000000000002", NodeUID: "78991103-0000-4000-8000-000000000003", BootID: "78991104-0000-4000-8000-000000000004"}
	events, starts, sourceTimes := preciseProviderProofEvents(t, source, now.Add(-time.Second))
	lineage := events[0].ObservedLineage.Observation
	lineage.Profile = "kubernetes-container-v1"
	const agent, session = "pid_78991201-0000-4000-8000-000000000001", "pid_78991202-0000-4000-8000-000000000002"
	semanticBody, err := json.Marshal(map[string]any{"source": "otlp", "events": []any{map[string]any{"event_time": now.Format("2006-01-02T15:04:05.000Z"), "evidence_id": "pid_78991203-0000-4000-8000-000000000003", "observed_lineage": lineage, "attributes": map[string]string{"event.id": "precision-semantic", "event.class": "tool", "event.action": "invoke", "agent.id": agent, "session.id": session, "task.id": "precision-task", "tool.id": "precision-tool", "sandbox.id": "precision-observed-sandbox", "trace.id": strings.Repeat("e", 32), "span.id": strings.Repeat("f", 16)}}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(semanticBody)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+wires["otlp"])
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
	request.Header.Set("Idempotency-Key", "precision-semantic-proof-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var semanticAccepted struct {
		Batch string `json:"batch_id"`
	}
	if response.Code != http.StatusAccepted || json.Unmarshal(response.Body.Bytes(), &semanticAccepted) != nil || semanticAccepted.Batch == "" {
		t.Fatal("fresh semantic ingest", response.Code, response.Body.String())
	}
	var preciseBatch string
	lostHTTP, wrongBinding := true, false
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Now: func() time.Time { return now }, Token: func() ([]byte, error) { return []byte(wires["tetragon"]), nil }, Do: func(r *http.Request) (*http.Response, error) {
		if wrongBinding {
			r.Header.Set("X-Zasp-Expected-Enrollment", strings.Repeat("f", 64))
		}
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, r)
		if result.Code == http.StatusAccepted {
			var accepted struct {
				Batch string `json:"batch_id"`
			}
			if json.Unmarshal(result.Body.Bytes(), &accepted) != nil || accepted.Batch == "" {
				t.Fatal("invalid precise acceptance")
			}
			if preciseBatch != "" && preciseBatch != accepted.Batch {
				t.Fatal("HTTP replay changed batch")
			}
			preciseBatch = accepted.Batch
		}
		if lostHTTP {
			lostHTTP = false
			if result.Code != http.StatusAccepted {
				t.Fatal("precise intake", result.Code, result.Body.String())
			}
			return nil, errors.New("lost actual committed HTTP response")
		}
		return result.Result(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := client.PreparePreciseEnvelope(events)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IngestPreciseEnvelope(ctx, envelope); !errors.Is(err, sensoradapter.ErrClientRetryable) {
		t.Fatal("expected lost HTTP response", err)
	}
	if err := client.IngestPreciseEnvelope(ctx, envelope); err != nil {
		t.Fatal("frozen HTTP replay", err)
	}
	wrongBinding = true
	if err := client.IngestPreciseEnvelope(ctx, envelope); err == nil {
		t.Fatal("foreign enrollment admitted")
	}
	wrongBinding = false
	var rawKey, rawVersion string
	var rawDigest []byte
	if err := f.admin.QueryRow(ctx, `SELECT raw_artifact_key,raw_artifact_version_id,raw_artifact_checksum FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, preciseBatch).Scan(&rawKey, &rawVersion, &rawDigest); err != nil {
		t.Fatal(err)
	}
	rawObject, err := f.archive.config.API.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(f.archive.config.Bucket), Key: &rawKey, VersionId: &rawVersion, ExpectedBucketOwner: aws.String(f.archive.config.ExpectedOwner), ChecksumMode: s3types.ChecksumModeEnabled})
	if err != nil {
		t.Fatal(err)
	}
	archived, readErr := io.ReadAll(io.LimitReader(rawObject.Body, (1<<20)+1))
	rawObject.Body.Close()
	actualDigest := sha256.Sum256(archived)
	if readErr != nil || len(archived) > 1<<20 || !bytes.Equal(actualDigest[:], rawDigest) || aws.ToString(rawObject.VersionId) != rawVersion || aws.ToString(rawObject.SSEKMSKeyId) != f.archive.config.KMSKeyARN {
		t.Fatal("exact precise S3 archive authority", readErr)
	}
	decoded, err := runtimeevent.DecodePreciseArchivedBatch(f.scope, archived)
	if err != nil || len(decoded.Records) != 2 {
		t.Fatal("precise archived decode", err)
	}
	for i, record := range decoded.Records {
		if record.ObservedLineage.SourceEventTime != sourceTimes[i] || record.ObservedLineage.ProcessStartTime != starts[i] {
			t.Fatal("S3 lost original nanoseconds", record.ObservedLineage)
		}
	}
	for batch, want := range map[string]string{semanticAccepted.Batch: "archive:runtime-archive-v1,index:runtime-index-v1,correlate:runtime-correlation-v3,project:runtime-projection-v2,complete:runtime-complete-v2", preciseBatch: "archive:runtime-archive-v2,index:runtime-index-v2,correlate:runtime-correlation-v4,project:runtime-projection-v3,complete:runtime-complete-v3"} {
		var tuple string
		if err := f.admin.QueryRow(ctx, `SELECT string_agg(stage||':'||implementation_version,',' ORDER BY CASE stage WHEN 'archive' THEN 1 WHEN 'index' THEN 2 WHEN 'correlate' THEN 3 WHEN 'project' THEN 4 ELSE 5 END) FROM zasp_runtime_stage_work WHERE batch_id=$1`, batch).Scan(&tuple); err != nil || tuple != want {
			t.Fatal("fresh persisted tuple", tuple, want, err)
		}
	}

	selected := "zasp-runtime-sessions-v2"
	search, err := opensearchdriver.NewConfiguredSessionIndex(selected, opensearchdriver.Config{Endpoint: f.endpoint, Region: "us-east-1", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20, AllowTestLoopback: true}, f.credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	defer search.Close()
	if err := search.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	searchExecutor, err := newRuntimePreciseSessionSearchExecutor(f.archive, f.receipts, search)
	if err != nil {
		t.Fatal(err)
	}
	index, err := newRuntimeIndexExecutor(runtimeIndexExecutorConfig{Reader: f.archive, Index: f.index, Receipts: f.receipts, ImplementationVersion: "runtime-index-v2"})
	if err != nil {
		t.Fatal(err)
	}
	lostReceipt := &runtimeCandidateLostReceipt{ObjectReferencingArtifactStore: f.receipts}
	graph := &runtimeCandidateRecoveryGraph{delegate: f.graph}
	correlation, err := newRuntimeCorrelationExecutorWithDatabase(runtimeCorrelationExecutorConfig{Reader: f.archive, Receipts: lostReceipt, Graph: graph, ImplementationVersion: "runtime-correlation-v4"}, &precisionProofCandidateDatabase{JSONDatabase: f.database("zasp_e2e_correlation"), test: t})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: f.archive, Receipts: f.receipts, Graph: f.graph, ImplementationVersion: "runtime-projection-v3"})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: f.receipts, ImplementationVersion: "runtime-complete-v3"})
	if err != nil {
		t.Fatal(err)
	}
	processors := map[runtimeevent.RuntimeStage]workerProcessor{}
	for _, stage := range []struct {
		config             workerRuntimeConfig
		principal, version string
		executor           runtimeStageExecutor
	}{
		{validRuntimeArchiveConfig(), "zasp_e2e_archive", "runtime-archive-v2", f.archive}, {validRuntimeIndexConfig(), "zasp_e2e_index", "runtime-index-v2", index}, {validRuntimeCorrelationConfig(), "zasp_e2e_correlation", "runtime-correlation-v4", correlation}, {validRuntimeProjectionConfig(), "zasp_e2e_runtime_projection", "runtime-projection-v3", projection}, {validRuntimeCompleteConfig(), "zasp_e2e_coordinator", "runtime-complete-v3", complete},
	} {
		stage.config.RuntimeStageVersion = stage.version
		stage.config.BatchSize = 1
		stage.config.LeaseDuration = 10 * time.Second
		stage.config.ShutdownTimeout = 5 * time.Second
		name, _, ok := runtimeStageBinding(stage.config.Mode)
		if !ok {
			t.Fatal("unknown stage")
		}
		deps := &productionRuntimeStageDependencies{Stage: name, Executor: stage.executor, ready: func(context.Context) error { return nil }, close: func() error { return nil }}
		if name == runtimeevent.RuntimeStageIndex {
			stage.config.RuntimeSessionIndex = selected
			deps.Sessions = searchExecutor
			deps.SessionReady = search.Ready
		}
		worker, err := composeRuntimeStageWorkerRuntime(stage.config, f.database(stage.principal), deps)
		if err != nil {
			t.Fatal("precise stage composition", name, err)
		}
		if err := worker.Ready(ctx); err != nil {
			t.Fatal("precise stage readiness", name, err)
		}
		processors[name] = worker.Processor
	}
	publisher := &runtimePipelinePublisher{queue: f.queue, t: t}
	outboxConfig := validSchedulerRuntimeConfig()
	outboxConfig.Mode, outboxConfig.DatabaseAuthority, outboxConfig.WorkerID = workerModeRuntimeOutbox, "zasp_outbox_worker", "precision-proof-outbox"
	outboxConfig.RuntimeQueueURL = "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-runtime-events"
	outboxConfig.AWSRegion = "us-west-2"
	outboxConfig.OutboxRoleARN = "arn:aws:iam::123456789012:role/zasp-production-runtime-outbox"
	outboxConfig.OutboxTokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	outboxConfig.RuntimeDeliverySchema = "runtime-event-v2"
	outboxRuntime, err := composeOutboxWorkerRuntime(outboxConfig, f.database("zasp_e2e_outbox"), publisher, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := outboxRuntime.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	outbox := outboxRuntime.Processor
	observed := &runtimePipelineDeliveryQueue{Queue: f.queue}
	config := validRuntimeCoordinatorConfig()
	config.RuntimeDeliverySchema = "runtime-event-v2"
	coordinator, err := composeRuntimeCoordinatorWorkerRuntime(config, f.database("zasp_e2e_coordinator"), &productionRuntimeQueueDependencies{Queue: observed, ready: func(context.Context) error { return nil }, close: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	api, err := apiserver.NewPostgresRepositoryWithRuntimeSessionSearchIndex(f.database("zasp_e2e_api"), search, selected)
	if err != nil {
		t.Fatal(err)
	}
	identity := apiserver.RequestIdentity{PrincipalID: workerID(t, "pid_10000004-0000-4000-8000-000000000004"), Scope: f.scope, Permissions: []string{"view"}, CredentialKind: apiserver.CredentialBearerToken}
	readAPI := func() sandboxCutoverPage {
		body, err := api.ReadAdministration(ctx, identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"})
		if err != nil {
			t.Fatal(err)
		}
		var page sandboxCutoverPage
		if json.Unmarshal(body, &page) != nil {
			t.Fatal("invalid precise API page")
		}
		return page
	}
	for _, batch := range []string{semanticAccepted.Batch, preciseBatch} {
		if err := outbox.RunOnce(ctx); err != nil {
			t.Fatal("precise outbox", err)
		}
		done, stop := startRuntimeCandidateCoordinator(t, ctx, runtimeCandidateRecoveryFixture{admin: f.admin, coordinator: coordinator.Processor}, f.scope, batch)
		if batch == preciseBatch {
			lostReceipt.loseNext = true
		}
		for _, stage := range []runtimeevent.RuntimeStage{runtimeevent.RuntimeStageArchive, runtimeevent.RuntimeStageIndex, runtimeevent.RuntimeStageCorrelate, runtimeevent.RuntimeStageProject, runtimeevent.RuntimeStageComplete} {
			if batch == preciseBatch && (stage == runtimeevent.RuntimeStageCorrelate || stage == runtimeevent.RuntimeStageComplete) {
				authority, principal := runtimeevent.ProductionPipelineAuthorityCorrelation, "zasp_e2e_correlation"
				if stage == runtimeevent.RuntimeStageComplete {
					authority, principal = runtimeevent.ProductionPipelineAuthorityCoordinator, "zasp_e2e_coordinator"
				}
				repo, err := runtimeevent.NewPostgresPrecisePipelineRepository(f.database(principal), authority)
				if err != nil {
					t.Fatal(err)
				}
				token, err := newWorkerLeaseToken()
				if err != nil {
					t.Fatal(err)
				}
				leases, err := repo.ClaimStages(ctx, "precise-disappeared", token, 5, 1)
				if err != nil || len(leases) != 1 || leases[0].BatchID.String() != batch {
					t.Fatal("precise disappearance claim", stage, err)
				}
				lease := leases[0]
				execution := runtimeStageExecution{lease: lease, workerID: "precise-disappeared", leaseToken: token}
				if stage == runtimeevent.RuntimeStageCorrelate {
					if _, err := correlation.ExecuteAuthorized(ctx, execution); !errors.Is(err, errWorkerExecution) {
						t.Fatal("actual receipt response loss", err)
					}
				} else {
					effect, err := complete.ExecuteAuthorized(ctx, execution)
					if err != nil {
						t.Fatal(err)
					}
					before := snapshot([]string{batch})
					_, err = repo.FinishStage(ctx, runtimeevent.StageFinishRequest{Lease: lease, WorkerID: execution.workerID, LeaseToken: token, Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: effect.EffectDigest, ResultReference: effect.ResultReference, ResultVersionID: effect.ResultVersionID, ResultDigest: effect.ResultDigest, ProjectionReceipt: "{}"})
					if !errors.Is(err, runtimeevent.ErrProductionPipelineUnknown) || snapshot([]string{batch}) != before {
						t.Fatal("rejected precise completion retained partial evidence", err)
					}
				}
				// The disappeared process does not finish or renew. Real SQL lease
				// expiry makes the production worker reclaim its exact durable input.
				for time.Now().Before(lease.LeaseExpiresAt.Add(20 * time.Millisecond)) {
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(50 * time.Millisecond):
					}
				}
				if _, err := repo.HeartbeatStage(ctx, lease, execution.workerID, token, 5); err == nil {
					t.Fatal("expired precise owner renewed lease")
				}
			}
			for attempt := 0; attempt < 600; attempt++ {
				runErr := processors[stage].RunOnce(ctx)
				var state string
				if err := f.admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, batch, string(stage)).Scan(&state); err != nil {
					t.Fatal(err)
				}
				if state == "succeeded" {
					break
				}
				if state == "quarantined" || state == "exhausted" || state == "failed" || state == "unknown" || attempt == 599 {
					t.Fatal("precise stage did not complete", stage, state, runErr)
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(50 * time.Millisecond):
				}
			}
			t.Logf("precision provider batch %s stage %s completed", batch, stage)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("actual precise coordinator", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		stop()
		page := readAPI()
		if page.Search.State != "catching_up" || page.Search.Pending != 1 {
			t.Fatal("API freshness preceded provider checkpoint", page.Search)
		}
		if batch == preciseBatch && os.Getenv("ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER") == "true" {
			if !runtimePrecisionProofEnabled() {
				t.Fatal("precision browser requires all explicit proof flags")
			}
			metadata := runtimePrecisionBrowserMetadata{
				Scope: runtimePrecisionBrowserScope{org, workspace, environment}, BatchID: preciseBatch,
				AgentID: agent, SessionID: session, SandboxID: "precision-observed-sandbox", SandboxSourceSensorID: semantic,
				ProcessStartTimes: starts, SourceEventTimes: sourceTimes,
			}
			for confidence, event := range map[string]*runtimePrecisionBrowserEvent{"strong": &metadata.BoundEvent, "unattributed": &metadata.UnknownEvent} {
				var at time.Time
				if err := f.admin.QueryRow(ctx, `SELECT e.event_id,e.evidence_id,e.event_time FROM zasp_runtime_session_events e WHERE confidence=$2 AND EXISTS(SELECT 1 FROM zasp_runtime_session_projection_receipts r WHERE r.batch_id=$1 AND (r.organization_id,r.workspace_id,r.environment_id)=(e.organization_id,e.workspace_id,e.environment_id) AND e.event_id=ANY(r.event_ids))`, preciseBatch, confidence).Scan(&event.EventID, &event.EvidenceID, &at); err != nil {
					t.Fatal("precise browser persisted event metadata", err)
				}
				event.At = at.UTC().Format("2006-01-02T15:04:05.000Z")
			}
			if err := awaitRuntimePrecisionBrowserCheckpoint(ctx, os.Getenv("ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER_ENDPOINT"), os.Getenv("ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER_TOKEN"), metadata); err != nil {
				t.Fatal(err)
			}
		}
		if err := processors[runtimeevent.RuntimeStageIndex].RunOnce(ctx); err != nil {
			t.Fatal("precise target2 indexing", err)
		}
		page = readAPI()
		if page.Search.State != "current" || page.Search.Pending != 0 {
			t.Fatal("precise API not current after checkpoint", page.Search)
		}
		var legacyCheckpoints int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE batch_id=$1`, batch).Scan(&legacyCheckpoints); err != nil || legacyCheckpoints != 0 {
			t.Fatal("fresh sandbox/precise work leaked to legacy search outbox", batch, legacyCheckpoints, err)
		}
	}
	if len(lostReceipt.writes) != 3 || !bytes.Equal(lostReceipt.bodies[1], lostReceipt.bodies[2]) || lostReceipt.writes[1].VersionID != lostReceipt.writes[2].VersionID || len(graph.results) != 3 || !graph.results[2].Replayed {
		t.Fatal("provider response loss did not replay exact graph/S3 authority", len(lostReceipt.writes), len(graph.results))
	}
	var strong, unknown, bound int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FILTER(WHERE confidence='strong' AND agent_id=$2 AND session_id=$3 AND sandbox_id='precision-observed-sandbox' AND sandbox_source_sensor_id=$4),count(*) FILTER(WHERE confidence='unattributed' AND agent_id IS NULL AND session_id IS NULL AND sandbox_id IS NULL AND sandbox_source_sensor_id IS NULL),count(*) FILTER(WHERE sandbox_id IS NOT NULL) FROM zasp_runtime_session_events e WHERE EXISTS(SELECT 1 FROM zasp_runtime_session_projection_receipts r WHERE r.batch_id=$1 AND (r.organization_id,r.workspace_id,r.environment_id)=(e.organization_id,e.workspace_id,e.environment_id) AND e.event_id=ANY(r.event_ids))`, preciseBatch, agent, session, semantic).Scan(&strong, &unknown, &bound); err != nil || strong != 1 || unknown != 1 || bound != 1 {
		t.Fatal("same-millisecond process starts collided or invented sandbox", strong, unknown, bound, err)
	}
	for _, confidence := range []string{"strong", "unattributed"} {
		var eventID string
		if err := f.admin.QueryRow(ctx, `SELECT e.event_id FROM zasp_runtime_session_events e WHERE confidence=$2 AND EXISTS(SELECT 1 FROM zasp_runtime_session_projection_receipts r WHERE r.batch_id=$1 AND (r.organization_id,r.workspace_id,r.environment_id)=(e.organization_id,e.workspace_id,e.environment_id) AND e.event_id=ANY(r.event_ids))`, preciseBatch, confidence).Scan(&eventID); err != nil {
			t.Fatal(err)
		}
		target := session
		if confidence == "unattributed" {
			target = "unattributed"
		}
		body, err := api.ReadAdministration(ctx, identity, "getSessionEvent", map[string]string{"id": target, "eventId": eventID})
		var event struct {
			ID, Confidence string
			SandboxID      string `json:"sandbox_id"`
			SandboxSource  string `json:"sandbox_source_sensor_id"`
		}
		if err != nil || json.Unmarshal(body, &event) != nil || event.ID != eventID || event.Confidence != confidence {
			t.Fatal("precise API event readback", confidence, err, string(body))
		}
		if confidence == "strong" && (event.SandboxID != "precision-observed-sandbox" || event.SandboxSource != semantic) || confidence == "unattributed" && (event.SandboxID != "" || event.SandboxSource != "") {
			t.Fatal("precise API changed sandbox evidence", string(body))
		}
	}
	foreign := identity
	foreign.Scope, err = domain.NewScope(workerID(t, "pid_78930001-0000-4000-8000-000000000001"), workerID(t, "pid_78930002-0000-4000-8000-000000000002"), workerID(t, "pid_78930003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	if body, err := api.ReadAdministration(ctx, foreign, "listSessions", map[string]string{"kind": "runtime", "limit": "25"}); !errors.Is(err, apiserver.ErrRepositoryNotFound) || len(body) != 0 {
		t.Fatal("precise API crossed tenant authorization", err)
	}
	providerRequest := sandboxCutoverProviderRequest(t, ctx, f.endpoint)
	providerSnapshot := func() []byte {
		query, _ := json.Marshal(map[string]any{"size": 10, "track_total_hits": true, "version": true, "seq_no_primary_term": true, "sort": []any{map[string]string{"document_id": "asc"}}, "query": map[string]any{"term": map[string]string{"batch_id": preciseBatch}}})
		body := providerRequest(http.MethodPost, "/zasp-runtime-sessions-v2/_search", query)
		var result struct {
			TimedOut bool `json:"timed_out"`
			Shards   struct {
				Failed int `json:"failed"`
			} `json:"_shards"`
			Hits struct {
				Total struct {
					Value    int    `json:"value"`
					Relation string `json:"relation"`
				} `json:"total"`
				Items []json.RawMessage `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(body, &result) != nil || result.TimedOut || result.Shards.Failed != 0 || result.Hits.Total.Relation != "eq" || result.Hits.Total.Value != 2 || len(result.Hits.Items) != 2 {
			t.Fatal("target2 precise occurrences incomplete", string(body))
		}
		confidences := map[string]int{}
		for _, raw := range result.Hits.Items {
			var hit struct {
				Source struct {
					Confidence      string `json:"confidence"`
					AgentID         string `json:"agent_id"`
					InvestigationID string `json:"investigation_id"`
					SandboxID       string `json:"sandbox_id"`
					SandboxSource   string `json:"sandbox_source_sensor_id"`
				} `json:"_source"`
			}
			if json.Unmarshal(raw, &hit) != nil {
				t.Fatal("invalid target2 source")
			}
			value := hit.Source
			confidences[value.Confidence]++
			if value.Confidence == "strong" && (value.AgentID != agent || value.InvestigationID != session || value.SandboxID != "precision-observed-sandbox" || value.SandboxSource != semantic) || value.Confidence == "unattributed" && (value.AgentID != "" || value.InvestigationID != "unattributed" || value.SandboxID != "" || value.SandboxSource != "") {
				t.Fatal("target2 changed precise sandbox evidence", string(raw))
			}
		}
		if confidences["strong"] != 1 || confidences["unattributed"] != 1 {
			t.Fatal("target2 confidence split changed", confidences)
		}
		canonical, _ := json.Marshal(result.Hits.Items)
		return canonical
	}
	providerBefore := providerSnapshot()
	before := snapshot([]string{semanticAccepted.Batch, preciseBatch})
	if err := client.IngestPreciseEnvelope(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := f.queue.PublishBatch(ctx, publisher.jobs); err != nil {
		t.Fatal(err)
	}
	wantAcks := observed.ackCount.Load() + int64(len(publisher.jobs))
	for attempt := 0; attempt < 200 && observed.ackCount.Load() < wantAcks; attempt++ {
		if err := coordinator.Processor.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if observed.ackCount.Load() < wantAcks {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if observed.ackCount.Load() != wantAcks || snapshot([]string{semanticAccepted.Batch, preciseBatch}) != before || snapshot(historical) != historicalBefore || !bytes.Equal(providerSnapshot(), providerBefore) || !bytes.Equal(historicalProviderSnapshot(), historicalProviderBefore) {
		t.Fatal("physical redelivery/HTTP replay changed canonical history")
	}
	f.assertQueuesEmpty()
	t.Log("runtime precise provider pipeline proven: registered51; precise normalizer/enrolled client and HTTP; fresh V1 semantic1/1/3/2/2 plus V2 Tetragon2/2/4/3/3 durable outbox/real SQS; same-millisecond nanosecond starts produce sandbox-bound Strong versus unbound unattributed; real S3/TLS Neo4j response-loss replay; target2 OpenSearch checkpoint and API freshness; immutable HTTP/SQS replay, historical evidence and empty DLQ. Local source fixture only; live Tetragon/cloud attestation NOT RUN")
}

func preciseProviderProofEvents(t *testing.T, source sensoradapter.LineageSource, base time.Time) ([]sensoradapter.PreciseRuntimeEvent, []string, []string) {
	t.Helper()
	normalizer, err := sensoradapter.NewPreciseLineageNormalizer(8, source)
	if err != nil {
		t.Fatal(err)
	}
	starts := []string{base.Add(123456789 * time.Nanosecond).Format(time.RFC3339Nano), base.Add(123456790 * time.Nanosecond).Format(time.RFC3339Nano)}
	sourceTimes := []string{base.Add(123999999 * time.Nanosecond).Format(time.RFC3339Nano), base.Add(124111111 * time.Nanosecond).Format(time.RFC3339Nano)}
	events := make([]sensoradapter.PreciseRuntimeEvent, 2)
	for i := range events {
		provider := map[string]any{"node_name": source.NodeName, "cluster_name": "precision-cluster", "node_labels": map[string]string{}, "time": sourceTimes[i], "process_exec": map[string]any{"process": map[string]any{"exec_id": fmt.Sprintf("precision-exec-%d", i), "pid": 42, "uid": 1000, "binary": "/usr/bin/precision-agent", "flags": "execve", "start_time": base.Add(time.Duration(123456789 + i)).Format("2006-01-02T15:04:05.000000000Z"), "pod": map[string]any{"namespace": "precision", "name": "agent", "uid": "78991105-0000-4000-8000-000000000005", "container": map[string]any{"id": "containerd://" + strings.Repeat("e", 64), "name": "agent"}}}}}
		line, err := json.Marshal(provider)
		if err != nil {
			t.Fatal(err)
		}
		events[i], err = normalizer.Normalize(line)
		if err != nil || events[i].ObservedLineage.SourceEventTime != sourceTimes[i] || events[i].ObservedLineage.ProcessStartTime != starts[i] {
			t.Fatal("precise source normalization", events[i], err)
		}
	}
	return events, starts, sourceTimes
}

func TestRuntimePrecisionProofSourceFixture(t *testing.T) {
	source := sensoradapter.LineageSource{Profile: "tetragon-local-stream-v3", GenerationID: "78991101-0000-4000-8000-000000000001", EnrollmentBinding: strings.Repeat("a", 64), NodeName: "precision-node", ClusterUID: "78991102-0000-4000-8000-000000000002", NodeUID: "78991103-0000-4000-8000-000000000003", BootID: "78991104-0000-4000-8000-000000000004"}
	events, _, _ := preciseProviderProofEvents(t, source, time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	if events[0].ObservedLineage.ProcessStartTime != "2026-09-11T12:00:00.123456789Z" || events[1].ObservedLineage.ProcessStartTime != "2026-09-11T12:00:00.12345679Z" || events[0].ObservedLineage.SourceEventTime != "2026-09-11T12:00:00.123999999Z" || events[1].ObservedLineage.SourceEventTime != "2026-09-11T12:00:00.124111111Z" {
		t.Fatal("provider fixture lost nanoseconds")
	}
}
