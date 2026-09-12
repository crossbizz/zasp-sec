package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// The opt-in must never upgrade the shared database before the broad schema49
// acceptance suite. Only its existing runtime-only lane can install release50.
func TestRuntimeSandboxSearchCutoverRequiresBothExplicitFlags(t *testing.T) {
	for _, item := range []struct {
		only, sandbox string
		want          bool
	}{
		{"", "", false}, {"true", "", false}, {"", "true", false},
		{"false", "true", false}, {"true", "TRUE", false}, {"true", "true", true},
	} {
		t.Run(item.only+"/"+item.sandbox, func(t *testing.T) {
			t.Setenv("ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY", item.only)
			t.Setenv("ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH", item.sandbox)
			if got := runtimeSandboxSearchCutoverEnabled(); got != item.want {
				t.Fatalf("cutover enabled=%t want=%t", got, item.want)
			}
		})
	}
}

func runtimeSandboxSearchCutoverEnabled() bool {
	return os.Getenv("ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY") == "true" && os.Getenv("ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH") == "true"
}

type runtimeSandboxSearchCutoverFixture struct {
	admin       *pgx.Conn
	runner      *migrations.Runner
	database    func(string) apiserver.JSONDatabase
	scope       domain.Scope
	archive     *runtimeArchiveExecutor
	rawIndex    *runtimeIndexExecutor
	rawReady    func(context.Context) error
	receipts    artifactstore.ObjectReferencingArtifactStore
	oldIndex    *opensearchdriver.SessionIndex
	endpoint    string
	credentials aws.CredentialsProvider
}

type sandboxCutoverPage struct {
	Items  []json.RawMessage                    `json:"items"`
	Search apiserver.RuntimeSessionSearchStatus `json:"search"`
}

func sandboxCutoverProviderRequest(t *testing.T, ctx context.Context, endpoint string) func(string, string, []byte) []byte {
	t.Helper()
	runtimePipelineLoopback(t, endpoint)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	return func(method, path string, body []byte) []byte {
		request, err := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("owned provider request", err)
		}
		defer response.Body.Close()
		result, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		if err != nil || len(result) > 8<<20 || response.StatusCode != http.StatusOK {
			t.Fatalf("owned provider request %s %s: status=%d err=%v", method, path, response.StatusCode, err)
		}
		return result
	}
}

// This consumes receipts produced earlier by the real schema48/49 pipeline.
// It never seeds progress, rebuilds receipts, or activates sandbox producers.
func proveRuntimeSandboxSearchCutover(t *testing.T, ctx context.Context, f runtimeSandboxSearchCutoverFixture) {
	t.Helper()
	if !runtimeSandboxSearchCutoverEnabled() {
		t.Fatal("sandbox cutover requires the explicit runtime-only lane")
	}
	if version, err := f.runner.Version(ctx); err != nil || version != 49 {
		t.Fatal("cutover predecessor is not49", version, err)
	}
	queueSnapshot := func(sandbox bool) string {
		query := `SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY organization_id,workspace_id,environment_id,batch_id,batch_generation),'[]'::jsonb)::text FROM zasp_runtime_session_search_outbox q`
		if sandbox {
			query = `SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY organization_id,workspace_id,environment_id,batch_id,batch_generation),'[]'::jsonb)::text FROM zasp_runtime_sandbox_search_outbox q`
		}
		var result string
		if err := f.admin.QueryRow(ctx, query).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	oldQueue := queueSnapshot(false)
	var receiptCount, occurrenceCount, oldIndexed int
	if err := f.admin.QueryRow(ctx, `SELECT count(*),COALESCE(sum(cardinality(event_ids)),0) FROM zasp_runtime_session_projection_receipts`).Scan(&receiptCount, &occurrenceCount); err != nil || receiptCount < 7 || occurrenceCount < 58 {
		t.Fatal("missing real historical receipt fixture", receiptCount, occurrenceCount, err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='indexed' AND indexed_at IS NOT NULL`).Scan(&oldIndexed); err != nil || oldIndexed != receiptCount {
		t.Fatal("historical receipts are not fully indexedv1", oldIndexed, err)
	}
	var scopes []domain.Scope
	rows, err := f.admin.Query(ctx, `SELECT DISTINCT organization_id,workspace_id,environment_id FROM zasp_runtime_session_projection_receipts ORDER BY 1,2,3`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var org, workspace, environment string
		if err := rows.Scan(&org, &workspace, &environment); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		scope, err := domain.NewScope(workerID(t, org), workerID(t, workspace), workerID(t, environment))
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		scopes = append(scopes, scope)
	}
	rows.Close()
	if rows.Err() != nil || len(scopes) < 2 {
		t.Fatal("missing cross-tenant receipt fixture", rows.Err())
	}
	apiDatabase := f.database("zasp_e2e_api")
	oldAPI, err := apiserver.NewPostgresRepositoryWithRuntimeSessionSearchIndex(apiDatabase, f.oldIndex, "zasp-runtime-sessions-v1")
	if err != nil {
		t.Fatal("compose old API", err)
	}
	identity := apiserver.RequestIdentity{PrincipalID: workerID(t, "pid_10000004-0000-4000-8000-000000000004"), Scope: f.scope, Permissions: []string{"view"}, CredentialKind: apiserver.CredentialBearerToken}
	readPage := func(repository *apiserver.PostgresRepository) sandboxCutoverPage {
		body, err := repository.ReadAdministration(ctx, identity, "listSessions", map[string]string{"kind": "runtime", "limit": "25"})
		if err != nil {
			t.Fatal("real API repository search", err)
		}
		var page sandboxCutoverPage
		if err := json.Unmarshal(body, &page); err != nil || page.Items == nil {
			t.Fatal("invalid API page", err)
		}
		return page
	}
	before := readPage(oldAPI)
	if before.Search.State != "current" || before.Search.Pending != 0 || len(before.Items) != 2 {
		t.Fatalf("old API baseline is incomplete: %+v", before)
	}
	if err := f.runner.UpProductionRuntimeSandboxBinding(ctx); err != nil {
		t.Fatal("production runner49-to50", err)
	}
	if version, err := f.runner.Version(ctx); err != nil || version != 50 {
		t.Fatal("sandbox release not installed", version, err)
	}
	if queueSnapshot(false) != oldQueue {
		t.Fatal("migration changed v1 checkpoint history")
	}
	var newPending, boundReceipts int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox WHERE state='pending' AND attempt=0 AND worker_id IS NULL AND indexed_at IS NULL`).Scan(&newPending); err != nil || newPending != receiptCount {
		t.Fatal("v2 did not backfill every receipt as pending", newPending, err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox fresh JOIN zasp_runtime_session_search_outbox old USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE (fresh.receipt_digest,fresh.receipt_reference,fresh.receipt_version,fresh.document_ids)=(old.receipt_digest,old.receipt_reference,old.receipt_version,old.document_ids)`).Scan(&boundReceipts); err != nil || boundReceipts != receiptCount {
		t.Fatal("v2 backfill changed committed receipt authority", boundReceipts, err)
	}

	selected := "zasp-runtime-sessions-v2"
	index, err := opensearchdriver.NewConfiguredSessionIndex(selected, opensearchdriver.Config{Endpoint: f.endpoint, Region: "us-east-1", RequestTimeout: 5 * time.Second, MaximumRequestBytes: 8 << 20, MaximumResponseBytes: 8 << 20, AllowTestLoopback: true}, f.credentials, v4.NewSigner(), func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	if err := index.InitializeSchema(ctx); err != nil {
		t.Fatal("initialize fixed v2 mapping", err)
	}
	request := sandboxCutoverProviderRequest(t, ctx, f.endpoint)
	var acknowledgement struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if err := json.Unmarshal(request(http.MethodPut, "/zasp-runtime-sessions-v2/_settings", []byte(`{"index":{"number_of_replicas":0}}`)), &acknowledgement); err != nil || !acknowledgement.Acknowledged {
		t.Fatal("owned single-node v2 replica setup failed", err)
	}
	if err := index.Ready(ctx); err != nil {
		t.Fatal("exact v2 mapping/marker readiness", err)
	}
	var mapping map[string]struct {
		Mappings struct {
			Properties map[string]struct {
				Type string `json:"type"`
			} `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(request(http.MethodGet, "/zasp-runtime-sessions-v2/_mapping", nil), &mapping); err != nil || mapping[selected].Mappings.Properties["sandbox_id"].Type != "keyword" || mapping[selected].Mappings.Properties["sandbox_source_sensor_id"].Type != "keyword" {
		t.Fatal("real v2 mapping lacks sandbox fields", err)
	}
	providerSnapshot := func() (int, []byte) {
		var response struct {
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
		body := request(http.MethodPost, "/zasp-runtime-sessions-v2/_search", []byte(`{"size":1000,"track_total_hits":true,"version":true,"seq_no_primary_term":true,"sort":[{"document_id":"asc"}],"query":{"term":{"record_type":"runtime_session_event"}}}`))
		if err := json.Unmarshal(body, &response); err != nil || response.TimedOut || response.Shards.Failed != 0 || response.Hits.Total.Relation != "eq" || len(response.Hits.Items) != response.Hits.Total.Value {
			t.Fatal("invalid complete provider snapshot", err)
		}
		canonical, err := json.Marshal(response.Hits.Items)
		if err != nil {
			t.Fatal(err)
		}
		return response.Hits.Total.Value, canonical
	}
	if count, _ := providerSnapshot(); count != 0 {
		t.Fatal("new v2 index already contains session documents", count)
	}
	newAPI, err := apiserver.NewPostgresRepositoryWithRuntimeSessionSearchIndex(apiDatabase, index, selected)
	if err != nil {
		t.Fatal("compose selected v2 API", err)
	}
	catchingUp := readPage(newAPI)
	if catchingUp.Search.State != "catching_up" || catchingUp.Search.Pending != 2 || catchingUp.Search.LastIndexed != nil || len(catchingUp.Items) != 0 {
		t.Fatalf("empty v2 adopted v1 freshness: %+v", catchingUp)
	}
	assertOldAPI := func() {
		page := readPage(oldAPI)
		if page.Search.State != "current" || page.Search.Pending != 0 || !slices.EqualFunc(page.Items, before.Items, func(a, b json.RawMessage) bool { return bytes.Equal(a, b) }) || queueSnapshot(false) != oldQueue {
			t.Fatal("v2 cutover changed old API results or checkpoint history")
		}
	}
	assertOldAPI()
	executor, err := newRuntimeSessionSearchExecutor(f.archive, f.receipts, index)
	if err != nil {
		t.Fatal(err)
	}
	config := validRuntimeIndexConfig()
	config.RuntimeSessionIndex, config.BatchSize = selected, 1
	worker, err := composeRuntimeStageWorkerRuntime(config, f.database("zasp_e2e_index"), &productionRuntimeStageDependencies{Stage: runtimeevent.RuntimeStageIndex, Executor: f.rawIndex, Sessions: executor, SessionReady: index.Ready, ready: f.rawReady, close: func() error { return nil }})
	if err != nil {
		t.Fatal("compose selected production worker", err)
	}
	if err := worker.Ready(ctx); err != nil {
		t.Fatal("selected worker readiness", err)
	}
	for drained := 0; drained < receiptCount; drained++ {
		if err := worker.Processor.RunOnce(ctx); err != nil {
			t.Fatal("real S3-to-v2 indexing", drained, err)
		}
		var indexed, pending, quarantined int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='indexed' AND indexed_at IS NOT NULL AND attempt=1),count(*) FILTER(WHERE state='pending'),count(*) FILTER(WHERE state='quarantined') FROM zasp_runtime_sandbox_search_outbox`).Scan(&indexed, &pending, &quarantined); err != nil || indexed != drained+1 || pending != receiptCount-indexed || quarantined != 0 {
			t.Fatal("v2 worker did not checkpoint exactly one receipt", indexed, pending, quarantined, err)
		}
		assertOldAPI()
		var scopedPending int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND state<>'indexed'`, f.scope.OrganizationID().String(), f.scope.WorkspaceID().String(), f.scope.EnvironmentID().String()).Scan(&scopedPending); err != nil {
			t.Fatal(err)
		}
		page := readPage(newAPI)
		want := "current"
		if scopedPending > 0 {
			want = "catching_up"
		}
		if page.Search.State != want || page.Search.Pending != scopedPending {
			t.Fatal("v2 API freshness preceded scoped completion", page.Search, scopedPending)
		}
	}
	count, immutableBefore := providerSnapshot()
	if count != occurrenceCount {
		t.Fatal("v2 provider omitted canonical occurrences", count, occurrenceCount)
	}
	for _, scope := range scopes {
		var expected []string
		if err := f.admin.QueryRow(ctx, `SELECT COALESCE(array_agg(id ORDER BY id),'{}'::text[]) FROM zasp_runtime_session_summaries WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&expected); err != nil {
			t.Fatal(err)
		}
		page, err := index.Search(ctx, scope, sessionsearch.Filters{}, "", 25)
		if err != nil || len(expected) == 0 || !slices.Equal(page.InvestigationIDs, expected) {
			t.Fatal("provider visibility differs from canonical scoped investigations", page, expected, err)
		}
	}
	after := readPage(newAPI)
	if after.Search.State != "current" || after.Search.Pending != 0 || after.Search.Quarantined != 0 || after.Search.LastIndexed == nil || !slices.EqualFunc(after.Items, before.Items, func(a, b json.RawMessage) bool { return bytes.Equal(a, b) }) {
		t.Fatalf("switched v2 API is incomplete: %+v", after)
	}
	foreign := identity
	for _, scope := range scopes {
		if scope.OrganizationID() != f.scope.OrganizationID() {
			foreign.Scope = scope
			break
		}
	}
	if foreign.Scope == identity.Scope {
		t.Fatal("missing populated foreign tenant")
	}
	if body, err := newAPI.ReadAdministration(ctx, foreign, "listSessions", map[string]string{"kind": "runtime", "limit": "25"}); !errors.Is(err, apiserver.ErrRepositoryNotFound) || len(body) != 0 {
		t.Fatal("API exposed populated foreign tenant", err)
	}
	foreignScope, err := domain.NewScope(workerID(t, "pid_90000001-0000-4000-8000-000000000001"), workerID(t, "pid_90000002-0000-4000-8000-000000000002"), workerID(t, "pid_90000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	foreign.PrincipalID, foreign.Scope = workerID(t, "pid_90000004-0000-4000-8000-000000000004"), foreignScope
	body, err := newAPI.ReadAdministration(ctx, foreign, "listSessions", map[string]string{"kind": "runtime", "limit": "25"})
	var empty sandboxCutoverPage
	if err != nil || json.Unmarshal(body, &empty) != nil || len(empty.Items) != 0 {
		t.Fatal("authorized empty foreign tenant inherited results", err)
	}
	v2Queue := queueSnapshot(true)
	if err := worker.Processor.RunOnce(ctx); err != nil {
		t.Fatal("idle v2 worker replay", err)
	}
	_, immutableAfter := providerSnapshot()
	if queueSnapshot(true) != v2Queue || queueSnapshot(false) != oldQueue || !bytes.Equal(immutableBefore, immutableAfter) {
		t.Fatal("idle worker replay changed checkpoints or immutable provider documents")
	}
	t.Logf("runtime sandbox search backfill cutover proven: production runner49-to50, %d real PostgreSQL/S3 receipts and %d visible OpenSearch occurrences across %d scopes, selected v2 worker and API repository, empty-target catch-up, old API current, v1 checkpoints unchanged, tenant denial and idle replay; local owned providers only, fresh sandbox producer activation NOT RUN", receiptCount, occurrenceCount, len(scopes))
}
