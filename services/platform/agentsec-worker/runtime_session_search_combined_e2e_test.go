package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type sessionSearchProofDatabase struct {
	apiserver.JSONDatabase
	test *testing.T
}

func (database *sessionSearchProofDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	body, err := database.JSONDatabase.QueryJSON(ctx, statement, args...)
	if strings.Contains(statement, "session_search") {
		database.test.Logf("owned session search DB query=%s response_bytes=%d err=%v", statement, len(body), err)
	}
	return body, err
}

// This fixture executes the production processor using its registered index
// principal. Receipt/outbox rows come from actual worker completion, not seeding.
func proveRuntimeSessionSearchIndex(t *testing.T, ctx context.Context, admin *pgx.Conn, scope domain.Scope, batchID domain.ProductID, archive []byte, index *opensearchdriver.SessionIndex, processor workerProcessor, receipts artifactstore.ObjectReferencingArtifactStore) {
	t.Helper()
	var reference, version string
	var digest []byte
	var generation int64
	if err := admin.QueryRow(ctx, `SELECT project.result_reference,project.result_version_id,receipt.receipt_digest,receipt.batch_generation
 FROM zasp_runtime_session_projection_receipts receipt
 JOIN zasp_runtime_stage_work project USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 JOIN zasp_runtime_stage_work complete USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
 WHERE receipt.organization_id=$1 AND receipt.workspace_id=$2 AND receipt.environment_id=$3 AND receipt.batch_id=$4
 AND project.stage='project' AND project.state='succeeded' AND receipt.receipt_digest=project.result_digest
 AND complete.stage='complete' AND complete.state='succeeded'`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String()).Scan(&reference, &version, &digest, &generation); err != nil || len(digest) != sha256.Size {
		t.Fatalf("committed session search authority unavailable: %v", err)
	}
	locator, ok := runtimeReceiptLocator(scope, reference, version)
	if !ok {
		t.Fatal("invalid committed receipt locator")
	}
	artifact, err := receipts.Get(ctx, locator)
	if err != nil || !exactRuntimeReceiptArtifact(artifact, locator) {
		t.Fatalf("committed receipt readback: %v", err)
	}
	defer clear(artifact.Body)
	binding := sessionsearch.ReceiptBinding{Scope: scope, BatchID: batchID, Generation: generation}
	copy(binding.ReceiptDigest[:], digest)
	var state string
	var attempt int
	if err := admin.QueryRow(ctx, `SELECT state,attempt FROM zasp_runtime_session_search_outbox WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4 AND batch_generation=$5`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String(), generation).Scan(&state, &attempt); err != nil || state != "pending" || attempt != 0 {
		t.Fatalf("committed search outbox missing: state=%s attempt=%d err=%v", state, attempt, err)
	}
	if processor == nil {
		t.Fatal("production session indexing processor missing")
	}
	for replay := 0; replay < 2; replay++ {
		if err := processor.RunOnce(ctx); err != nil {
			t.Fatalf("production session index processor: %v", err)
		}
	}
	var checkpointDigest []byte
	var indexedAt *time.Time
	if err := admin.QueryRow(ctx, `SELECT state,attempt,receipt_digest,indexed_at FROM zasp_runtime_session_search_outbox WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4 AND batch_generation=$5`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String(), generation).Scan(&state, &attempt, &checkpointDigest, &indexedAt); err != nil || state != "indexed" || attempt != 1 || indexedAt == nil || !bytes.Equal(checkpointDigest, digest) {
		t.Fatalf("search checkpoint was not fenced: state=%s attempt=%d err=%v", state, attempt, err)
	}
	for replay := 0; replay < 2; replay++ {
		result, err := index.Apply(ctx, binding, artifact.Body, archive)
		if err != nil || result.Scope != scope || result.BatchID != batchID || result.Generation != generation || result.ReceiptDigest != binding.ReceiptDigest || len(result.DocumentIDs) != 26 {
			t.Fatalf("session index write/replay %d: %#v %v", replay, result, err)
		}
	}
	page, err := index.Search(ctx, scope, sessionsearch.Filters{Process: "/usr/bin/agent"}, "", 1)
	if err != nil || len(page.InvestigationIDs) != 1 || page.InvestigationIDs[0] != "unattributed" || page.After != "unattributed" {
		t.Fatalf("real structured session search: %#v %v", page, err)
	}
	if page, err := index.Search(ctx, scope, sessionsearch.Filters{Process: "/usr/bin/agent"}, "unattributed", 1); err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatalf("real session pagination: %#v %v", page, err)
	}
	if page, err := index.Search(ctx, scope, sessionsearch.Filters{Process: "/usr/bin/other"}, "", 25); err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatalf("wrong process matched: %#v %v", page, err)
	}
	foreign, err := domain.NewScope(scope.OrganizationID(), scope.WorkspaceID(), workerID(t, "pid_79000999-0000-4000-8000-000000000999"))
	if err != nil {
		t.Fatal(err)
	}
	if page, err := index.Search(ctx, foreign, sessionsearch.Filters{}, "", 25); err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatalf("cross-environment search leaked: %#v %v", page, err)
	}
	if _, err := index.Search(ctx, scope, sessionsearch.Filters{RawQuery: `{"match_all":{}}`}, "", 25); err == nil {
		t.Fatal("raw DSL admitted")
	}
	t.Log("runtime session search index proven: committed PG receipt, exact S3 archive, real OpenSearch, immutable replay, structured process filter, pagination and scope denial; search API remains pending")
	t.Log("production session indexing outbox proven: completion transaction, registered index worker, exact receipt/archive read, live lease renewal, indexed checkpoint and idle replay without duplicate claims")
	proveRuntimeStructuredSearchSelectors(t, ctx, index)
}

// The harness runs exactly one owned OpenSearch node. Explicitly configure its
// dedicated proof index with zero replicas; do not relax production refresh
// validation to count unassigned copies as successful or claim HA evidence.
func configureOwnedSingleNodeSessionIndex(t *testing.T, ctx context.Context, endpoint string) {
	t.Helper()
	runtimePipelineLoopback(t, endpoint)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(method, path string, body []byte) []byte {
		call, err := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			call.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(call)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(result) > 16384 || response.StatusCode != http.StatusOK {
			t.Fatalf("owned index configuration rejected: %v", err)
		}
		return result
	}
	before := request(http.MethodPost, "/zasp-runtime-sessions-v1/_refresh", nil)
	var shards struct {
		Shards struct{ Total, Successful, Failed int } `json:"_shards"`
	}
	if json.Unmarshal(before, &shards) != nil || shards.Shards.Total != 2 || shards.Shards.Successful != 1 || shards.Shards.Failed != 0 {
		t.Fatalf("single-node default replica assumption not observed: %s", before)
	}
	t.Logf("owned single-node default refresh observed: %s; configuring this proof index only with zero replicas", before)
	result := request(http.MethodPut, "/zasp-runtime-sessions-v1/_settings", []byte(`{"index":{"number_of_replicas":0}}`))
	var ack struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if json.Unmarshal(result, &ack) != nil || !ack.Acknowledged {
		t.Fatal("owned single-node replica update not acknowledged")
	}
	after := request(http.MethodPost, "/zasp-runtime-sessions-v1/_refresh", nil)
	if json.Unmarshal(after, &shards) != nil || shards.Shards.Total != 1 || shards.Shards.Successful != 1 || shards.Shards.Failed != 0 {
		t.Fatalf("owned replica configuration not effective: %s", after)
	}
}
