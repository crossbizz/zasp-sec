package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

type runtimeCandidateRecoveryFixture struct {
	admin               *pgx.Conn
	database            func(string) apiserver.JSONDatabase
	handler             http.Handler
	outbox, coordinator workerProcessor
	queue               *runtimePipelineDeliveryQueue
	archive             *runtimeArchiveExecutor
	index               *runtimeIndexExecutor
	receipts            artifactstore.ObjectReferencingArtifactStore
	graph               *graphstore.Store
}

// This proof selects v2 only for its own never-claimed pending jobs. It does not
// activate production producers. Enrollment is fixture setup; all runtime rows,
// candidate snapshots, graph writes and receipts come from actual workers.
func proveRuntimeCandidateRecovery(t *testing.T, ctx context.Context, f runtimeCandidateRecoveryFixture) {
	t.Helper()
	org := "pid_78930001-0000-4000-8000-000000000001"
	workspace := "pid_78930002-0000-4000-8000-000000000002"
	environment := "pid_78930003-0000-4000-8000-000000000003"
	scope, err := domain.NewScope(workerID(t, org), workerID(t, workspace), workerID(t, environment))
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Candidate recovery','candidate-recovery.invalid')`, []any{org}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Candidate recovery')`, []any{org, workspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Candidate recovery','test')`, []any{org, workspace, environment}},
		{`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES($1,$2,$3,'test','metadata_only',30,true,false)`, []any{org, workspace, environment}},
	} {
		if _, err := f.admin.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatal(err)
		}
	}
	anchor, semantic := "pid_78930101-0000-4000-8000-000000000101", "pid_78930102-0000-4000-8000-000000000102"
	wires := map[string]string{}
	for i, source := range []struct{ id, kind string }{{anchor, "tetragon"}, {semantic, "otlp"}} {
		if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Candidate recovery',$5,'active')`, org, workspace, environment, source.id, source.kind); err != nil {
			t.Fatal(err)
		}
		credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{byte(0x71 + i)}, 16), bytes.Repeat([]byte{byte(0x81 + i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		defer credential.Destroy()
		locator, err := credential.LocatorDigest()
		if err != nil {
			t.Fatal(err)
		}
		tokenID := workerID(t, fmt.Sprintf("pid_78930201-0000-4000-8000-%012d", 201+i))
		salt := bytes.Repeat([]byte{byte(0x91 + i)}, 32)
		hash, err := credential.Hash(sensor.SensorTokenAudienceEventIngest, tokenID, 1, salt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,$6,$7,$8,transaction_timestamp()+interval '1 day')`, org, workspace, environment, source.id, tokenID.String(), locator[:], salt, hash[:]); err != nil {
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
	now := time.Now().UTC().Truncate(time.Millisecond)
	lineage := runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: "78931001-0000-4000-8000-000000000001", NodeUID: "78931002-0000-4000-8000-000000000002", BootID: "78931003-0000-4000-8000-000000000003", PodUID: "78931004-0000-4000-8000-000000000004", ContainerID: "containerd://" + strings.Repeat("c", 64), ProcessID: "42", ProcessStartTime: now.Add(-time.Minute).Format(time.RFC3339Nano), CgroupID: "78931"}
	agent, session := "pid_78930301-0000-4000-8000-000000000301", "pid_78930302-0000-4000-8000-000000000302"
	correlationDB := f.database("zasp_e2e_correlation")
	correlationRepo, err := runtimeevent.NewPostgresProductionPipelineRepository(correlationDB, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil || correlationRepo.ReadyCandidates(ctx) != nil {
		t.Fatal("recovery candidate authority readiness", err)
	}
	correlation, err := newRuntimeCorrelationExecutorWithDatabase(runtimeCorrelationExecutorConfig{Reader: f.archive, Receipts: f.receipts, Graph: f.graph, ImplementationVersion: "runtime-correlation-v2"}, correlationDB)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := newRuntimeProjectionExecutor(runtimeProjectionExecutorConfig{Reader: f.archive, Receipts: f.receipts, Graph: f.graph, ImplementationVersion: "runtime-projection-v1"})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := newRuntimeCompleteExecutor(runtimeCompleteExecutorConfig{Receipts: f.receipts, ImplementationVersion: "runtime-complete-v1"})
	if err != nil {
		t.Fatal(err)
	}
	processors := map[runtimeevent.RuntimeStage]workerProcessor{}
	newProcessor := func(stage runtimeevent.RuntimeStage, version string, repo runtimeStageAuthority, executor runtimeStageExecutor, worker string) workerProcessor {
		t.Helper()
		p, err := newRuntimeStageProcessor(runtimeStageProcessorConfig{Authority: repo, Executor: executor, Stage: stage, ImplementationVersion: version, WorkerID: worker, LeaseSeconds: 30, BatchSize: 1, HeartbeatInterval: time.Second, RetrySeconds: 1, NewLeaseToken: newWorkerLeaseToken})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, stage := range []struct {
		stage              runtimeevent.RuntimeStage
		authority          runtimeevent.ProductionPipelineAuthority
		principal, version string
		executor           runtimeStageExecutor
	}{
		{runtimeevent.RuntimeStageArchive, runtimeevent.ProductionPipelineAuthorityArchive, "zasp_e2e_archive", "runtime-archive-v1", f.archive},
		{runtimeevent.RuntimeStageIndex, runtimeevent.ProductionPipelineAuthorityIndex, "zasp_e2e_index", "runtime-index-v1", f.index},
		{runtimeevent.RuntimeStageProject, runtimeevent.ProductionPipelineAuthorityProjection, "zasp_e2e_runtime_projection", "runtime-projection-v1", projection},
		{runtimeevent.RuntimeStageComplete, runtimeevent.ProductionPipelineAuthorityCoordinator, "zasp_e2e_coordinator", "runtime-complete-v1", complete},
	} {
		repo, err := runtimeevent.NewPostgresProductionPipelineRepository(f.database(stage.principal), stage.authority)
		if err != nil || repo.Ready(ctx) != nil {
			t.Fatal("recovery stage authority readiness", err)
		}
		processors[stage.stage] = newProcessor(stage.stage, stage.version, repo, stage.executor, "candidate-recovery-"+string(stage.stage))
	}
	processors[runtimeevent.RuntimeStageCorrelate] = newProcessor(runtimeevent.RuntimeStageCorrelate, "runtime-correlation-v2", correlationRepo, correlation, "candidate-recovery-correlation")
	pause := func(duration time.Duration) {
		t.Helper()
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
	runStage := func(batch string, stage runtimeevent.RuntimeStage, processor workerProcessor) {
		t.Helper()
		for i := 0; i < 120; i++ {
			if err := processor.RunOnce(ctx); err != nil {
				t.Fatalf("candidate recovery stage %s: %v", stage, err)
			}
			var state string
			err := f.admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_stage_work WHERE organization_id=$1 AND batch_id=$2 AND stage=$3`, org, batch, string(stage)).Scan(&state)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal(err)
			}
			if state == "succeeded" {
				return
			}
			if state != "" && state != "pending" && state != "leased" {
				t.Fatalf("candidate recovery stage %s state %s", stage, state)
			}
			pause(50 * time.Millisecond)
		}
		t.Fatalf("candidate recovery stage %s did not finish", stage)
	}
	serial := 0
	ingest := func(source, agentID, sessionID string) (string, <-chan error, context.CancelFunc) {
		t.Helper()
		serial++
		event := map[string]any{"observed_lineage": lineage, "event_time": now.Format("2006-01-02T15:04:05.000Z"), "evidence_id": fmt.Sprintf("pid_78930401-0000-4000-8000-%012d", 400+serial)}
		if source == "otlp" {
			event["attributes"] = map[string]string{"event.id": fmt.Sprintf("candidate-recovery-%d", serial), "event.class": "tool", "event.action": "invoke", "agent.id": agentID, "session.id": sessionID, "task.id": "candidate-task", "tool.id": "candidate-tool", "sandbox.id": "candidate-sandbox", "trace.id": strings.Repeat("c", 32), "span.id": strings.Repeat("d", 16)}
		} else {
			event["event_id"] = fmt.Sprintf("candidate-recovery-%d", serial)
			event["class"] = "process"
			event["action"] = "exec"
			event["workload_id"] = "candidate-recovery"
			event["content"] = map[string]string{}
		}
		body, err := json.Marshal(map[string]any{"source": source, "events": []any{event}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtimeevent.DecodeArchivedBatch(scope, body); err != nil {
			t.Fatalf("candidate %s input fixture rejected before HTTP: %v", source, err)
		}
		request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+wires[source])
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
		request.Header.Set("Idempotency-Key", fmt.Sprintf("candidate-recovery-proof-%04d", serial))
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, request)
		var accepted struct {
			BatchID string `json:"batch_id"`
		}
		if response.Code != http.StatusAccepted || json.Unmarshal(response.Body.Bytes(), &accepted) != nil || accepted.BatchID == "" {
			t.Fatalf("candidate recovery ingest status=%d body=%s", response.Code, response.Body.String())
		}
		if err := f.outbox.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		coordinatorDone, stopCoordinator := startRuntimeCandidateCoordinator(t, ctx, f, scope, accepted.BatchID)
		t.Logf("candidate recovery accepted %s fixture batch %d", source, serial)
		for _, stage := range []runtimeevent.RuntimeStage{runtimeevent.RuntimeStageArchive, runtimeevent.RuntimeStageIndex} {
			runStage(accepted.BatchID, stage, processors[stage])
		}
		// Fixture-owned rollout selection only. Never seed completed work or edit a
		// live lease, receipt, snapshot, expiry or database clock.
		selected, err := f.admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-correlation-v2' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4 AND stage='correlate' AND state='pending' AND attempt=0 AND implementation_version='runtime-correlation-v1'`, org, workspace, environment, accepted.BatchID)
		if err != nil || selected.RowsAffected() != 1 {
			t.Fatal("fixture-only v2 selection failed", err)
		}
		return accepted.BatchID, coordinatorDone, stopCoordinator
	}
	finish := func(batch string, coordinatorDone <-chan error, correlate bool) {
		t.Helper()
		if correlate {
			runStage(batch, runtimeevent.RuntimeStageCorrelate, processors[runtimeevent.RuntimeStageCorrelate])
		}
		for _, stage := range []runtimeevent.RuntimeStage{runtimeevent.RuntimeStageProject, runtimeevent.RuntimeStageComplete} {
			runStage(batch, stage, processors[stage])
		}
		select {
		case err := <-coordinatorDone:
			if err != nil {
				t.Fatal("candidate coordinator", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		var state string
		if err := f.admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_batch_authorities WHERE organization_id=$1 AND batch_id=$2`, org, batch).Scan(&state); err != nil || state != "succeeded" {
			t.Fatalf("candidate completed batch state=%s err=%v", state, err)
		}
	}
	readReceipt := func(batch string) (artifactstore.Artifact, runtimecorrelation.Receipt) {
		t.Helper()
		var reference, version string
		var digest []byte
		if err := f.admin.QueryRow(ctx, `SELECT result_reference,result_version_id,result_digest FROM zasp_runtime_stage_work WHERE organization_id=$1 AND batch_id=$2 AND stage='correlate' AND state='succeeded'`, org, batch).Scan(&reference, &version, &digest); err != nil {
			t.Fatal(err)
		}
		locator, ok := runtimeReceiptLocator(scope, reference, version)
		if !ok {
			t.Fatal("candidate receipt locator")
		}
		artifact, err := f.receipts.Get(ctx, locator)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := runtimecorrelation.DecodeReceipt(artifact.Body)
		if err != nil || !bytes.Equal(digest, artifact.SHA256[:]) || sha256.Sum256(artifact.Body) != artifact.SHA256 || receipt.Scope != scope || receipt.BatchID.String() != batch || receipt.ImplementationVersion != "runtime-correlation-v2" || len(receipt.Results) != 1 {
			t.Fatal("candidate receipt binding", err)
		}
		return artifact, receipt
	}
	first, firstDone, _ := ingest("otlp", agent, session)
	finish(first, firstDone, true)
	_, firstReceipt := readReceipt(first)
	if firstReceipt.Results[0].Confidence.String() != "exact" {
		t.Fatal("semantic candidate wasn't Exact")
	}
	target, targetDone, stopTargetCoordinator := ingest("tetragon", "", "")
	leaseToken, err := newWorkerLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	const disappearedWorker = "candidate-recovery-disappeared"
	leases, err := correlationRepo.ClaimStages(ctx, disappearedWorker, leaseToken, 30, 1)
	if err != nil || len(leases) != 1 || leases[0].BatchID.String() != target || leases[0].Attempt != 1 || leases[0].Scope != scope {
		t.Fatal("candidate initial claim", err)
	}
	lease := leases[0]
	lostReceipt := &runtimeCandidateLostReceipt{ObjectReferencingArtifactStore: f.receipts, loseNext: true}
	observedGraph := &runtimeCandidateRecoveryGraph{delegate: f.graph}
	crashing, err := newRuntimeCorrelationExecutorWithDatabase(runtimeCorrelationExecutorConfig{Reader: f.archive, Receipts: lostReceipt, Graph: observedGraph, ImplementationVersion: "runtime-correlation-v2"}, correlationDB)
	if err != nil {
		t.Fatal(err)
	}
	// A lost write response is an unknown outcome, not a confirmed failure. The
	// simulated vanished process never records this outcome or renews its lease.
	if _, err := crashing.ExecuteAuthorized(ctx, runtimeStageExecution{lease: lease, workerID: disappearedWorker, leaseToken: leaseToken}); !errors.Is(err, errWorkerExecution) || len(lostReceipt.writes) != 1 || len(observedGraph.results) != 1 || observedGraph.results[0].Replayed {
		t.Fatalf("candidate disappearance boundary: error=%v receipt_writes=%d graph_commits=%d", err, len(lostReceipt.writes), len(observedGraph.results))
	}
	persisted, err := f.receipts.Get(ctx, lostReceipt.writes[0].Locator)
	if err != nil || !bytes.Equal(persisted.Body, lostReceipt.bodies[0]) {
		t.Fatal("lost response lacked durable S3 object", err)
	}
	readSnapshot := func() ([]byte, []byte) {
		t.Helper()
		var body, digest []byte
		if err := f.admin.QueryRow(ctx, `SELECT snapshot_body,snapshot_digest FROM zasp_runtime_candidate_snapshots WHERE organization_id=$1 AND batch_id=$2 AND generation=$3`, org, target, lease.Generation).Scan(&body, &digest); err != nil {
			t.Fatal(err)
		}
		return body, digest
	}
	frozenBody, frozenDigest := readSnapshot()
	// The authority intentionally serializes active deliveries and same-stage
	// leases per organization. Stop the target coordinator as well as correlation,
	// then let both real DB leases expire before admitting the late batch.
	stopTargetCoordinator()
	select {
	case err := <-targetDone:
		if err == nil {
			t.Fatal("crashed target coordinator unexpectedly acknowledged")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.queue.deliveryMu.Lock()
	targetDelivery, captured := f.queue.deliveries[target]
	f.queue.deliveryMu.Unlock()
	if !captured {
		t.Fatal("target SQS delivery was not observed")
	}
	// Actual provider visibility postpones redelivery until after late evidence.
	// No DB state, receipt, stage lease or database clock is edited.
	if err := f.queue.ExtendVisibility(ctx, []jobqueue.Receipt{targetDelivery}, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	var deliveryExpires time.Time
	if err := f.admin.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_runtime_deliveries WHERE organization_id=$1 AND batch_id=$2 AND disposition='held' AND provider_ack_digest IS NULL`, org, target).Scan(&deliveryExpires); err != nil {
		t.Fatal(err)
	}
	expires := lease.LeaseExpiresAt
	if deliveryExpires.After(expires) {
		expires = deliveryExpires
	}
	pause(time.Until(expires.Add(100 * time.Millisecond)))
	var expired bool
	if err := f.admin.QueryRow(ctx, `SELECT work.state='leased' AND work.attempt=1 AND work.lease_expires_at<=clock_timestamp() AND delivery.disposition='held' AND delivery.lease_expires_at<=clock_timestamp() AND delivery.provider_ack_digest IS NULL FROM zasp_runtime_stage_work work JOIN zasp_runtime_deliveries delivery USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE work.organization_id=$1 AND work.batch_id=$2 AND work.stage='correlate'`, org, target).Scan(&expired); err != nil || !expired {
		t.Fatal("crashed worker leases did not naturally expire", err)
	}
	late, lateDone, _ := ingest("otlp", "pid_78930501-0000-4000-8000-000000000501", "pid_78930502-0000-4000-8000-000000000502")
	finish(late, lateDone, true)
	if err := f.queue.ExtendVisibility(ctx, []jobqueue.Receipt{targetDelivery}, time.Second); err != nil {
		t.Fatal(err)
	}
	targetDone, _ = startRuntimeCandidateCoordinator(t, ctx, f, scope, target)
	replacement := newProcessor(runtimeevent.RuntimeStageCorrelate, "runtime-correlation-v2", correlationRepo, crashing, "candidate-recovery-replacement")
	runStage(target, runtimeevent.RuntimeStageCorrelate, replacement)
	var attempt int
	if err := f.admin.QueryRow(ctx, `SELECT attempt FROM zasp_runtime_stage_work WHERE organization_id=$1 AND batch_id=$2 AND stage='correlate'`, org, target).Scan(&attempt); err != nil || attempt != 2 {
		t.Fatal("candidate was not reclaimed under a new attempt", err)
	}
	if len(observedGraph.results) != 2 || !observedGraph.results[1].Replayed {
		t.Fatal("replacement did not replay real Neo4j commit")
	}
	before, after := observedGraph.results[0], observedGraph.results[1]
	before.Replayed = true
	if !reflect.DeepEqual(before, after) || len(lostReceipt.writes) != 2 || lostReceipt.writes[0].Locator != lostReceipt.writes[1].Locator || !bytes.Equal(lostReceipt.bodies[0], lostReceipt.bodies[1]) {
		t.Fatal("replacement changed graph or versioned S3 receipt")
	}
	afterBody, afterDigest := readSnapshot()
	if !bytes.Equal(frozenBody, afterBody) || !bytes.Equal(frozenDigest, afterDigest) {
		t.Fatal("late admission changed frozen PostgreSQL bytes")
	}
	artifact, recovered := readReceipt(target)
	result := recovered.Results[0]
	if artifact.Locator != persisted.Locator || !bytes.Equal(artifact.Body, persisted.Body) || result.Confidence.String() != "strong" || result.AgentID.String() != agent || result.SessionID.String() != session || !bytes.Equal(recovered.CandidateSnapshotDigest[:], frozenDigest) {
		t.Fatal("recovered decision wasn't the original frozen Strong attribution")
	}
	staleDB := &runtimeCandidateFinishObserver{JSONDatabase: correlationDB}
	staleRepo, err := runtimeevent.NewPostgresProductionPipelineRepository(staleDB, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	staleLease := lease
	// Defeat only the Go precheck, not the real DB lease. The old attempt and
	// credentials must reach SQL and be denied by its authoritative fence.
	staleLease.LeaseExpiresAt = time.Now().Add(30 * time.Second)
	if _, err := staleRepo.FinishStage(ctx, runtimeevent.StageFinishRequest{Lease: staleLease, WorkerID: disappearedWorker, LeaseToken: leaseToken, Outcome: runtimeevent.StageOutcomeSucceeded, EffectDigest: recovered.EffectDigest, ResultReference: mustCandidateObjectReference(t, f.receipts, artifact.Locator), ResultVersionID: artifact.VersionID, ResultDigest: artifact.SHA256}); !errors.Is(err, runtimeevent.ErrProductionPipelineUnknown) || staleDB.calls != 1 || !errors.Is(staleDB.resultErr, apiserver.ErrRepositoryNotFound) {
		t.Fatal("SQL stale-worker fence was not exercised", err)
	}
	unchanged, _ := readReceipt(target)
	if unchanged.Locator != artifact.Locator || !bytes.Equal(unchanged.Body, artifact.Body) {
		t.Fatal("stale SQL completion changed replacement")
	}
	finish(target, targetDone, false)
	ambiguous, ambiguousDone, _ := ingest("tetragon", "", "")
	finish(ambiguous, ambiguousDone, true)
	_, ambiguousReceipt := readReceipt(ambiguous)
	uncertain := ambiguousReceipt.Results[0]
	if uncertain.Confidence.String() != "probable" || !uncertain.AgentID.IsZero() || !uncertain.SessionID.IsZero() {
		t.Fatal("new batch didn't see conflicting candidates as unattributed Probable")
	}
	var durableStrong, durableProbable, totalEvents int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE event_id=$4 AND source='tetragon' AND confidence='strong' AND agent_id=$6 AND session_id=$7),count(*) FILTER (WHERE event_id=$5 AND source='tetragon' AND confidence='probable' AND agent_id IS NULL AND session_id IS NULL),count(*) FROM zasp_runtime_session_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, org, workspace, environment, result.EventID.String(), uncertain.EventID.String(), agent, session).Scan(&durableStrong, &durableProbable, &totalEvents); err != nil || durableStrong != 1 || durableProbable != 1 || totalEvents != 4 {
		t.Fatal("completed sessions lost recovered confidence or duplicated events", err)
	}
	t.Log("runtime candidate recovery proven: authenticated ingest, registered PostgreSQL roles, natural lease expiry, frozen late-admission replay, actual TLS Neo4j replay and identical S3 version, Strong recovery and fresh Probable conflict; fixture-selected v2 jobs, cloud and producer activation NOT RUN")
}

func mustCandidateObjectReference(t *testing.T, store artifactstore.ObjectReferencingArtifactStore, locator artifactstore.Locator) string {
	t.Helper()
	ref, err := store.ObjectReference(locator)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// Poll the actual coordinator, including empty SQS short polls. Observe only the
// exact batch's persisted acknowledgement on a separate connection. Cleanup waits
// for this goroutine; no pgx.Conn is shared concurrently or allowed to outlive it.
func startRuntimeCandidateCoordinator(t *testing.T, parent context.Context, f runtimeCandidateRecoveryFixture, scope domain.Scope, batch string) (<-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	observer, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done, stopped := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("candidate coordinator did not stop")
		}
	})
	go func() {
		defer close(stopped)
		defer observer.Close(context.Background())
		for {
			if err := f.coordinator.RunOnce(ctx); err != nil {
				done <- err
				return
			}
			var disposition string
			err := observer.QueryRow(ctx, `SELECT disposition FROM zasp_runtime_deliveries WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND batch_id=$4`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch).Scan(&disposition)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				done <- err
				return
			}
			if disposition == "acked" {
				done <- nil
				return
			}
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				done <- ctx.Err()
				return
			case <-timer.C:
			}
		}
	}()
	return done, cancel
}

type runtimeCandidateLostReceipt struct {
	artifactstore.ObjectReferencingArtifactStore
	loseNext bool
	writes   []artifactstore.Artifact
	bodies   [][]byte
}

func (store *runtimeCandidateLostReceipt) Put(ctx context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	artifact, err := store.ObjectReferencingArtifactStore.Put(ctx, request)
	if err != nil {
		return artifact, err
	}
	store.writes = append(store.writes, artifact)
	store.bodies = append(store.bodies, bytes.Clone(request.Body))
	if store.loseNext {
		store.loseNext = false
		return artifactstore.Artifact{}, artifactstore.ErrPut
	}
	return artifact, nil
}

type runtimeCandidateRecoveryGraph struct {
	delegate *graphstore.Store
	results  []graphstore.SnapshotApplyResult
}

type runtimeCandidateFinishObserver struct {
	apiserver.JSONDatabase
	calls     int
	resultErr error
}

func (observer *runtimeCandidateFinishObserver) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	observer.calls++
	body, err := observer.JSONDatabase.QueryJSON(ctx, statement, args...)
	observer.resultErr = err
	return body, err
}

func (graph *runtimeCandidateRecoveryGraph) ApplySnapshot(ctx context.Context, snapshot graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
	result, err := graph.delegate.ApplySnapshot(ctx, snapshot)
	if err == nil {
		graph.results = append(graph.results, result)
	}
	return result, err
}
