package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func runtimeCorrelationRoutingPredecessor(t *testing.T, ctx context.Context) (*pgx.Conn, *migrations.Runner, *pgx.Conn) {
	t.Helper()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	for _, up := range []func(context.Context) error{runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority, runner.UpProductionRuntimeAcceptance} {
		if err := up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"candidate_coordinator", "candidate_archive", "candidate_index", "candidate_correlation", "candidate_projection", "candidate_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_register_principals(session_user,'candidate_coordinator','candidate_archive','candidate_index','candidate_correlation','candidate_projection','candidate_gateway')`); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "candidate_correlation"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	return admin, runner, worker
}

func TestRuntimeCorrelationRoutingLegacyClaimLeavesV2Untouched(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	const sensor = "pid_78900001-0000-4000-8000-000000000001"
	seedRuntimeCandidateSensor(t, ctx, admin, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, sensor, "tetragon")
	for index, state := range []string{"pending", "retryable", "expired-leased", "exhausted"} {
		t.Run(state, func(t *testing.T) {
			args := seedRuntimeCandidateBatch(t, ctx, admin, index+1, sensor, "tetragon", 0)
			if state == "expired-leased" {
				if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
					t.Fatal(err)
				}
			} else if state == "exhausted" {
				// Seed exhausted work directly. Don't disable the mutation fence or
				// impersonate a compatible worker to prepare this controlled fixture.
				if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt) VALUES($1,$2,$3,$4,$5,'correlate',3,'runtime-correlation-v2',$6,$6,'pending',100)`, args[0], args[1], args[2], args[3], args[4], args[9]); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET state=$2,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1 AND stage='correlate'`, args[3], state); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				t.Helper()
				var value string
				if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('stages',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.batch_id,s.stage) FROM zasp_runtime_stage_work s),'batches',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.batch_id) FROM zasp_runtime_batch_authorities b),'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.batch_id) FROM zasp_runtime_deliveries d),'fairness',(SELECT jsonb_agg(to_jsonb(f) ORDER BY f.stage,f.organization_id) FROM zasp_runtime_stage_fairness f))::text`).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := snapshot()
			var claimed json.RawMessage
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('legacy-reader','legacy-reader-lease',30,10)`).Scan(&claimed); err != nil {
				t.Fatal(err)
			}
			if string(claimed) != "[]" || before != snapshot() {
				t.Fatal("legacy poll mutated or claimed v2 work", string(claimed))
			}
		})
	}
}

func TestRuntimeCorrelationRoutingFinalAttemptCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	const sensor = "pid_78900001-0000-4000-8000-000000000001"
	seedRuntimeCandidateSensor(t, ctx, admin, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, sensor, "tetragon")
	for index, outcome := range []string{"retryable", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			args := seedRuntimeCandidateBatch(t, ctx, admin, index+1, sensor, "tetragon", 0)
			for _, query := range []string{
				`DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`,
				`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt) SELECT organization_id,workspace_id,environment_id,batch_id,batch_generation,'correlate',3,'runtime-correlation-v2',effect_digest,effect_digest,'pending',99 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='index'`,
				`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version) SELECT organization_id,workspace_id,environment_id,batch_id,sensor_id,idempotency_key,content_digest,event_count,raw_artifact_reference,payload_size_bytes,payload_media_type,payload_schema_version FROM zasp_runtime_batch_authorities WHERE batch_id=$1`,
				`INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) SELECT organization_id,workspace_id,environment_id,batch_id,'runtime',batch_id,idempotency_key,request_digest FROM zasp_runtime_batch_authorities WHERE batch_id=$1`,
			} {
				if _, err := admin.Exec(ctx, query, args[3]); err != nil {
					t.Fatal(err)
				}
			}
			database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
			if err != nil {
				t.Fatal(err)
			}
			repository, err := runtimeevent.NewPostgresCorrelationPipelineRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			leases, err := repository.ClaimStages(ctx, "final-worker", "final-lease-token-01", 60, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(leases) != 1 || leases[0].Attempt != 100 || leases[0].BatchID.String() != args[3] {
				t.Fatal("final attempt not claimed", leases)
			}
			var marker string
			if err := worker.QueryRow(ctx, `SELECT COALESCE(current_setting('zasp.runtime_correlation_claim_version',true),'')`).Scan(&marker); err != nil || marker != "" {
				t.Fatal("claim leaked marker", marker, err)
			}
			errorClass, retrySeconds := "malformed", 0
			if outcome == "retryable" {
				errorClass, retrySeconds = "retryable", 1
			}
			finishArgs := []any{args[0], args[1], args[2], args[3], args[4], "final-worker", "final-lease-token-01", 100, args[9], "runtime-correlation-v2", outcome, nil, nil, nil, nil, errorClass, retrySeconds}
			var result, replay json.RawMessage
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, finishArgs...).Scan(&result); err != nil {
				t.Fatal("live-owner final completion rejected", err)
			}
			var terminal bool
			if err := admin.QueryRow(ctx, `SELECT s.state='failed' AND s.last_error_class='exhausted' AND s.attempt=100 AND s.lease_owner IS NULL AND s.completed_at IS NOT NULL AND s.completion_digest=b.completion_digest AND s.completion_digest=j.completion_digest AND s.completion_result=$2::jsonb AND b.state='failed' AND l.state='failed' AND j.state='failed' AND d.disposition='ack_pending' FROM zasp_runtime_stage_work s JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_deliveries d USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_batches l ON l.id=s.batch_id JOIN zasp_discovery_jobs j ON j.authority_id=s.batch_id AND j.kind='runtime' WHERE s.batch_id=$1 AND s.stage='correlate'`, args[3], result).Scan(&terminal); err != nil || !terminal {
				t.Fatal("terminal cascades or receipt missing", terminal, err, string(result))
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, finishArgs...).Scan(&replay); err != nil || string(replay) != string(result) {
				t.Fatal("terminal completion replay changed", string(replay), err)
			}
			request := runtimeevent.StageFinishRequest{Lease: leases[0], WorkerID: "final-worker", LeaseToken: "final-lease-token-01", Outcome: runtimeevent.StageOutcome(outcome), ErrorClass: errorClass, RetryAfter: time.Duration(retrySeconds) * time.Second}
			if replay, err := repository.FinishStage(ctx, request); err != nil || replay.State != runtimeevent.StageOutcomeFailed || replay.ErrorClass != "exhausted" || replay.Attempt != 100 {
				t.Fatal("Go repository rejected durable terminal replay", replay, err)
			}
		})
	}
}

func TestRuntimeCorrelationRoutingMetadataFingerprint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _, _ := runtimeCorrelationRoutingPredecessor(t, ctx)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, migrations.ProductionRuntimeCorrelationRouting().UpSQL()); err != nil {
		t.Fatal(err)
	}
	var actual string
	var secure bool
	if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_live_fingerprint(),zasp_production_runtime_correlation_routing_security_ready()`).Scan(&actual, &secure); err != nil || !secure || actual != migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint() {
		t.Fatalf("routing fingerprint actual=%s secure=%t err=%v", actual, secure, err)
	}
}

func TestRuntimeCorrelationRoutingRunnerAndAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, _ := runtimeCorrelationRoutingPredecessor(t, ctx)
	var before string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_acceptance_live_fingerprint()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_discovery_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	for cycle := 0; cycle < 2; cycle++ {
		if err := repository.Ready(ctx); err != nil {
			t.Fatal("compatible API rejected schema48", err)
		}
		if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
			t.Fatal("routing upgrade", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 49 {
			t.Fatal("routing version", version, err)
		}
		if err := repository.Ready(ctx); err != nil {
			t.Fatal("compatible API rejected schema49", err)
		}
		if err := runner.DownProductionRuntimeCorrelationRouting(ctx); err != nil {
			t.Fatal("routing rollback", err)
		}
		var restored string
		if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_acceptance_live_fingerprint()`).Scan(&restored); err != nil || restored != before {
			t.Fatal("rollback did not restore exact schema48", err)
		}
	}
}

func TestRuntimeCorrelationRoutingRepositoryCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresCorrelationPipelineRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatal("healthy48 reader rejected", err)
	}
	if leases, err := repository.ClaimStages(ctx, "capability-reader", "capability-lease-token", 30, 1); err != nil || len(leases) != 0 {
		t.Fatal("empty48 claim fallback failed", leases, err)
	}
	scope := fixtureRequestIdentity(t).Scope
	const sensor = "pid_78900001-0000-4000-8000-000000000001"
	seedRuntimeCandidateSensor(t, ctx, admin, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, sensor, "tetragon")
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, sensor, "tetragon", 0)
	// Controlled repository fixture, not fresh-ingestion product evidence.
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-correlation-v1',state='pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatal("healthy49 reader rejected", err)
	}
	for _, version := range []string{"runtime-correlation-v1", "runtime-correlation-v2"} {
		if version == "runtime-correlation-v2" {
			args = seedRuntimeCandidateBatch(t, ctx, admin, 2, sensor, "tetragon", 0)
			if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET state='pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
				t.Fatal(err)
			}
			legacy, _ := runtimeevent.NewPostgresProductionPipelineRepository(database, runtimeevent.ProductionPipelineAuthorityCorrelation)
			if leases, err := legacy.ClaimStages(ctx, "legacy-reader", "legacy-lease-token", 30, 1); err != nil || len(leases) != 0 {
				t.Fatal("legacy reader stole49 v2", leases, err)
			}
		}
		leases, err := repository.ClaimStages(ctx, "capability-reader", "capability-lease-token", 30, 1)
		if err != nil || len(leases) != 1 || leases[0].ImplementationVersion != version || leases[0].BatchID.String() != args[3] {
			t.Fatal("compatible repository didn't drain version", version, leases, err)
		}
		if result, err := repository.FinishStage(ctx, runtimeevent.StageFinishRequest{Lease: leases[0], WorkerID: "capability-reader", LeaseToken: "capability-lease-token", Outcome: runtimeevent.StageOutcomeFailed, ErrorClass: "malformed"}); err != nil || result.State != runtimeevent.StageOutcomeFailed {
			t.Fatal("repository completion rejected", result, err)
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_correlation_routing_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(ctx); err != runtimeevent.ErrProductionPipelineUnavailable {
		t.Fatal("repository accepted drift", err)
	}
	if _, err := repository.ClaimStages(ctx, "capability-reader", "capability-lease-token", 30, 1); err != runtimeevent.ErrProductionPipelineUnavailable {
		t.Fatal("poll trusted stale readiness", err)
	}
}

func TestRuntimeCorrelationRoutingFencesAlreadyEnteredLegacyClaim(t *testing.T) {
	for _, test := range []struct {
		name      string
		fenced    bool
		exhausted bool
	}{{"negative-control-without-trigger", false, false}, {"mutation-fenced", true, false}, {"exhaustion-negative-control", false, true}, {"exhaustion-fenced", true, true}} {
		t.Run(test.name, func(t *testing.T) { proveRuntimeCorrelationRoutingInFlight(t, test.fenced, test.exhausted) })
	}
}

func proveRuntimeCorrelationRoutingInFlight(t *testing.T, fenced, exhausted bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	barrier, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Close(context.Background())
	tx, err := barrier.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-runtime-stage-claim:correlate',0))`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var result json.RawMessage
		done <- worker.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('legacy-reader','legacy-reader-lease',30,10)`).Scan(&result)
	}()
	settled := false
	defer func() {
		tx.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("legacy claim did not join after releasing barrier")
			}
		}
	}()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := admin.QueryRow(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, worker.PgConn().PID(), barrier.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("old claim did not enter its predecessor body before migration")
	}
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal("upgrade with old body suspended", err)
	}
	scope := fixtureRequestIdentity(t).Scope
	const sensor = "pid_78900001-0000-4000-8000-000000000001"
	seedRuntimeCandidateSensor(t, ctx, admin, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, sensor, "tetragon")
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, sensor, "tetragon", 0)
	if exhausted {
		if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,predecessor_digest,input_digest,state,attempt,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,$5,'correlate',3,'runtime-correlation-v2',$6,$6,'leased',100,'candidate-worker','candidate-lease-token-01',clock_timestamp()+interval '1 hour')`, args[0], args[1], args[2], args[3], args[4], args[9]); err != nil {
			t.Fatal(err)
		}
	}
	// Make it eligible relative to the old transaction's start, not merely to
	// this later fixture insertion. The unfenced control must actually mutate it.
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET available_at=clock_timestamp()-interval '1 hour',lease_expires_at=clock_timestamp()-interval '1 hour' WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
		t.Fatal(err)
	}
	if !fenced {
		// Deliberately remove only the new fence in this disposable negative
		// control. This is not accepted as a healthy release or a product proof.
		if _, err := admin.Exec(ctx, `ALTER TABLE zasp_runtime_stage_work DISABLE TRIGGER zasp_runtime_correlation_claim_version`); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		settled = true
		var provider *pgconn.PgError
		if fenced && (!errors.As(err, &provider) || provider.Code != "42501" || provider.Message != "runtime correlation claim version rejected") {
			t.Fatal("old body wasn't rejected by the version mutation fence", err)
		}
		if !fenced && err != nil {
			t.Fatal("unfenced control did not execute the old body", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var attempt int
	var owner, state, batchState, disposition string
	wantAttempt, wantOwner := 1, "candidate-worker"
	wantState, wantBatchState, wantDisposition := "leased", "processing", "held"
	if !fenced {
		wantAttempt, wantOwner = 2, "legacy-reader"
	}
	if exhausted {
		wantAttempt = 100
		if !fenced {
			wantOwner, wantState, wantBatchState, wantDisposition = "", "failed", "failed", "ack_pending"
		}
	}
	if err := admin.QueryRow(ctx, `SELECT s.attempt,COALESCE(s.lease_owner,''),s.state,b.state,d.disposition FROM zasp_runtime_stage_work s JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_deliveries d USING(organization_id,workspace_id,environment_id,batch_id) WHERE s.batch_id=$1 AND s.stage='correlate'`, args[3]).Scan(&attempt, &owner, &state, &batchState, &disposition); err != nil || attempt != wantAttempt || owner != wantOwner || state != wantState || batchState != wantBatchState || disposition != wantDisposition {
		t.Fatal("in-flight control did not establish the required mutation boundary", attempt, owner, state, batchState, disposition, err)
	}
}

func TestRuntimeCorrelationRoutingCapabilityRestorationAndRecoveryHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	const sensor = "pid_78900001-0000-4000-8000-000000000001"
	seedRuntimeCandidateSensor(t, ctx, admin, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, sensor, "tetragon")
	args := seedRuntimeCandidateBatch(t, ctx, admin, 1, sensor, "tetragon", 0)
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET available_at=clock_timestamp()-interval '1 hour',lease_expires_at=clock_timestamp()-interval '1 hour' WHERE batch_id=$1 AND stage='correlate'`, args[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state) VALUES($1,$2,$3,1,$4,'requested')`, args[:4]...); err != nil {
		t.Fatal(err)
	}
	// First prove that an uncaught failure rolls the local marker back with the
	// transaction, after the helper set it and the existing recovery trigger ran.
	aborted, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aborted.Exec(ctx, `SELECT set_config('zasp.runtime_correlation_claim_version','caller-marker',true)`); err != nil {
		t.Fatal(err)
	}
	_, err = aborted.Exec(ctx, `SELECT zasp_runtime_claim_correlation_v2('upgraded-reader','upgraded-reader-lease',30,10)`)
	var provider *pgconn.PgError
	if !errors.As(err, &provider) || provider.Code != "55000" || provider.Message != "tenant recovery hold active" {
		aborted.Rollback(ctx)
		t.Fatal("expected a post-marker recovery hold refusal", err)
	}
	if err := aborted.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var marker string
	if err := worker.QueryRow(ctx, `SELECT COALESCE(current_setting('zasp.runtime_correlation_claim_version',true),'')`).Scan(&marker); err != nil || marker != "" {
		t.Fatal("aborted claim leaked capability", marker, err)
	}
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT set_config('zasp.runtime_correlation_claim_version','runtime-correlation-v2',true)`); err != nil {
		t.Fatal(err)
	}
	var claimed json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('legacy-reader','legacy-reader-lease',30,10)`).Scan(&claimed); err != nil || string(claimed) != "[]" {
		t.Fatal("caller marker changed legacy selection", string(claimed), err)
	}
	if err := tx.QueryRow(ctx, `SELECT current_setting('zasp.runtime_correlation_claim_version')`).Scan(&marker); err != nil || marker != "runtime-correlation-v2" {
		t.Fatal("legacy helper failed to restore prior marker", marker, err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('zasp.runtime_correlation_claim_version','caller-marker',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DO $test$ BEGIN BEGIN PERFORM zasp_runtime_claim_correlation_v2('upgraded-reader','upgraded-reader-lease',30,10); RAISE EXCEPTION 'held claim unexpectedly succeeded'; EXCEPTION WHEN SQLSTATE '55000' THEN IF SQLERRM<>'tenant recovery hold active' THEN RAISE;END IF;END;END $test$`); err != nil {
		t.Fatal("caller could not catch the expected recovery refusal", err)
	}
	if err := tx.QueryRow(ctx, `SELECT current_setting('zasp.runtime_correlation_claim_version')`).Scan(&marker); err != nil || marker != "caller-marker" {
		t.Fatal("caught claim failure leaked capability", marker, err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_recovery_holds WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, args[:3]...); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT zasp_runtime_claim_correlation_v2('upgraded-reader','upgraded-reader-lease',30,10)`).Scan(&claimed); err != nil {
		t.Fatal("upgraded claim failed after hold release", err)
	}
	var leases []struct {
		Version string `json:"implementation_version"`
		Attempt int    `json:"attempt"`
	}
	if err := json.Unmarshal(claimed, &leases); err != nil || len(leases) != 1 || leases[0].Version != "runtime-correlation-v2" || leases[0].Attempt != 2 {
		t.Fatal("upgraded claim didn't preserve the original v2 job", string(claimed), err)
	}
	if err := tx.QueryRow(ctx, `SELECT current_setting('zasp.runtime_correlation_claim_version')`).Scan(&marker); err != nil || marker != "caller-marker" {
		t.Fatal("successful claim leaked capability", marker, err)
	}
	if err := tx.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('legacy-reader','legacy-reader-lease',30,10)`).Scan(&claimed); err != nil || string(claimed) != "[]" {
		t.Fatal("subsequent legacy claim changed v2 work", string(claimed), err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionRuntimeCorrelationRouting(ctx); err == nil {
		t.Fatal("rollback discarded retained v2 work")
	}
	if version, err := runner.Version(ctx); err != nil || version != 49 {
		t.Fatal("refused rollback changed the release", version, err)
	}
}

func TestRuntimeCorrelationRoutingRejectsNullClaimArguments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	_, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	for _, function := range []string{"zasp_runtime_claim_stage", "zasp_runtime_claim_correlation_v2"} {
		for index, name := range []string{"worker", "token", "duration", "limit"} {
			t.Run(function+"/"+name, func(t *testing.T) {
				args := []any{"routing-reader", "routing-reader-lease", 30, 10}
				args[index] = nil
				var result json.RawMessage
				err := worker.QueryRow(ctx, `SELECT `+function+`($1,$2,$3,$4)`, args...).Scan(&result)
				var provider *pgconn.PgError
				if !errors.As(err, &provider) || provider.Code != "42501" {
					t.Fatal("null claim authority accepted", string(result), err)
				}
			})
		}
	}
}

func TestRuntimeCorrelationRoutingDirectClaimsRejectReleaseDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, runner, worker := runtimeCorrelationRoutingPredecessor(t, ctx)
	if err := runner.UpProductionRuntimeCorrelationRouting(ctx); err != nil {
		t.Fatal(err)
	}
	metadata := migrations.ProductionRuntimeCorrelationRouting()
	for _, drift := range []struct {
		name, change, restore string
		args                  []any
	}{
		{"trigger disabled", `ALTER TABLE zasp_runtime_stage_work DISABLE TRIGGER zasp_runtime_correlation_claim_version`, `ALTER TABLE zasp_runtime_stage_work ENABLE TRIGGER zasp_runtime_correlation_claim_version`, nil},
		{"private helper grant", `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean) FROM PUBLIC`, nil},
		{"upgraded entry grant", `GRANT EXECUTE ON FUNCTION zasp_runtime_claim_correlation_v2(text,text,integer,integer) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION zasp_runtime_claim_correlation_v2(text,text,integer,integer) FROM PUBLIC`, nil},
		{"checksum", `UPDATE zasp_schema_versions SET checksum=repeat('a',64) WHERE version=49`, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=49`, []any{metadata.Checksum()}},
		{"install checksum", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_correlation_routing_checksum'`, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_correlation_routing_checksum'`, []any{metadata.Checksum()}},
		{"fingerprint", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_correlation_routing_fingerprint'`, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_correlation_routing_fingerprint'`, []any{migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()}},
		{"future release", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(50,'unexpected_future_release',repeat('a',64))`, `DELETE FROM zasp_schema_versions WHERE version=50`, nil},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, drift.change); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, drift.restore, drift.args...); err != nil {
					t.Error("couldn't restore controlled drift", err)
				}
			}()
			var ready bool
			if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&ready); err == nil && ready {
				t.Fatal("pinned readiness accepted drift")
			}
			for _, function := range []string{"zasp_runtime_claim_stage", "zasp_runtime_claim_correlation_v2"} {
				if _, err := worker.Exec(ctx, `SELECT `+function+`('routing-reader','routing-reader-lease',30,10)`); err == nil {
					t.Error("direct claim accepted drift", function)
				}
			}
		})
	}
	var ready bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_correlation_routing_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("restored routing authority unavailable", err)
	}
	if _, err := worker.Exec(ctx, `SELECT zasp_runtime_claim_stage_compatible('routing-reader','routing-reader-lease',30,10,true)`); err == nil {
		t.Fatal("private helper was directly callable")
	}
	config := admin.Config().Copy()
	config.User = "candidate_archive"
	other, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(context.Background())
	if _, err := other.Exec(ctx, `SELECT zasp_runtime_claim_correlation_v2('routing-reader','routing-reader-lease',30,10)`); err == nil {
		t.Fatal("unrelated stage principal claimed correlation")
	}
}
