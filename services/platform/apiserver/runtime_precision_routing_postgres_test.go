package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func precisionStageWorker(t *testing.T, ctx context.Context, admin *pgx.Conn, stage string) *pgx.Conn {
	t.Helper()
	config := admin.Config().Copy()
	config.User = map[string]string{"archive": "candidate_archive", "index": "candidate_index", "correlate": "candidate_correlation", "project": "candidate_projection", "complete": "candidate_coordinator"}[stage]
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	return worker
}

func TestRuntimePrecisionRoutingCachedOldClaimBody(t *testing.T) {
	for _, state := range []string{"pending", "exhausted"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			var definition string
			if err := admin.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_runtime_claim_stage_compatible(text,text,integer,integer,boolean)'::regprocedure)`).Scan(&definition); err != nil {
				t.Fatal(err)
			}
			definition = strings.Replace(definition, "FUNCTION public.zasp_runtime_claim_stage_compatible(", "FUNCTION public.zasp_test_cached_stage(", 1)
			if _, err := admin.Exec(ctx, definition+`; ALTER FUNCTION zasp_test_cached_stage(text,text,integer,integer,boolean) OWNER TO zasp_discovery_authority; REVOKE ALL ON FUNCTION zasp_test_cached_stage(text,text,integer,integer,boolean) FROM PUBLIC; GRANT EXECUTE ON FUNCTION zasp_test_cached_stage(text,text,integer,integer,boolean) TO zasp_runtime_archive_worker`); err != nil {
				t.Fatal(err)
			}
			installRuntimePrecision(t, ctx, admin)
			seedPrecisionStage(t, ctx, admin, "archive", "runtime-archive-v2", state)
			before := sandboxStageState(t, ctx, admin)
			worker := precisionStageWorker(t, ctx, admin, "archive")
			var body []byte
			err := worker.QueryRow(ctx, `SELECT zasp_test_cached_stage('cached-worker','cached-worker-lease',60,10,false)`).Scan(&body)
			requireSandboxSQLState(t, err, "42501")
			if sandboxStageState(t, ctx, admin) != before {
				t.Fatal("cached body changed work, fairness or delivery")
			}
		})
	}
}

func TestRuntimePrecisionRoutingFinalAttemptFinishReplay(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			version, function := "runtime-projection-v3", "zasp_runtime_claim_projection_v3"
			if stage == "complete" {
				version, function = "runtime-complete-v3", "zasp_runtime_claim_completion_v3"
			}
			args := seedPrecisionStage(t, ctx, admin, stage, version, "final attempt")
			worker := precisionStageWorker(t, ctx, admin, stage)
			for _, query := range []string{`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version) SELECT organization_id,workspace_id,environment_id,batch_id,sensor_id,idempotency_key,content_digest,event_count,raw_artifact_reference,payload_size_bytes,payload_media_type,payload_schema_version FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, `INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) SELECT organization_id,workspace_id,environment_id,batch_id,'runtime',batch_id,idempotency_key,request_digest FROM zasp_runtime_batch_authorities WHERE batch_id=$1`} {
				if _, err := admin.Exec(ctx, query, args[3]); err != nil {
					t.Fatal(err)
				}
			}
			var body, replay []byte
			if err := worker.QueryRow(ctx, `SELECT `+function+`('final-worker','final-worker-lease',60,1)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			finish := []any{args[0], args[1], args[2], args[3], args[4], "final-worker", "final-worker-lease", 100, args[9], version, "retryable", nil, nil, nil, nil, "retryable", 1}
			query := `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
			if err := worker.QueryRow(ctx, query, finish...).Scan(&body); err != nil {
				t.Fatal("live final owner", err)
			}
			if err := worker.QueryRow(ctx, query, finish...).Scan(&replay); err != nil || string(body) != string(replay) {
				t.Fatal("terminal replay", err)
			}
			var terminal bool
			if err := admin.QueryRow(ctx, `SELECT s.state='failed' AND s.last_error_class='exhausted' AND s.attempt=100 AND s.completion_digest=b.completion_digest AND s.completion_digest=j.completion_digest AND s.completion_result=$3::jsonb AND b.state='failed' AND l.state='failed' AND j.state='failed' AND d.disposition='ack_pending' FROM zasp_runtime_stage_work s JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_deliveries d USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_batches l ON l.id=s.batch_id JOIN zasp_discovery_jobs j ON j.authority_id=s.batch_id AND j.kind='runtime' WHERE s.batch_id=$1 AND s.stage=$2`, args[3], stage, body).Scan(&terminal); err != nil || !terminal {
				t.Fatal("terminal cascade", err)
			}
		})
	}
}

func seedPrecisionStage(t *testing.T, ctx context.Context, admin *pgx.Conn, stage, version, state string) []any {
	t.Helper()
	if stage == "project" || stage == "complete" {
		return seedSandboxStageClaim(t, ctx, admin, stage, version, state)
	}
	args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v2", nil)
	order := map[string]int{"archive": 1, "index": 2, "correlate": 3}[stage]
	attempt := 1
	rowState := state
	if state == "exhausted" {
		attempt, rowState = 100, "pending"
	}
	if state == "final attempt" {
		attempt, rowState = 99, "pending"
	}
	if state == "expired leased" {
		rowState = "leased"
	}
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage_order>=$2`, args[3], order); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,predecessor_digest,state,attempt,available_at,lease_owner,lease_token,lease_expires_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $7=1 THEN b.content_digest ELSE p.effect_digest END,CASE WHEN $7=1 THEN NULL ELSE p.effect_digest END,$9,$10,clock_timestamp()-interval '1 hour',CASE WHEN $9='leased' THEN 'prior-worker' END,CASE WHEN $9='leased' THEN 'prior-lease-token-01' END,CASE WHEN $9='leased' THEN clock_timestamp()-interval '1 hour' END FROM zasp_runtime_batch_authorities b LEFT JOIN zasp_runtime_stage_work p ON p.batch_id=b.batch_id AND p.stage_order=$7-1 WHERE b.batch_id=$4`, args[0], args[1], args[2], args[3], args[4], stage, order, version, rowState, attempt); err != nil {
		t.Fatal(err)
	}
	return args
}

func TestRuntimePrecisionRoutingArchiveIndexCorrelation(t *testing.T) {
	for _, stage := range []string{"archive", "index", "correlate"} {
		for _, state := range []string{"pending", "retryable", "expired leased", "exhausted", "final attempt"} {
			t.Run(stage+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, _ := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				installRuntimePrecision(t, ctx, admin)
				version, newName := map[string]string{"archive": "runtime-archive-v2", "index": "runtime-index-v2", "correlate": "runtime-correlation-v4"}[stage], map[string]string{"archive": "zasp_runtime_claim_archive_v2", "index": "zasp_runtime_claim_index_v2", "correlate": "zasp_runtime_claim_correlation_v4"}[stage]
				args := seedPrecisionStage(t, ctx, admin, stage, version, state)
				before := sandboxStageState(t, ctx, admin)
				worker := precisionStageWorker(t, ctx, admin, stage)
				var body []byte
				for _, function := range []string{"zasp_runtime_claim_stage", map[string]string{"archive": "zasp_runtime_claim_stage", "index": "zasp_runtime_claim_stage", "correlate": "zasp_runtime_claim_correlation_v3"}[stage]} {
					if err := worker.QueryRow(ctx, `SELECT `+function+`('old-worker','old-worker-lease-01',60,10)`).Scan(&body); err != nil || string(body) != "[]" || sandboxStageState(t, ctx, admin) != before {
						t.Fatal("old claim touched precise stage", string(body), err)
					}
				}
				if err := worker.QueryRow(ctx, `SELECT `+newName+`('new-worker','new-worker-lease-01',60,10)`).Scan(&body); err != nil {
					t.Fatal(err)
				}
				var leases []struct {
					Batch   string `json:"batch_id"`
					Version string `json:"implementation_version"`
					Attempt int    `json:"attempt"`
				}
				if err := json.Unmarshal(body, &leases); err != nil {
					t.Fatal(err)
				}
				if state == "exhausted" {
					var failed bool
					if len(leases) != 0 {
						t.Fatal(string(body))
					}
					if err := admin.QueryRow(ctx, `SELECT state='failed' AND last_error_class='exhausted' FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, args[3], stage).Scan(&failed); err != nil || !failed {
						t.Fatal("missing exhaustion", err)
					}
				} else if len(leases) != 1 || leases[0].Batch != args[3] || leases[0].Version != version || (state == "final attempt" && leases[0].Attempt != 100) {
					t.Fatal("precise lease", string(body))
				}
			})
		}
	}
}

func TestRuntimePrecisionRoutingReadinessAfterLockWait(t *testing.T) {
	for _, lock := range []string{"advisory", "exhaustion-row"} {
		t.Run(lock, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			worker := precisionStageWorker(t, ctx, admin, "project")
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			state, lockSQL := "pending", `SELECT pg_advisory_xact_lock(hashtextextended('zasp-runtime-stage-claim:project',0)) WHERE $1::text IS NOT NULL`
			if lock == "exhaustion-row" {
				state, lockSQL = "exhausted", `SELECT 1 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='project' FOR UPDATE`
			}
			args := seedPrecisionStage(t, ctx, admin, "project", "runtime-projection-v3", state)
			before := sandboxStageState(t, ctx, admin)
			err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, []any{"waiting-worker", "waiting-worker-lease", 60, args[3]}, `SELECT zasp_runtime_claim_projection_v3($1,$2,$3,10) WHERE $4::text IS NOT NULL`, lockSQL, func(tx pgx.Tx) {
				if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
					t.Fatal(err)
				}
			})
			requireSandboxSQLState(t, err, "55000")
			if sandboxStageState(t, ctx, admin) != before {
				t.Fatal("post-wait drift changed rows or fairness")
			}
		})
	}
}

func TestRuntimePrecisionRoutingPersistedSchemaAndCachedProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	for i, schema := range []string{"runtime-event-v1", "runtime-event-v2"} {
		args := seedRuntimeCandidateBatchVersion(t, ctx, admin, i+1, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v2", nil)
		if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_stage_work WHERE batch_id=$1`, args[3]); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_batch_authorities SET state='uploading',payload_schema_version=$2,raw_artifact_reference=NULL,raw_artifact_version_id=NULL,raw_artifact_checksum=NULL,raw_artifact_size_bytes=NULL,raw_artifact_kms_key=NULL,finalized_at=NULL WHERE batch_id=$1`, args[3], schema); err != nil {
			t.Fatal(err)
		}
		if schema == "runtime-event-v2" {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(ctx, `INSERT INTO zasp_runtime_batch_authorities SELECT (jsonb_populate_record(NULL::zasp_runtime_batch_authorities,to_jsonb(b)||jsonb_build_object('batch_id','pid_78900099-0000-4000-8000-000000000099','sensor_id',$2::text,'sensor_token_id',$2::text,'source_kind','otlp','idempotency_key','bad-source-request-01'))).* FROM zasp_runtime_batch_authorities b WHERE batch_id=$1`, args[3], sandboxSemantic)
			requireSandboxSQLState(t, err, "23514")
			_ = tx.Rollback(ctx)
			_, err = admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest) VALUES($1,$2,$3,$4,$5,'archive',1,'runtime-archive-v1',$6)`, args[0], args[1], args[2], args[3], args[4], args[9])
			requireSandboxSQLState(t, err, "22023")
		}
		var body []byte
		if err := admin.QueryRow(ctx, `SELECT zasp_runtime_commit_reserved_batch(organization_id,workspace_id,environment_id,batch_id,batch_generation,request_digest,$2,$3,'s3://zasp-evidence/'||raw_artifact_key,raw_artifact_key,'provider-v1',content_digest,payload_size_bytes,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh') FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, args[3], fmt.Sprintf("pid_78900050-0000-4000-8000-%012d", i+1), fmt.Sprintf("pid_78900051-0000-4000-8000-%012d", i+1)).Scan(&body); err != nil {
			t.Fatal("commit", err)
		}
		var tuple string
		if err := admin.QueryRow(ctx, `SELECT string_agg(implementation_version,',' ORDER BY stage_order) FROM zasp_runtime_stage_work WHERE batch_id=$1`, args[3]).Scan(&tuple); err != nil {
			t.Fatal(err)
		}
		want := "runtime-archive-v1,runtime-index-v1,runtime-correlation-v2,runtime-projection-v1,runtime-complete-v1"
		if schema == "runtime-event-v2" {
			want = "runtime-archive-v2,runtime-index-v2,runtime-correlation-v4,runtime-projection-v3,runtime-complete-v3"
		}
		if tuple != want {
			t.Fatal("persisted schema routing", tuple, want)
		}
	}
}

func TestRuntimePrecisionRoutingCachedReservationRejectsDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v2", nil)
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
		t.Fatal(err)
	}
	_, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_batch_authorities SELECT (jsonb_populate_record(NULL::zasp_runtime_batch_authorities,to_jsonb(b)||jsonb_build_object('batch_id','pid_78900099-0000-4000-8000-000000000099','batch_generation',99,'idempotency_key','cached-precise-reserve-01','payload_schema_version','runtime-event-v2'))).* FROM zasp_runtime_batch_authorities b WHERE batch_id=$1`, args[3])
	requireSandboxSQLState(t, err, "55000")
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_batch_authorities`).Scan(&count); err != nil || count != 1 {
		t.Fatal("drift retained new reservation", count, err)
	}
}

func TestRuntimePrecisionRoutingReservationReadinessAfterSensorLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	args := seedRuntimeCandidateBatchVersion(t, ctx, admin, 1, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v2", nil)
	worker, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, []any{args[3], args[0], args[1], sandboxAnchor}, `INSERT INTO zasp_runtime_batch_authorities SELECT (jsonb_populate_record(NULL::zasp_runtime_batch_authorities,to_jsonb(b)||jsonb_build_object('batch_id','pid_78900099-0000-4000-8000-000000000099','batch_generation',99,'idempotency_key','cached-precise-reserve-01','payload_schema_version','runtime-event-v2'))).* FROM zasp_runtime_batch_authorities b WHERE batch_id=$1 AND $2::text IS NOT NULL AND $3::text IS NOT NULL AND $4::text IS NOT NULL RETURNING to_jsonb(zasp_runtime_batch_authorities)`, `SELECT 1 FROM zasp_sensors WHERE id=$1 FOR UPDATE`, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_checksum'`); err != nil {
			t.Fatal(err)
		}
	})
	requireSandboxSQLState(t, err, "55000")
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_batch_authorities`).Scan(&count); err != nil || count != 1 {
		t.Fatal("post-lock drift retained reservation", count, err)
	}
}
