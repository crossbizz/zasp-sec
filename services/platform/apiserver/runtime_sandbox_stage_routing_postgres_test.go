package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func sandboxStageWorker(t *testing.T, ctx context.Context, admin *pgx.Conn, stage string) *pgx.Conn {
	t.Helper()
	config := admin.Config().Copy()
	config.User = "candidate_projection"
	if stage == "complete" {
		config.User = "candidate_coordinator"
	}
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	return worker
}

func TestRuntimeSandboxStageRoutingRestoresMarkerInTransaction(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			worker := sandboxStageWorker(t, ctx, admin, stage)
			function, version := "zasp_runtime_claim_projection_v2", "runtime-projection-v2"
			if stage == "complete" {
				function, version = "zasp_runtime_claim_completion_v2", "runtime-complete-v2"
			}
			seedSandboxStageClaim(t, ctx, admin, stage, version, "pending")
			for _, marker := range []string{"", "outer-caller-marker"} {
				t.Run(marker, func(t *testing.T) {
					tx, err := worker.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(context.Background())
					if _, err := tx.Exec(ctx, `SELECT set_config('zasp.runtime_session_claim_version',$1,true)`, marker); err != nil {
						t.Fatal(err)
					}
					// The nested call must claim the pending job before its caller raises
					// a caught exception. The following successful call proves rollback.
					if _, err := tx.Exec(ctx, `DO $caught$ BEGIN BEGIN IF jsonb_array_length(`+function+`('nested-worker','nested-worker-lease',60,10))<>1 THEN RAISE EXCEPTION 'missing nested lease'; END IF; RAISE EXCEPTION USING ERRCODE='22023'; EXCEPTION WHEN SQLSTATE '22023' THEN NULL; END; END $caught$`); err != nil {
						t.Fatal(err)
					}
					var after string
					if err := tx.QueryRow(ctx, `SELECT current_setting('zasp.runtime_session_claim_version',true)`).Scan(&after); err != nil || after != marker {
						t.Fatal("caught caller exception changed outer marker", after, err)
					}
					var body json.RawMessage
					if err := tx.QueryRow(ctx, `SELECT `+function+`('marker-worker','marker-worker-lease',60,10)`).Scan(&body); err != nil || string(body) == "[]" {
						t.Fatal("successful claim missing", string(body), err)
					}
					if err := tx.QueryRow(ctx, `SELECT current_setting('zasp.runtime_session_claim_version',true)`).Scan(&after); err != nil || after != marker {
						t.Fatal("successful claim changed caller marker before commit", after, err)
					}
				})
			}
		})
	}
}

func TestRuntimeSandboxStageRoutingFinalAttemptCompletion(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		for _, outcome := range []string{"retryable", "failed"} {
			t.Run(stage+"/"+outcome, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, _ := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				worker := sandboxStageWorker(t, ctx, admin, stage)
				version, function := "runtime-projection-v2", "zasp_runtime_claim_projection_v2"
				if stage == "complete" {
					version, function = "runtime-complete-v2", "zasp_runtime_claim_completion_v2"
				}
				args := seedSandboxStageClaim(t, ctx, admin, stage, version, "final attempt")
				for _, query := range []string{
					`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version) SELECT organization_id,workspace_id,environment_id,batch_id,sensor_id,idempotency_key,content_digest,event_count,raw_artifact_reference,payload_size_bytes,payload_media_type,payload_schema_version FROM zasp_runtime_batch_authorities WHERE batch_id=$1`,
					`INSERT INTO zasp_discovery_jobs(organization_id,workspace_id,environment_id,id,kind,authority_id,idempotency_key,request_digest) SELECT organization_id,workspace_id,environment_id,batch_id,'runtime',batch_id,idempotency_key,request_digest FROM zasp_runtime_batch_authorities WHERE batch_id=$1`,
				} {
					if _, err := admin.Exec(ctx, query, args[3]); err != nil {
						t.Fatal(err)
					}
				}
				var claim json.RawMessage
				if err := worker.QueryRow(ctx, `SELECT `+function+`('final-worker','final-worker-lease',60,1)`).Scan(&claim); err != nil {
					t.Fatal(err)
				}
				var result, replay json.RawMessage
				errorClass, retrySeconds := "malformed", 0
				if outcome == "retryable" {
					errorClass, retrySeconds = "retryable", 1
				}
				finishArgs := []any{args[0], args[1], args[2], args[3], args[4], "final-worker", "final-worker-lease", 100, args[9], version, outcome, nil, nil, nil, nil, errorClass, retrySeconds}
				finishSQL := `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
				if err := worker.QueryRow(ctx, finishSQL, finishArgs...).Scan(&result); err != nil {
					t.Fatal("live-owner final completion rejected", err)
				}
				var terminal bool
				if err := admin.QueryRow(ctx, `SELECT s.state='failed' AND s.last_error_class='exhausted' AND s.attempt=100 AND s.lease_owner IS NULL AND s.completed_at IS NOT NULL AND s.completion_digest=b.completion_digest AND s.completion_digest=j.completion_digest AND s.completion_result=$3::jsonb AND b.state='failed' AND l.state='failed' AND j.state='failed' AND d.disposition='ack_pending' FROM zasp_runtime_stage_work s JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_deliveries d USING(organization_id,workspace_id,environment_id,batch_id) JOIN zasp_runtime_batches l ON l.id=s.batch_id JOIN zasp_discovery_jobs j ON j.authority_id=s.batch_id AND j.kind='runtime' WHERE s.batch_id=$1 AND s.stage=$2`, args[3], stage, result).Scan(&terminal); err != nil || !terminal {
					t.Fatal("terminal cascades or receipt missing", terminal, err, string(result))
				}
				if err := worker.QueryRow(ctx, finishSQL, finishArgs...).Scan(&replay); err != nil || string(replay) != string(result) {
					t.Fatal("terminal replay changed", string(replay), err)
				}
			})
		}
	}

}

func TestRuntimeSandboxStageRoutingRejectsDriftAfterWait(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		for _, lock := range []string{"advisory", "exhaustion-row"} {
			t.Run(stage+"/"+lock, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, _ := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				worker := sandboxStageWorker(t, ctx, admin, stage)
				observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer observer.Close(context.Background())
				function, version := "zasp_runtime_claim_projection_v2", "runtime-projection-v2"
				if stage == "complete" {
					function, version = "zasp_runtime_claim_completion_v2", "runtime-complete-v2"
				}
				state := "pending"
				lockSQL := `SELECT pg_advisory_xact_lock(hashtextextended('zasp-runtime-stage-claim:` + stage + `',0)) WHERE $1::text IS NOT NULL`
				if lock == "exhaustion-row" {
					state = "exhausted"
					lockSQL = `SELECT 1 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage='` + stage + `' FOR UPDATE`
				}
				args := seedSandboxStageClaim(t, ctx, admin, stage, version, state)
				before := sandboxStageState(t, ctx, admin)
				claimArgs := []any{"waiting-worker", "waiting-worker-lease", 60, args[3]}
				err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, claimArgs, `SELECT `+function+`($1,$2,$3,10) WHERE $4::text IS NOT NULL`, lockSQL, func(tx pgx.Tx) {
					if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`); err != nil {
						t.Fatal(err)
					}
				})
				requireSandboxSQLState(t, err, "55000")
				if after := sandboxStageState(t, ctx, admin); after != before {
					t.Fatal("post-wait drift changed stage, fairness, authority or delivery")
				}
			})
		}
	}
}

func seedSandboxStageClaim(t *testing.T, ctx context.Context, admin *pgx.Conn, stage, version, state string) []any {
	t.Helper()
	return seedSandboxStageClaimNumber(t, ctx, admin, stage, version, state, 1)
}

func seedSandboxStageClaimNumber(t *testing.T, ctx context.Context, admin *pgx.Conn, stage, version, state string, ordinal int) []any {
	t.Helper()
	args := seedRuntimeCandidateBatchVersion(t, ctx, admin, ordinal, sandboxAnchor, "tetragon", 0, 1, "runtime-correlation-v2", nil)
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_stage_work SET state='succeeded',effect_digest=$2,result_reference='s3://zasp-evidence/correlation.json',result_version_id='correlation-v1',result_digest=$2,completed_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1 AND stage='correlate'`, args[3], args[9]); err != nil {
		t.Fatal(err)
	}
	order := 4
	if stage == "complete" {
		order = 5
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,predecessor_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) VALUES($1,$2,$3,$4,$5,'project',4,'runtime-projection-v1',$6,$6,'succeeded',1,$6,'s3://zasp-evidence/projected.json','projection-v1',$6,clock_timestamp())`, args[0], args[1], args[2], args[3], args[4], args[9]); err != nil {
			t.Fatal(err)
		}
	}
	attempt := 1
	if state == "exhausted" {
		attempt = 100
	}
	if state == "final attempt" {
		attempt = 99
	}
	rowState := state
	if state == "exhausted" || state == "final attempt" {
		rowState = "pending"
	}
	if state == "expired leased" {
		rowState = "leased"
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,predecessor_digest,state,attempt,available_at,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,clock_timestamp()-interval '1 hour',CASE WHEN $10='leased' THEN 'prior-worker' END,CASE WHEN $10='leased' THEN 'prior-lease-token-01' END,CASE WHEN $10='leased' THEN clock_timestamp()-interval '1 hour' END)`, args[0], args[1], args[2], args[3], args[4], stage, order, version, args[9], rowState, attempt); err != nil {
		t.Fatal(err)
	}
	return args
}

func sandboxStageState(t *testing.T, ctx context.Context, admin *pgx.Conn) string {
	t.Helper()
	var body string
	if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('work',(SELECT jsonb_agg(to_jsonb(w) ORDER BY batch_id,stage) FROM zasp_runtime_stage_work w),'fairness',(SELECT jsonb_agg(to_jsonb(f) ORDER BY stage,organization_id) FROM zasp_runtime_stage_fairness f),'batch',(SELECT jsonb_agg(to_jsonb(b) ORDER BY batch_id) FROM zasp_runtime_batch_authorities b),'delivery',(SELECT jsonb_agg(to_jsonb(d) ORDER BY batch_id) FROM zasp_runtime_deliveries d))::text`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRuntimeSandboxStageRoutingOldReadersLeaveV2Untouched(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		for _, state := range []string{"pending", "retryable", "expired leased", "exhausted", "final attempt"} {
			t.Run(stage+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, other := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				worker := sandboxStageWorker(t, ctx, admin, stage)
				version, statement := "runtime-projection-v2", `SELECT zasp_runtime_claim_projection_v2('new-worker','new-worker-lease-01',60,10)`
				if stage == "complete" {
					version = "runtime-complete-v2"
					statement = `SELECT zasp_runtime_claim_completion_v2('new-worker','new-worker-lease-01',60,10)`
				}
				args := seedSandboxStageClaim(t, ctx, admin, stage, version, state)
				before := sandboxStageState(t, ctx, admin)
				var body json.RawMessage
				if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('old-worker','old-worker-lease-01',60,10)`).Scan(&body); err != nil {
					t.Fatal(err)
				}
				if string(body) != "[]" || sandboxStageState(t, ctx, admin) != before {
					t.Fatal("legacy reader mutated sandbox stage", string(body))
				}
				requireSandboxSQLState(t, other.QueryRow(ctx, statement).Scan(&body), "42501")
				if err := worker.QueryRow(ctx, statement).Scan(&body); err != nil {
					t.Fatal("v2 claim rejected", err)
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
					var terminal bool
					if err := admin.QueryRow(ctx, `SELECT state='failed' AND last_error_class='exhausted' AND attempt=100 FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`, args[3], stage).Scan(&terminal); err != nil || !terminal || len(leases) != 0 {
						t.Fatal("exhaustion not settled", err, string(body))
					}
				} else {
					want := 2
					if state == "final attempt" {
						want = 100
					}
					if len(leases) != 1 || leases[0].Batch != args[3] || leases[0].Version != version || leases[0].Attempt != want {
						t.Fatal("new claim wrong lease", string(body))
					}
				}
				var marker string
				if err := worker.QueryRow(ctx, `SELECT COALESCE(current_setting('zasp.runtime_session_claim_version',true),'')`).Scan(&marker); err != nil || marker != "" {
					t.Fatal("capability marker leaked", marker, err)
				}
			})
		}
	}
}

// Removing the mutation trigger must let the already-entered v49 body change
// the v2 row. This negative control proves the race is real, not a skipped claim.
func TestRuntimeSandboxStageRoutingFencesAlreadyEnteredLegacyClaim(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		for _, state := range []string{"pending", "exhausted"} {
			for _, fenced := range []bool{false, true} {
				name := "unfenced-control"
				if fenced {
					name = "fenced"
				}
				t.Run(stage+"/"+state+"/"+name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
					defer cancel()
					admin, _ := runtimeSandboxPredecessor(t, ctx)
					worker := sandboxStageWorker(t, ctx, admin, stage)
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
					if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-runtime-stage-claim:'||$1,0))`, stage); err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() {
						var body json.RawMessage
						done <- worker.QueryRow(ctx, `SELECT zasp_runtime_claim_stage('old-worker','old-worker-lease-01',60,10)`).Scan(&body)
					}()
					settled := false
					defer func() {
						tx.Rollback(context.Background())
						if !settled {
							select {
							case <-done:
							case <-time.After(5 * time.Second):
								t.Error("old claim did not join after barrier release")
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
						t.Fatal("old claim did not enter the v49 body")
					}
					installRuntimeSandboxDraft(t, ctx, admin)
					version := "runtime-projection-v2"
					if stage == "complete" {
						version = "runtime-complete-v2"
					}
					args := seedSandboxStageClaim(t, ctx, admin, stage, version, state)
					before := sandboxStageState(t, ctx, admin)
					if !fenced {
						if _, err := admin.Exec(ctx, `ALTER TABLE zasp_runtime_stage_work DISABLE TRIGGER zasp_runtime_session_claim_version`); err != nil {
							t.Fatal(err)
						}
					}
					if err := tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						settled = true
						if fenced {
							requireSandboxSQLState(t, err, "42501")
							if after := sandboxStageState(t, ctx, admin); after != before {
								t.Fatal("fenced call mutated work, fairness, authority or delivery")
							}
							return
						}
						if err != nil {
							t.Fatal("unfenced control did not reach old mutation", err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					var mutated bool
					query := `SELECT state='leased' AND attempt=2 AND lease_owner='old-worker' FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`
					if state == "exhausted" {
						query = `SELECT state='failed' AND attempt=100 AND last_error_class='exhausted' FROM zasp_runtime_stage_work WHERE batch_id=$1 AND stage=$2`
					}
					if err := admin.QueryRow(ctx, query, args[3], stage).Scan(&mutated); err != nil || !mutated {
						t.Fatal("negative control did not demonstrate old mutation", mutated, err)
					}
				})
			}
		}
	}
}

func TestRuntimeSandboxStageRoutingPreservesV1AndSkipsUnknownVersions(t *testing.T) {
	for _, stage := range []string{"project", "complete"} {
		for _, versionSuffix := range []string{"v1", "v3"} {
			t.Run(stage+"/"+versionSuffix, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				admin, _ := runtimeSandboxPredecessor(t, ctx)
				installRuntimeSandboxDraft(t, ctx, admin)
				worker := sandboxStageWorker(t, ctx, admin, stage)
				prefix, statement := "runtime-projection-", `SELECT zasp_runtime_claim_projection_v2('new-worker','new-worker-lease-01',60,10)`
				if stage == "complete" {
					prefix, statement = "runtime-complete-", `SELECT zasp_runtime_claim_completion_v2('new-worker','new-worker-lease-01',60,10)`
				}
				args := seedSandboxStageClaim(t, ctx, admin, stage, prefix+versionSuffix, "pending")
				before := sandboxStageState(t, ctx, admin)
				var body json.RawMessage
				if err := worker.QueryRow(ctx, statement).Scan(&body); err != nil {
					t.Fatal(err)
				}
				if versionSuffix == "v3" {
					if string(body) != "[]" || sandboxStageState(t, ctx, admin) != before {
						t.Fatal("unknown future job version was touched", string(body))
					}
					return
				}
				var leases []struct {
					Version string `json:"implementation_version"`
					Batch   string `json:"batch_id"`
				}
				if err := json.Unmarshal(body, &leases); err != nil || len(leases) != 1 || leases[0].Version != prefix+"v1" || leases[0].Batch != args[3] {
					t.Fatal("new reader rewrote or skipped the historical job", string(body), err)
				}
			})
		}
	}
}
