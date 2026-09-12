package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func precisionRecoveryIngest(t *testing.T, ctx context.Context, admin *pgx.Conn) *pgx.Conn {
	t.Helper()
	config := admin.Config().Copy()
	config.User = "invocation_ingest"
	ingest, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ingest.Close(context.Background()) })
	return ingest
}

// These are actual authenticated reservations with the upload deliberately left
// incomplete. Tests explicitly seed scheduling, interrupted/terminal state and
// final-attempt rows; claims and durable transitions use registered authority.
func reservePrecisionRecovery(t *testing.T, ctx context.Context, admin *pgx.Conn, schemas ...string) []string {
	t.Helper()
	const token = "pid_78990021-0000-4000-8000-000000000021"
	locator, secret, salt := bytes.Repeat([]byte{0xe1}, 16), bytes.Repeat([]byte{0xe2}, 32), bytes.Repeat([]byte{0xe3}, 32)
	credential, err := sensor.NewTokenCredential(locator, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	locatorHash, _ := credential.LocatorDigest()
	tokenHash, _ := credential.Hash(sensor.SensorTokenAudienceEventIngest, mustProductID(t, token), 1, salt)
	if _, err := admin.Exec(ctx, `SELECT zasp_runtime_issue_sensor_token(organization_id,workspace_id,environment_id,id,$2,1,1,$3,$4,$5,transaction_timestamp()+interval '1 day') FROM zasp_sensors WHERE id=$1`, sandboxAnchor, token, locatorHash[:], salt, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	var batches []string
	for i, schema := range schemas {
		batch := fmt.Sprintf("pid_78990022-0000-4000-8000-%012d", i+1)
		var body []byte
		if err := admin.QueryRow(ctx, `SELECT zasp_runtime_reserve_batch($1,$2,'event-ingest',$3,$4,$5,'tetragon','application/json',$6,1,1)`, locator, secret, batch, fmt.Sprintf("precision-recovery-%04d", i), bytes.Repeat([]byte{0xe4}, 32), schema).Scan(&body); err != nil {
			t.Fatal("reserve", err)
		}
		batches = append(batches, batch)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET available_at=transaction_timestamp()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	return batches
}

func precisionRecoveryState(t *testing.T, ctx context.Context, admin *pgx.Conn, batch string) string {
	t.Helper()
	var state string
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(w)::text FROM zasp_runtime_ingest_reconciliation_work w WHERE batch_id=$1`, batch).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestRuntimePrecisionReconciliationOldClaimLeavesV2Untouched(t *testing.T) {
	for _, state := range []string{"pending", "expired", "observed"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			ingest := precisionRecoveryIngest(t, ctx, admin)
			batches := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2", "runtime-event-v1")
			if state == "expired" {
				if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_runtime_ingest_reconciliation_work WHERE batch_id=$1 RETURNING *) INSERT INTO zasp_runtime_ingest_reconciliation_work SELECT (jsonb_populate_record(NULL::zasp_runtime_ingest_reconciliation_work,to_jsonb(removed)||jsonb_build_object('state','leased','attempt',100,'lease_owner','old-worker','lease_token','old-worker-lease-01','lease_expires_at',transaction_timestamp()-interval '1 hour'))).* FROM removed`, batches[0]); err != nil {
					t.Fatal(err)
				}
			}
			if state == "observed" {
				if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_batch_authorities SET state='quarantined',completion_result='{"state":"quarantined"}',completion_digest=decode(repeat('11',32),'hex'),completed_at=transaction_timestamp() WHERE batch_id=$1`, batches[0]); err != nil {
					t.Fatal(err)
				}
			}
			before := precisionRecoveryState(t, ctx, admin, batches[0])
			var body []byte
			if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation('old-worker','old-worker-lease-01',60,10)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var claims []struct {
				Batch string `json:"batch_id"`
			}
			if err := json.Unmarshal(body, &claims); err != nil {
				t.Fatal(err)
			}
			if len(claims) != 1 || claims[0].Batch != batches[1] || precisionRecoveryState(t, ctx, admin, batches[0]) != before {
				t.Fatal("old consumer claimed or mutated V2", string(body))
			}
			if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('new-worker','new-worker-lease-01',60,10)`).Scan(&body); err != nil {
				t.Fatal("precise recovery", err)
			}
			var actual string
			if err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_ingest_reconciliation_work WHERE batch_id=$1`, batches[0]).Scan(&actual); err != nil || actual != map[string]string{"pending": "leased", "expired": "exhausted", "observed": "succeeded"}[state] {
				t.Fatal("precise recovery branch", actual, err)
			}
		})
	}
}

func TestRuntimePrecisionReconciliationCachedOldClaimRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	batches := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2")
	before := precisionRecoveryState(t, ctx, admin, batches[0])
	var body []byte
	err := admin.QueryRow(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET state='leased',attempt=attempt+1,lease_owner='cached-worker',lease_token='cached-worker-lease-01',lease_expires_at=transaction_timestamp()+interval '1 minute' RETURNING to_jsonb(zasp_runtime_ingest_reconciliation_work)`).Scan(&body)
	requireSandboxSQLState(t, err, "42501")
	if precisionRecoveryState(t, ctx, admin, batches[0]) != before {
		t.Fatal("cached body changed V2 recovery")
	}
}

func TestRuntimePrecisionReconciliationV2FinishesPersistedTuple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	batches := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v1", "runtime-event-v2")
	if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_runtime_ingest_reconciliation_work RETURNING *) INSERT INTO zasp_runtime_ingest_reconciliation_work SELECT (jsonb_populate_record(NULL::zasp_runtime_ingest_reconciliation_work,to_jsonb(removed)||jsonb_build_object('attempt',99))).* FROM removed; UPDATE zasp_runtime_batch_authorities SET state='unknown'`); err != nil {
		t.Fatal(err)
	}
	var body []byte
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('precise-worker','precise-worker-lease-01',60,10)`).Scan(&body); err != nil {
		t.Fatal("versioned claim", err)
	}
	var claims []struct {
		Batch   string `json:"batch_id"`
		Attempt int    `json:"attempt"`
		Schema  string `json:"schema_version"`
	}
	if err := json.Unmarshal(body, &claims); err != nil || len(claims) != 2 || claims[0].Attempt != 100 || claims[1].Attempt != 100 || claims[0].Schema != "runtime-event-v1" || claims[1].Schema != "runtime-event-v2" {
		t.Fatal("mixed final-attempt claims", string(body), err)
	}
	for i, batch := range batches {
		var org, workspace, env, key string
		var generation, size int64
		var digest []byte
		if err := admin.QueryRow(ctx, `SELECT organization_id,workspace_id,environment_id,batch_generation,raw_artifact_key,content_digest,payload_size_bytes FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batch).Scan(&org, &workspace, &env, &generation, &key, &digest, &size); err != nil {
			t.Fatal(err)
		}
		query := `SELECT zasp_runtime_finish_reconciliation($1,$2,$3,$4,$5,'precise-worker','precise-worker-lease-01',$6,$7,$8,$9,'recovery-version-1',$10,$11,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh')`
		args := []any{org, workspace, env, batch, generation, fmt.Sprintf("pid_78990050-0000-4000-8000-%012d", i+1), fmt.Sprintf("pid_78990051-0000-4000-8000-%012d", i+1), "s3://zasp-evidence/" + key, key, digest, size}
		if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
			t.Fatal("finish", err)
		}
		var versions []string
		if err := admin.QueryRow(ctx, `SELECT array_agg(implementation_version ORDER BY stage_order) FROM zasp_runtime_stage_work WHERE batch_id=$1`, batch).Scan(&versions); err != nil {
			t.Fatal(err)
		}
		want := []string{"runtime-archive-v1", "runtime-index-v1", "runtime-correlation-v2", "runtime-projection-v1", "runtime-complete-v1"}
		if i == 1 {
			want = []string{"runtime-archive-v2", "runtime-index-v2", "runtime-correlation-v4", "runtime-projection-v3", "runtime-complete-v3"}
		}
		if fmt.Sprint(versions) != fmt.Sprint(want) {
			t.Fatal("persisted tuple", versions)
		}
		before := precisionRecoveryState(t, ctx, admin, batch)
		if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil || !bytes.Contains(body, []byte(`"replayed": true`)) || precisionRecoveryState(t, ctx, admin, batch) != before {
			t.Fatal("finish replay", string(body), err)
		}
	}
}

func TestRuntimePrecisionReconciliationTransitionsAndDrift(t *testing.T) {
	for _, transition := range []string{"release", "quarantine", "finish"} {
		t.Run(transition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			ingest := precisionRecoveryIngest(t, ctx, admin)
			batch := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2")[0]
			if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_runtime_ingest_reconciliation_work RETURNING *) INSERT INTO zasp_runtime_ingest_reconciliation_work SELECT (jsonb_populate_record(NULL::zasp_runtime_ingest_reconciliation_work,to_jsonb(removed)||jsonb_build_object('attempt',99))).* FROM removed`); err != nil {
				t.Fatal(err)
			}
			var body []byte
			if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('precise-worker','precise-worker-lease-01',60,10)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			identity := fixtureRequestIdentity(t).Scope
			args := []any{identity.OrganizationID().String(), identity.WorkspaceID().String(), identity.EnvironmentID().String(), batch}
			query := `SELECT zasp_runtime_release_reconciliation($1,$2,$3,$4,1,'precise-worker','precise-worker-lease-01',5,'outcome_unknown')`
			if transition == "quarantine" {
				query = `SELECT zasp_runtime_quarantine_reconciliation($1,$2,$3,$4,1,'precise-worker','precise-worker-lease-01')`
			}
			if transition == "finish" {
				var key string
				if err := admin.QueryRow(ctx, `SELECT raw_artifact_key FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batch).Scan(&key); err != nil {
					t.Fatal(err)
				}
				args = append(args, "s3://zasp-evidence/"+key, key, bytes.Repeat([]byte{0xe4}, 32))
				query = `SELECT zasp_runtime_finish_reconciliation($1,$2,$3,$4,1,'precise-worker','precise-worker-lease-01','pid_78990050-0000-4000-8000-000000000001','pid_78990051-0000-4000-8000-000000000001',$5,$6,'recovery-version-1',$7,1,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh')`
			}
			before := precisionRecoveryState(t, ctx, admin, batch)
			var pin string
			if err := admin.QueryRow(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint' RETURNING (SELECT zasp_production_runtime_precision_live_fingerprint())`).Scan(&pin); err != nil {
				t.Fatal(err)
			}
			err := ingest.QueryRow(ctx, query, args...).Scan(&body)
			requireSandboxSQLState(t, err, "55000")
			err = ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('precise-worker','precise-worker-lease-01',60,10)`).Scan(&body)
			requireSandboxSQLState(t, err, "55000")
			if before != precisionRecoveryState(t, ctx, admin, batch) {
				t.Fatal("drift changed recovery work")
			}
			if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_precision_fingerprint'`, pin); err != nil {
				t.Fatal(err)
			}
			if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
				t.Fatal("live final-attempt transition", err)
			}
			var state string
			var attempt int
			if err := admin.QueryRow(ctx, `SELECT state,attempt FROM zasp_runtime_ingest_reconciliation_work WHERE batch_id=$1`, batch).Scan(&state, &attempt); err != nil || attempt != 100 || state != map[string]string{"release": "exhausted", "quarantine": "quarantined", "finish": "succeeded"}[transition] {
				t.Fatal(state, attempt, err)
			}
		})
	}
}

func TestRuntimePrecisionReconciliationPostWaitDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	batch := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2")[0]
	var body []byte
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('precise-worker','precise-worker-lease-01',60,1)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	before := precisionRecoveryState(t, ctx, admin, batch)
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	scope := fixtureRequestIdentity(t).Scope
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch}
	err = blockedRuntimeCandidateStatement(t, ctx, admin, ingest, observer, args, `SELECT zasp_runtime_release_reconciliation($1,$2,$3,$4,1,'precise-worker','precise-worker-lease-01',5,'outcome_unknown')`, `SELECT 1 FROM zasp_runtime_ingest_reconciliation_work WHERE batch_id=$1 FOR UPDATE`, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
			t.Fatal(err)
		}
	})
	requireSandboxSQLState(t, err, "55000")
	if before != precisionRecoveryState(t, ctx, admin, batch) {
		t.Fatal("post-wait drift changed recovery lease")
	}
}

func TestRuntimePrecisionReconciliationCachedExhaustionAndObservation(t *testing.T) {
	for _, state := range []string{"expired", "observed"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			batch := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2")[0]
			query := `UPDATE zasp_runtime_ingest_reconciliation_work SET state='succeeded',completion_worker='observed',completion_token_digest=decode(repeat('11',32),'hex'),completion_digest=decode(repeat('11',32),'hex'),completion_result='{}',completed_at=transaction_timestamp() WHERE batch_id=$1`
			if state == "expired" {
				if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_runtime_ingest_reconciliation_work RETURNING *) INSERT INTO zasp_runtime_ingest_reconciliation_work SELECT (jsonb_populate_record(NULL::zasp_runtime_ingest_reconciliation_work,to_jsonb(removed)||jsonb_build_object('state','leased','attempt',100,'lease_owner','old-worker','lease_token','old-worker-lease-01','lease_expires_at',transaction_timestamp()-interval '1 hour'))).* FROM removed`); err != nil {
					t.Fatal(err)
				}
				query = `UPDATE zasp_runtime_ingest_reconciliation_work SET state='exhausted',last_error_code='exhausted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE batch_id=$1`
			}
			before := precisionRecoveryState(t, ctx, admin, batch)
			_, err := admin.Exec(ctx, query, batch)
			requireSandboxSQLState(t, err, "42501")
			if before != precisionRecoveryState(t, ctx, admin, batch) {
				t.Fatal("cached old cleanup changed V2")
			}
		})
	}
}

func TestRuntimePrecisionReconciliationRecoveryHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	batch := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2")[0]
	before := precisionRecoveryState(t, ctx, admin, batch)
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state) SELECT organization_id,workspace_id,environment_id,1,batch_id,'requested' FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batch); err != nil {
		t.Fatal(err)
	}
	var body []byte
	err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('new-worker','new-worker-lease-01',60,10)`).Scan(&body)
	requireSandboxSQLState(t, err, "55000")
	if before != precisionRecoveryState(t, ctx, admin, batch) {
		t.Fatal("recovery hold consumed attempt")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='released',released_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('new-worker','new-worker-lease-01',60,10)`).Scan(&body); err != nil || string(body) == "[]" {
		t.Fatal("released hold didn't resume", err)
	}
}

func TestRuntimePrecisionReconciliationExpiredLeaseAllowsAuthenticatedFinalize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	batch := reservePrecisionRecovery(t, ctx, admin, "runtime-event-v2")[0]
	var body []byte
	if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_reconciliation_v2('recovery-worker','recovery-worker-lease-01',60,1)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_ingest_reconciliation_work SET lease_expires_at=transaction_timestamp()-interval '1 minute' WHERE batch_id=$1`, batch); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := admin.QueryRow(ctx, `SELECT raw_artifact_key FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batch).Scan(&key); err != nil {
		t.Fatal(err)
	}
	query := `SELECT zasp_runtime_finalize_batch($1,$2,'event-ingest',$3,'pid_78990050-0000-4000-8000-000000000001','pid_78990051-0000-4000-8000-000000000001',$4,$5,'authenticated-finalize-version',$6,1,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh')`
	args := []any{bytes.Repeat([]byte{0xe1}, 16), bytes.Repeat([]byte{0xe2}, 32), batch, "s3://zasp-evidence/" + key, key, bytes.Repeat([]byte{0xe4}, 32)}
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil {
		t.Fatal("authenticated finalization after expired recovery lease", err)
	}
	var settled bool
	if err := admin.QueryRow(ctx, `SELECT w.state='succeeded' AND w.completion_worker='request' AND b.state='queued' AND (SELECT count(*) FROM zasp_runtime_stage_work s WHERE s.batch_id=b.batch_id)=5 FROM zasp_runtime_ingest_reconciliation_work w JOIN zasp_runtime_batch_authorities b USING(organization_id,workspace_id,environment_id,batch_id) WHERE b.batch_id=$1`, batch).Scan(&settled); err != nil || !settled {
		t.Fatal("request recovery completion", settled, err)
	}
	before := precisionRecoveryState(t, ctx, admin, batch)
	if err := ingest.QueryRow(ctx, query, args...).Scan(&body); err != nil || before != precisionRecoveryState(t, ctx, admin, batch) {
		t.Fatal("authenticated finalize replay", err)
	}
}
