package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func precisionOutboxWorker(t *testing.T, ctx context.Context, admin *pgx.Conn) *pgx.Conn {
	t.Helper()
	config := admin.Config().Copy()
	config.User = "invocation_discovery_outbox"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	return worker
}

// Admission and finalization really produce the outbox. No test grants or
// successful stage/receipt rows are needed to exercise queue publication.
func seedPrecisionOutbox(t *testing.T, ctx context.Context, admin *pgx.Conn, schemas ...string) []string {
	t.Helper()
	batches := reservePrecisionRecovery(t, ctx, admin, schemas...)
	ingest := precisionRecoveryIngest(t, ctx, admin)
	for i, batch := range batches {
		var key string
		if err := admin.QueryRow(ctx, `SELECT raw_artifact_key FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batch).Scan(&key); err != nil {
			t.Fatal(err)
		}
		var body []byte
		if err := ingest.QueryRow(ctx, `SELECT zasp_runtime_finalize_batch($1,$2,'event-ingest',$3,$4,$5,$6,$7,'outbox-proof-version',$8,1,'arn:aws:kms:us-west-2:123456789012:key/abcdefgh')`, bytes.Repeat([]byte{0xe1}, 16), bytes.Repeat([]byte{0xe2}, 32), batch, fmt.Sprintf("pid_78990050-0000-4000-8000-%012d", i+1), fmt.Sprintf("pid_78990051-0000-4000-8000-%012d", i+1), "s3://zasp-evidence/"+key, key, bytes.Repeat([]byte{0xe4}, 32)).Scan(&body); err != nil {
			t.Fatal(err)
		}
	}
	return batches
}

func precisionOutboxState(t *testing.T, ctx context.Context, admin *pgx.Conn, batch string) string {
	t.Helper()
	var body string
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(o)::text FROM zasp_discovery_outbox o WHERE deterministic_key='runtime:'||$1`, batch).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRuntimePrecisionDeliveryOldOutboxLeavesV2(t *testing.T) {
	for _, state := range []string{"pending", "expired", "exhausted", "expired-exhausted"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			worker := precisionOutboxWorker(t, ctx, admin)
			batches := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2", "runtime-event-v1")
			patch := `{}`
			if state == "expired" {
				patch = `{"state":"leased","attempt":1,"lease_owner":"old-worker","lease_token":"old-worker-lease-01","lease_expires_at":"2020-01-01T00:00:00Z"}`
			}
			if state == "exhausted" {
				patch = `{"state":"failed","attempt":100}`
			}
			if state == "expired-exhausted" {
				patch = `{"state":"leased","attempt":100,"lease_owner":"old-worker","lease_token":"old-worker-lease-01","lease_expires_at":"2020-01-01T00:00:00Z"}`
			}
			if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1 RETURNING *) INSERT INTO zasp_discovery_outbox SELECT (jsonb_populate_record(NULL::zasp_discovery_outbox,to_jsonb(removed)||$2::jsonb)).* FROM removed`, batches[0], patch); err != nil {
				t.Fatal(err)
			}
			before := precisionOutboxState(t, ctx, admin, batches[0])
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox('runtime-events','old-worker','old-worker-lease-01',30,10)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var response struct {
				Items []struct {
					Payload struct {
						Batch string `json:"batch_id"`
					} `json:"payload"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &response); err != nil || len(response.Items) != 1 || response.Items[0].Payload.Batch != batches[1] || before != precisionOutboxState(t, ctx, admin, batches[0]) {
				t.Fatal("old publisher changed V2", string(body), err)
			}
			// Finish the old V1 lease so per-organization fairness permits V2.
			var outbox string
			if err := admin.QueryRow(ctx, `SELECT id FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1`, batches[1]).Scan(&outbox); err != nil {
				t.Fatal(err)
			}
			scope := fixtureRequestIdentity(t).Scope
			if _, err := worker.Exec(ctx, `SELECT zasp_runtime_ack_outbox('runtime-events',$1,$2,$3,$4,'old-worker','old-worker-lease-01','sha256:'||repeat('b',64))`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), outbox); err != nil {
				t.Fatal(err)
			}
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-01',30,10)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var expected bool
			if err := admin.QueryRow(ctx, `SELECT CASE WHEN $2 IN('exhausted','expired-exhausted') THEN state='exhausted' AND attempt=100 ELSE state='leased' AND attempt=CASE WHEN $2='expired' THEN 2 ELSE 1 END END FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1`, batches[0], state).Scan(&expected); err != nil || !expected {
				t.Fatal("precise publisher did not recover V2", state, expected, err)
			}
		})
	}
}

func TestRuntimePrecisionDeliveryCachedOutboxMutationRejected(t *testing.T) {
	for _, state := range []string{"pending", "exhausted"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
			query := `UPDATE zasp_discovery_outbox SET state='leased',attempt=attempt+1,lease_owner='cached-worker',lease_token='cached-worker-lease-01',lease_expires_at=transaction_timestamp()+interval '1 minute' WHERE deterministic_key='runtime:'||$1`
			if state == "exhausted" {
				if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_discovery_outbox RETURNING *) INSERT INTO zasp_discovery_outbox SELECT (jsonb_populate_record(NULL::zasp_discovery_outbox,to_jsonb(removed)||'{"state":"failed","attempt":100}'::jsonb)).* FROM removed`); err != nil {
					t.Fatal(err)
				}
				query = `UPDATE zasp_discovery_outbox SET state='exhausted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error='maximum publish attempts exhausted' WHERE deterministic_key='runtime:'||$1`
			}
			before := precisionOutboxState(t, ctx, admin, batch)
			_, err := admin.Exec(ctx, query, batch)
			requireSandboxSQLState(t, err, "42501")
			if before != precisionOutboxState(t, ctx, admin, batch) {
				t.Fatal("cached mutation changed V2 outbox")
			}
		})
	}
}

func TestRuntimePrecisionDeliveryClaimRejectsDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
	coordinator := precisionStageWorker(t, ctx, admin, "complete")
	scope := fixtureRequestIdentity(t).Scope
	var digest []byte
	if err := admin.QueryRow(ctx, `SELECT payload_digest FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1`, batch).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	var body []byte
	err := coordinator.QueryRow(ctx, `SELECT zasp_runtime_claim_delivery($1,$2,$3,$4,1,'precision-message-01',$5,1,'delivery-worker','delivery-worker-lease-01',30,30)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch, digest).Scan(&body)
	requireSandboxSQLState(t, err, "55000")
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_deliveries WHERE batch_id=$1`, batch).Scan(&count); err != nil || count != 0 {
		t.Fatal("drift retained delivery", count, err)
	}
}

func TestRuntimePrecisionDeliveryNewOutboxDrainsBothSchemas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	worker := precisionOutboxWorker(t, ctx, admin)
	batches := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2", "runtime-event-v1")
	if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_discovery_outbox RETURNING *) INSERT INTO zasp_discovery_outbox SELECT (jsonb_populate_record(NULL::zasp_discovery_outbox,to_jsonb(removed)||'{"attempt":99}'::jsonb)).* FROM removed`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_discovery_outbox(organization_id,workspace_id,environment_id,id,topic,deterministic_key,payload_version,payload,payload_digest) SELECT organization_id,workspace_id,environment_id,'pid_78990059-0000-4000-8000-000000000001','discovery-jobs','precision-other-topic',1,'{}'::jsonb,digest('{}','sha256') FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batches[0]); err != nil {
		t.Fatal(err)
	}
	for i, batch := range batches {
		var body []byte
		if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-01',30,10)`).Scan(&body); err != nil {
			t.Fatal(err)
		}
		var response struct {
			Items []struct {
				ID        string `json:"id"`
				Attempt   int    `json:"attempt"`
				Org       string `json:"organization_id"`
				Workspace string `json:"workspace_id"`
				Env       string `json:"environment_id"`
				Payload   struct {
					Batch    string `json:"batch_id"`
					Schema   string `json:"payload_schema_version"`
					Pipeline int    `json:"pipeline_version"`
				} `json:"payload"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &response); err != nil || len(response.Items) != 1 || response.Items[0].Attempt != 100 || response.Items[0].Payload.Batch != batch || response.Items[0].Payload.Pipeline != 15 || response.Items[0].Payload.Schema != []string{"runtime-event-v2", "runtime-event-v1"}[i] {
			t.Fatal("mixed final claim", string(body), err)
		}
		item := response.Items[0]
		if i == 0 {
			var blocked []byte
			before := precisionOutboxState(t, ctx, admin, batches[1])
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox('runtime-events','old-worker','old-worker-lease-01',30,10)`).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			var empty struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(blocked, &empty); err != nil || len(empty.Items) != 0 || before != precisionOutboxState(t, ctx, admin, batches[1]) {
				t.Fatal("mixed claims violated one live lease per organization", string(blocked), err)
			}
		}
		if err := worker.QueryRow(ctx, `SELECT zasp_runtime_heartbeat_outbox('runtime-events','new-worker','new-worker-lease-01',30,1)`).Scan(&body); err != nil {
			t.Fatal("final100 heartbeat", err)
		}
		query := `SELECT zasp_runtime_ack_outbox('runtime-events',$1,$2,$3,$4,'new-worker','new-worker-lease-01','sha256:'||repeat('a',64))`
		args := []any{item.Org, item.Workspace, item.Env, item.ID}
		if err := worker.QueryRow(ctx, query, args...).Scan(&body); err != nil {
			t.Fatal("final100 ack", err)
		}
		before := precisionOutboxState(t, ctx, admin, batch)
		if err := worker.QueryRow(ctx, query, args...).Scan(&body); err != nil || before != precisionOutboxState(t, ctx, admin, batch) {
			t.Fatal("publication replay", err)
		}
	}
	var body []byte
	var untouched bool
	if err := admin.QueryRow(ctx, `SELECT state='pending' AND attempt=0 FROM zasp_discovery_outbox WHERE deterministic_key='precision-other-topic'`).Scan(&untouched); err != nil || !untouched {
		t.Fatal("runtime claim changed discovery work", untouched, err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_execution_claim_outbox('discovery-jobs','discovery-worker','discovery-worker-lease-01',30,10)`).Scan(&body); err != nil {
		t.Fatal("unchanged discovery claim", err)
	}
	var discovery struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil || len(discovery.Items) != 1 {
		t.Fatal("discovery claim did not retain its topic", string(body), err)
	}
	err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('discovery-jobs','new-worker','new-worker-lease-01',30,10)`).Scan(&body)
	requireSandboxSQLState(t, err, "22023")
	ingest := precisionRecoveryIngest(t, ctx, admin)
	err = ingest.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-01',30,10)`).Scan(&body)
	requireSandboxSQLState(t, err, "42501")
}

func TestRuntimePrecisionDeliveryOutboxMutationsPostWaitDrift(t *testing.T) {
	for _, operation := range []string{"heartbeat", "ack", "retry"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			worker := precisionOutboxWorker(t, ctx, admin)
			batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
			var body []byte
			if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-01',30,10)`).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var outbox string
			if err := admin.QueryRow(ctx, `SELECT id FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1`, batch).Scan(&outbox); err != nil {
				t.Fatal(err)
			}
			scope := fixtureRequestIdentity(t).Scope
			args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), outbox}
			query := `SELECT zasp_runtime_ack_outbox('runtime-events',$1,$2,$3,$4,'new-worker','new-worker-lease-01','sha256:'||repeat('b',64))`
			if operation == "retry" {
				query = `SELECT zasp_runtime_retry_outbox('runtime-events',$1,$2,$3,$4,'new-worker','new-worker-lease-01',1,'queue_publish_unknown')`
			}
			if operation == "heartbeat" {
				query = `SELECT zasp_runtime_heartbeat_outbox('runtime-events','new-worker','new-worker-lease-01',30,1) WHERE length($1::text||$2::text||$3::text||$4::text)>0`
			}
			before := precisionOutboxState(t, ctx, admin, batch)
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, args, query, `SELECT 1 FROM zasp_discovery_outbox WHERE id=$1 FOR UPDATE`, func(tx pgx.Tx) {
				if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
					t.Fatal(err)
				}
			})
			requireSandboxSQLState(t, err, "55000")
			if before != precisionOutboxState(t, ctx, admin, batch) {
				t.Fatal("postwait drift mutated publication", operation)
			}
		})
	}
}

func TestRuntimePrecisionDeliveryOutboxPostWaitDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	worker := precisionOutboxWorker(t, ctx, admin)
	batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
	before := precisionOutboxState(t, ctx, admin, batch)
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, []any{"runtime-events", "new-worker", "new-worker-lease-01", 30, 10}, `SELECT zasp_runtime_claim_outbox_v2($1,$2,$3,$4,$5)`, `SELECT pg_advisory_xact_lock(hashtextextended('zasp_runtime_outbox:runtime-events',0)) WHERE $1::integer=30`, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
			t.Fatal(err)
		}
	})
	requireSandboxSQLState(t, err, "55000")
	if before != precisionOutboxState(t, ctx, admin, batch) {
		t.Fatal("postwait drift consumed outbox")
	}
}

func precisionDeliveryArgs(t *testing.T, ctx context.Context, admin *pgx.Conn, batch string) []any {
	t.Helper()
	scope := fixtureRequestIdentity(t).Scope
	var digest []byte
	if err := admin.QueryRow(ctx, `SELECT payload_digest FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1`, batch).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	return []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batch, int64(1), "precision-message-01", digest, "delivery-worker", "delivery-worker-lease-01"}
}

const precisionDeliveryClaimSQL = `SELECT zasp_runtime_claim_delivery($1,$2,$3,$4,$5,$6,$7,1,$8,$9,30,30)`

func TestRuntimePrecisionDeliverySharedTransitionsAndPostWaitDrift(t *testing.T) {
	for _, operation := range []string{"claim", "heartbeat", "release", "ack"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			coordinator := precisionStageWorker(t, ctx, admin, "complete")
			batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
			args := precisionDeliveryArgs(t, ctx, admin, batch)
			var body []byte
			if operation != "claim" {
				if err := coordinator.QueryRow(ctx, precisionDeliveryClaimSQL, args...).Scan(&body); err != nil {
					t.Fatal(err)
				}
			}
			query := precisionDeliveryClaimSQL
			lock := `SELECT 1 FROM zasp_runtime_batch_authorities WHERE batch_id=$1 FOR UPDATE`
			if operation == "heartbeat" {
				query = `SELECT zasp_runtime_heartbeat_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,30,30)`
			}
			if operation == "release" {
				query = `SELECT zasp_runtime_release_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,'retryable','retryable')`
			}
			if operation == "ack" {
				if err := coordinator.QueryRow(ctx, `SELECT zasp_runtime_release_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,'quarantined','malformed')`, args...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				if err := coordinator.QueryRow(ctx, precisionDeliveryClaimSQL, args...).Scan(&body); err != nil {
					t.Fatal(err)
				}
				query = `SELECT zasp_runtime_ack_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,decode(repeat('a',64),'hex'))`
			}
			if operation != "claim" {
				lock = `SELECT 1 FROM zasp_runtime_deliveries WHERE batch_id=$1 FOR UPDATE`
			}
			snapshot := func() string {
				var s string
				if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('batch',to_jsonb(b),'delivery',(SELECT to_jsonb(d) FROM zasp_runtime_deliveries d WHERE d.batch_id=b.batch_id))::text FROM zasp_runtime_batch_authorities b WHERE b.batch_id=$1`, batch).Scan(&s); err != nil {
					t.Fatal(err)
				}
				return s
			}
			before := snapshot()
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			err = blockedRuntimeCandidateStatement(t, ctx, admin, coordinator, observer, args, query, lock, func(tx pgx.Tx) {
				if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
					t.Fatal(err)
				}
			})
			requireSandboxSQLState(t, err, "55000")
			if before != snapshot() {
				t.Fatal("postwait drift mutated delivery", operation)
			}
			if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=zasp_production_runtime_precision_live_fingerprint() WHERE key='production_runtime_precision_fingerprint'`); err != nil {
				t.Fatal(err)
			}
			if err := coordinator.QueryRow(ctx, query, args...).Scan(&body); err != nil {
				t.Fatal("healthy shared transition", operation, err)
			}
		})
	}
}

func TestRuntimePrecisionDeliveryOutboxDriftHoldAndFinalRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	worker := precisionOutboxWorker(t, ctx, admin)
	batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
	if _, err := admin.Exec(ctx, `WITH removed AS (DELETE FROM zasp_discovery_outbox RETURNING *) INSERT INTO zasp_discovery_outbox SELECT (jsonb_populate_record(NULL::zasp_discovery_outbox,to_jsonb(removed)||'{"attempt":99}'::jsonb)).* FROM removed`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state) SELECT organization_id,workspace_id,environment_id,1,batch_id,'requested' FROM zasp_runtime_batch_authorities WHERE batch_id=$1`, batch); err != nil {
		t.Fatal(err)
	}
	before := precisionOutboxState(t, ctx, admin, batch)
	var body []byte
	err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-01',30,10)`).Scan(&body)
	requireSandboxSQLState(t, err, "55000")
	if before != precisionOutboxState(t, ctx, admin, batch) {
		t.Fatal("hold consumed outbox attempt")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='released',released_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-01',30,10)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	scope := fixtureRequestIdentity(t).Scope
	var outbox string
	if err := admin.QueryRow(ctx, `SELECT id FROM zasp_discovery_outbox WHERE deterministic_key='runtime:'||$1`, batch).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), outbox}
	queries := []string{`SELECT zasp_runtime_heartbeat_outbox('runtime-events','new-worker','new-worker-lease-01',30,1)`, `SELECT zasp_runtime_ack_outbox('runtime-events',$1,$2,$3,$4,'new-worker','new-worker-lease-01','sha256:'||repeat('b',64))`, `SELECT zasp_runtime_retry_outbox('runtime-events',$1,$2,$3,$4,'new-worker','new-worker-lease-01',1,'queue_publish_unknown')`}
	before = precisionOutboxState(t, ctx, admin, batch)
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	for i, query := range queries {
		queryArgs := args
		if i == 0 {
			queryArgs = nil
		}
		err := worker.QueryRow(ctx, query, queryArgs...).Scan(&body)
		requireSandboxSQLState(t, err, "55000")
	}
	_, err = admin.Exec(ctx, `UPDATE zasp_discovery_outbox SET lease_expires_at=transaction_timestamp()+interval '2 minutes' WHERE deterministic_key='runtime:'||$1`, batch)
	requireSandboxSQLState(t, err, "55000")
	if before != precisionOutboxState(t, ctx, admin, batch) {
		t.Fatal("drift mutated live publication")
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=zasp_production_runtime_precision_live_fingerprint() WHERE key='production_runtime_precision_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, queries[2], args...).Scan(&body); err != nil {
		t.Fatal("live final100 retry", err)
	}
	var failed bool
	if err := admin.QueryRow(ctx, `SELECT state='failed' AND attempt=100 FROM zasp_discovery_outbox WHERE id=$1`, outbox).Scan(&failed); err != nil || !failed {
		t.Fatal("final retry", failed, err)
	}
	before = precisionOutboxState(t, ctx, admin, batch)
	if err := worker.QueryRow(ctx, queries[2], args...).Scan(&body); err != nil || before != precisionOutboxState(t, ctx, admin, batch) {
		t.Fatal("final retry replay changed evidence", err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox('runtime-events','old-worker','old-worker-lease-01',30,10)`).Scan(&body); err != nil || before != precisionOutboxState(t, ctx, admin, batch) {
		t.Fatal("old claim exhausted V2 final retry", err)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_runtime_claim_outbox_v2('runtime-events','new-worker','new-worker-lease-02',30,10)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var exhausted bool
	if err := admin.QueryRow(ctx, `SELECT state='exhausted' AND attempt=100 FROM zasp_discovery_outbox WHERE id=$1`, outbox).Scan(&exhausted); err != nil || !exhausted {
		t.Fatal("precise claim did not exhaust final retry", exhausted, err)
	}
}

func TestRuntimePrecisionDeliveryCachedTransportDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	coordinator := precisionStageWorker(t, ctx, admin, "complete")
	batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
	args := precisionDeliveryArgs(t, ctx, admin, batch)
	var body []byte
	if err := coordinator.QueryRow(ctx, precisionDeliveryClaimSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_precision_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`UPDATE zasp_runtime_deliveries SET lease_expires_at=transaction_timestamp()+interval '1 minute' WHERE batch_id=$1`, `UPDATE zasp_runtime_batch_authorities SET state='quarantined',completed_at=transaction_timestamp(),completion_digest=decode(repeat('a',64),'hex'),completion_result='{"state":"quarantined","error_class":"malformed"}' WHERE batch_id=$1`} {
		_, err := admin.Exec(ctx, query, batch)
		requireSandboxSQLState(t, err, "55000")
	}
}
