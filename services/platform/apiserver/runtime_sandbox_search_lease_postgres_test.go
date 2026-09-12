package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type sandboxSearchLease struct {
	Organization string   `json:"organization_id"`
	Workspace    string   `json:"workspace_id"`
	Environment  string   `json:"environment_id"`
	Batch        string   `json:"batch_id"`
	Generation   int64    `json:"generation"`
	Digest       string   `json:"receipt_digest"`
	IDs          []string `json:"document_ids"`
	Attempt      int      `json:"attempt"`
}

func sandboxSearchLeaseFixture(t *testing.T, ctx context.Context) (*pgx.Conn, *pgx.Conn) {
	t.Helper()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	config := admin.Config().Copy()
	config.User = "candidate_index"
	index, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { index.Close(context.Background()) })
	return admin, index
}

func claimSandboxSearch(t *testing.T, ctx context.Context, index *pgx.Conn, worker, token string) sandboxSearchLease {
	t.Helper()
	var body json.RawMessage
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim($1,$2,30)`, worker, token).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var lease sandboxSearchLease
	if err := json.Unmarshal(body, &lease); err != nil || lease.Attempt < 1 || len(lease.IDs) != 3 || len(lease.Digest) != 64 {
		t.Fatal("invalid v2 claim", string(body), err)
	}
	return lease
}

func finishSandboxSearch(ctx context.Context, index *pgx.Conn, lease sandboxSearchLease, worker, token, outcome string, ids []string, delay int) (json.RawMessage, error) {
	var body json.RawMessage
	err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_finish($1,$2,$3,$4,$5,$6,$7,$8,decode($9,'hex'),$10,$11,$12)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, worker, token, lease.Attempt, lease.Digest, outcome, ids, delay).Scan(&body)
	return body, err
}

func TestRuntimeSandboxSearchLeaseTargetAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, index := sandboxSearchLeaseFixture(t, ctx)
	var oldBody json.RawMessage
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_session_search_claim('v1-worker','v1-index-token-0001',30)`).Scan(&oldBody); err != nil {
		t.Fatal(err)
	}
	var old sandboxSearchLease
	if err := json.Unmarshal(oldBody, &old); err != nil || old.Attempt != 1 {
		t.Fatal("invalid old claim", err)
	}
	if _, err := finishSandboxSearch(ctx, index, old, "v1-worker", "v1-index-token-0001", "indexed", old.IDs, 0); err == nil {
		t.Fatal("v1 lease acknowledged v2 progress")
	}
	lease := claimSandboxSearch(t, ctx, index, "v2-worker", "v2-index-token-0001")
	api := sandboxSessionAPI(t, ctx, admin)
	var body json.RawMessage
	err := api.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim('v2-worker','v2-index-token-0002',30)`).Scan(&body)
	requireSandboxSQLState(t, err, "42501")
	for _, fault := range []struct {
		token string
		ids   []string
	}{{"foreign-index-token-1", lease.IDs}, {"v2-index-token-0001", lease.IDs[:2]}} {
		_, err := finishSandboxSearch(ctx, index, lease, "v2-worker", fault.token, "indexed", fault.ids, 0)
		requireSandboxSQLState(t, err, "40001")
	}
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,'v2-worker','v2-index-token-0001',$6,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, lease.Attempt).Scan(&body); err != nil {
		t.Fatal(err)
	}
	first, err := finishSandboxSearch(ctx, index, lease, "v2-worker", "v2-index-token-0001", "indexed", lease.IDs, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := finishSandboxSearch(ctx, index, lease, "v2-worker", "v2-index-token-0001", "indexed", lease.IDs, 0)
	if err != nil || string(first) != string(second) {
		t.Fatal("lost ACK retry changed checkpoint", string(first), string(second), err)
	}
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_session_search_outbox`).Scan(&state); err != nil || state != "leased" {
		t.Fatal("v2 changed v1 progress", state, err)
	}
	if err := rollbackRuntimeSandboxDraft(ctx, admin); err == nil {
		t.Fatal("rollback discarded indexed v2 evidence")
	}
}

func TestRuntimeSandboxSearchLeaseRecoveryHoldAndExhaustion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, index := sandboxSearchLeaseFixture(t, ctx)
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state) SELECT organization_id,workspace_id,environment_id,1,batch_id,'requested' FROM zasp_runtime_sandbox_search_outbox`); err != nil {
		t.Fatal(err)
	}
	var body json.RawMessage
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim('v2-worker','v2-index-token-0001',30)`).Scan(&body); err != nil || len(body) != 0 {
		t.Fatal("held scope claimed", string(body), err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='released',released_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	lease := claimSandboxSearch(t, ctx, index, "v2-worker", "v2-index-token-0001")
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='requested',released_at=NULL`); err != nil {
		t.Fatal(err)
	}
	_, err := finishSandboxSearch(ctx, index, lease, "v2-worker", "v2-index-token-0001", "indexed", lease.IDs, 0)
	requireSandboxSQLState(t, err, "55000")
	err = index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,'v2-worker','v2-index-token-0001',$6,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, lease.Attempt).Scan(&body)
	requireSandboxSQLState(t, err, "55000")
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='released',released_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if _, err := finishSandboxSearch(ctx, index, lease, "v2-worker", "v2-index-token-0001", "retryable", []string{}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_sandbox_search_outbox SET attempt=100,next_attempt_at=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='requested',released_at=NULL`); err != nil {
		t.Fatal(err)
	}
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim('v2-worker','v2-index-token-0002',30)`).Scan(&body); err != nil || len(body) != 0 {
		t.Fatal("held exhaustion mutated", string(body), err)
	}
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_sandbox_search_outbox`).Scan(&state); err != nil || state != "pending" {
		t.Fatal("held exhaustion not preserved", state, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_recovery_holds SET state='released',released_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim('v2-worker','v2-index-token-0003',30)`).Scan(&body); err != nil || len(body) != 0 {
		t.Fatal("exhausted work claimed", string(body), err)
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM zasp_runtime_sandbox_search_outbox`).Scan(&state); err != nil || state != "quarantined" {
		t.Fatal("exhaustion not retained", state, err)
	}
}

func TestRuntimeSandboxSearchLeaseRejectsReadinessAfterRowWait(t *testing.T) {
	for _, operation := range []string{"heartbeat", "finish"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, index := sandboxSearchLeaseFixture(t, ctx)
			lease := claimSandboxSearch(t, ctx, index, "v2-worker", "v2-index-token-0001")
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(ctx)
			var before string
			if err := admin.QueryRow(ctx, `SELECT row_to_json(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `SELECT 1 FROM zasp_runtime_sandbox_search_outbox FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if operation == "finish" {
					_, err := finishSandboxSearch(ctx, index, lease, "v2-worker", "v2-index-token-0001", "indexed", lease.IDs, 0)
					done <- err
					return
				}
				var body json.RawMessage
				done <- index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,'v2-worker','v2-index-token-0001',$6,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, lease.Attempt).Scan(&body)
			}()
			blocked := false
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, index.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("operation did not wait on owned row lock")
			}
			if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_sandbox_binding_checksum'`); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			requireSandboxSQLState(t, <-done, "55000")
			if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_sandbox_binding_checksum'`, migrations.ProductionRuntimeSandboxBinding().Checksum()); err != nil {
				t.Fatal(err)
			}
			var after string
			if err := admin.QueryRow(ctx, `SELECT row_to_json(q)::text FROM zasp_runtime_sandbox_search_outbox q`).Scan(&after); err != nil || before != after {
				t.Fatal("row-wait readiness drift mutated queue", err)
			}
		})
	}
}

func TestRuntimeSandboxSearchLeaseClaimSkipsScopeLock(t *testing.T) {
	for _, attempt := range []int{0, 100} {
		t.Run(time.Duration(attempt).String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, index := sandboxSearchLeaseFixture(t, ctx)
			if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_sandbox_search_outbox SET attempt=$1`, attempt); err != nil {
				t.Fatal(err)
			}
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'zasp-recovery-hold',organization_id,workspace_id,environment_id),0)) FROM zasp_runtime_sandbox_search_outbox`); err != nil {
				t.Fatal(err)
			}
			bounded, stop := context.WithTimeout(ctx, 2*time.Second)
			var body json.RawMessage
			err = index.QueryRow(bounded, `SELECT zasp_runtime_sandbox_search_claim('v2-worker','v2-index-token-0001',30)`).Scan(&body)
			stop()
			if err != nil || len(body) != 0 {
				t.Fatal("claim waited on recovery scope or changed held work", string(body), err)
			}
			var actual int
			var state string
			if err := tx.QueryRow(ctx, `SELECT state,attempt FROM zasp_runtime_sandbox_search_outbox`).Scan(&state, &actual); err != nil || state != "pending" || actual != attempt {
				t.Fatal("contended scope work mutated", state, actual, err)
			}
		})
	}
}

func TestRuntimeSandboxSearchLeaseConcurrentClaimAndReclaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, index := sandboxSearchLeaseFixture(t, ctx)
	peer, err := pgx.ConnectConfig(ctx, index.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close(ctx)
	type result struct {
		body  json.RawMessage
		err   error
		token string
	}
	start := make(chan struct{})
	done := make(chan result, 2)
	for i, connection := range []*pgx.Conn{index, peer} {
		token := []string{"concurrent-index-token-1", "concurrent-index-token-2"}[i]
		go func() {
			<-start
			var body json.RawMessage
			err := connection.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim('v2-worker',$1,30)`, token).Scan(&body)
			done <- result{body, err, token}
		}()
	}
	close(start)
	var winner result
	count := 0
	for range 2 {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		if len(r.body) > 0 {
			count++
			winner = r
		}
	}
	var lease sandboxSearchLease
	if count != 1 || json.Unmarshal(winner.body, &lease) != nil || lease.Attempt != 1 {
		t.Fatal("concurrent workers double claimed", count, string(winner.body))
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_sandbox_search_outbox SET lease_until=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	_, err = finishSandboxSearch(ctx, index, lease, "v2-worker", winner.token, "indexed", lease.IDs, 0)
	requireSandboxSQLState(t, err, "40001")
	reclaimed := claimSandboxSearch(t, ctx, index, "v2-worker", "reclaimed-index-token-1")
	if reclaimed.Attempt != 2 {
		t.Fatal("reclaim lost attempt fence", reclaimed.Attempt)
	}
	_, err = finishSandboxSearch(ctx, index, lease, "v2-worker", winner.token, "indexed", lease.IDs, 0)
	requireSandboxSQLState(t, err, "40001")
	if _, err := finishSandboxSearch(ctx, index, reclaimed, "v2-worker", "reclaimed-index-token-1", "retryable", []string{}, 60); err != nil {
		t.Fatal(err)
	}
	var body json.RawMessage
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_claim('v2-worker','reclaimed-index-token-2',30)`).Scan(&body); err != nil || len(body) != 0 {
		t.Fatal("retry delay ignored", string(body), err)
	}
}

func TestRuntimeSandboxSearchLeaseExpiresDuringScopeWait(t *testing.T) {
	for _, operation := range []string{"heartbeat", "finish"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, index := sandboxSearchLeaseFixture(t, ctx)
			lease := claimSandboxSearch(t, ctx, index, "v2-worker", "v2-index-token-0001")
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(ctx)
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `UPDATE zasp_runtime_sandbox_search_outbox SET lease_until=clock_timestamp()+interval '1 second'`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if operation == "finish" {
					_, err := finishSandboxSearch(ctx, index, lease, "v2-worker", "v2-index-token-0001", "indexed", lease.IDs, 0)
					done <- err
					return
				}
				var body json.RawMessage
				done <- index.QueryRow(ctx, `SELECT zasp_runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,'v2-worker','v2-index-token-0001',$6,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, lease.Attempt).Scan(&body)
			}()
			blocked := false
			deadline := time.Now().Add(750 * time.Millisecond)
			for time.Now().Before(deadline) {
				if err := observer.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, index.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("operation did not reach owned scope lock")
			}
			time.Sleep(1100 * time.Millisecond)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			requireSandboxSQLState(t, <-done, "40001")
			var unchanged bool
			if err := admin.QueryRow(ctx, `SELECT state='leased' AND attempt=1 AND lease_until<clock_timestamp() AND indexed_at IS NULL FROM zasp_runtime_sandbox_search_outbox`).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("expired scope-wait mutated lease", unchanged, err)
			}
		})
	}
}
