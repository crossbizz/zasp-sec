package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A v1 checkpoint is not evidence that the separate v2 provider was populated.
func TestRuntimeSandboxSearchBackfillPreservesOldCheckpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_session_search_outbox SET state='indexed',attempt=1,worker_id='old-worker',lease_digest=digest('old-index-token','sha256'),indexed_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(work)::text FROM zasp_runtime_session_search_outbox work`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	var pending, bound int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox WHERE state='pending' AND attempt=0 AND worker_id IS NULL AND indexed_at IS NULL`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("v2 pending backfill=%d err=%v", pending, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox fresh JOIN zasp_runtime_session_search_outbox old USING(organization_id,workspace_id,environment_id,batch_id,batch_generation) WHERE (fresh.receipt_digest,fresh.receipt_reference,fresh.receipt_version,fresh.document_ids)=(old.receipt_digest,old.receipt_reference,old.receipt_version,old.document_ids)`).Scan(&bound); err != nil || bound != 1 {
		t.Fatal("backfill lost immutable receipt binding", bound, err)
	}
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal("receipt replay", err)
	}
	var after string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(work)::text FROM zasp_runtime_session_search_outbox work`).Scan(&after); err != nil || before != after {
		t.Fatal("v2 install/replay changed old checkpoint", err)
	}
	if err := rollbackRuntimeSandboxDraft(ctx, admin); err != nil {
		t.Fatal("unattempted backfill should permit guarded rollback", err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox WHERE state='pending' AND attempt=0`).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("reinstall lost backfill", pending, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_runtime_sandbox_search_outbox SET attempt=1`); err != nil {
		t.Fatal(err)
	}
	if err := rollbackRuntimeSandboxDraft(ctx, admin); err == nil {
		t.Fatal("rollback discarded attempted v2 indexing evidence")
	}
}

func TestRuntimeSandboxSearchBackfillIgnoresMissingLegacyProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_session_search_outbox`); err != nil {
		t.Fatal(err)
	}
	installRuntimeSandboxDraft(t, ctx, admin)
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox WHERE state='pending' AND cardinality(document_ids)=3`).Scan(&count); err != nil || count != 1 {
		t.Fatal("v2 backfill depended on legacy progress", count, err)
	}
}

func TestRuntimeSandboxSearchBackfillCatalogDriftFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	for name, mutation := range map[string]string{
		"table grant":              `GRANT SELECT ON zasp_runtime_sandbox_search_outbox TO zasp_discovery_api`,
		"column grant":             `GRANT SELECT(receipt_reference) ON zasp_runtime_sandbox_search_outbox TO zasp_discovery_api`,
		"RLS":                      `ALTER TABLE zasp_runtime_sandbox_search_outbox NO FORCE ROW LEVEL SECURITY`,
		"trigger":                  `ALTER TABLE zasp_runtime_session_projection_receipts DISABLE TRIGGER zasp_runtime_sandbox_search_enqueue`,
		"helper grant":             `GRANT EXECUTE ON FUNCTION zasp_runtime_sandbox_search_enqueue() TO zasp_runtime_index_worker`,
		"index":                    `DROP INDEX zasp_runtime_sandbox_search_due_idx`,
		"policy":                   `ALTER POLICY zasp_runtime_sandbox_search_outbox_authority ON zasp_runtime_sandbox_search_outbox USING(false)`,
		"unexpected queue trigger": `CREATE TRIGGER unexpected_queue_mutation BEFORE INSERT ON zasp_runtime_sandbox_search_outbox FOR EACH ROW EXECUTE FUNCTION zasp_runtime_sandbox_search_enqueue()`,
		"legacy insert guard":      `ALTER TABLE zasp_runtime_session_search_outbox DISABLE TRIGGER zasp_runtime_legacy_search_insert_guard`,
		"legacy guard grant":       `GRANT EXECUTE ON FUNCTION zasp_runtime_legacy_search_insert_guard() TO zasp_runtime_index_worker`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2)`, migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("catalog drift accepted", ready, err)
			}
		})
	}
}

func TestRuntimeSandboxSearchBackfillEnqueuesNewReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox WHERE state='pending' AND attempt=0`).Scan(&count); err != nil || count != 1 {
		t.Fatal("new receipt not queued for v2", count, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox`).Scan(&count); err != nil || count != 0 {
		t.Fatal("sandbox receipt leaked into legacy queue", count, err)
	}
	// Reproduce the write a stale predecessor enqueue would attempt. A version
	// fence must reject it independently of the new enqueue's early return.
	_, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_session_search_outbox(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids)
 SELECT organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,receipt_reference,receipt_version,document_ids FROM zasp_runtime_sandbox_search_outbox`)
	requireSandboxSQLState(t, err, "22023")
	if err := coordinator.QueryRow(ctx, sandboxSessionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_sandbox_search_outbox`).Scan(&count); err != nil || count != 1 {
		t.Fatal("replay duplicated v2 work", count, err)
	}
	if _, err := coordinator.Exec(ctx, `SELECT * FROM zasp_runtime_sandbox_search_outbox`); err == nil {
		t.Fatal("coordinator received direct v2 table access")
	}
}

func TestRuntimeSandboxSearchBackfillFreshLegacyReceiptAfter50(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"zasp_runtime_session_search_outbox", "zasp_runtime_sandbox_search_outbox"} {
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()+` WHERE state='pending' AND attempt=0`).Scan(&count); err != nil || count != 1 {
			t.Fatal("fresh legacy receipt wasn't queued", table, count, err)
		}
	}
	var before string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(work)::text FROM zasp_runtime_sandbox_search_outbox work`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "candidate_index"
	index, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close(context.Background())
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_session_search_claim('legacy-worker','legacy-after50-token-0001',30)`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var lease sandboxSearchLease
	if err := json.Unmarshal(body, &lease); err != nil || lease.Attempt != 1 || len(lease.IDs) != 3 {
		t.Fatal("legacy claim rejected", string(body), err)
	}
	if err := index.QueryRow(ctx, `SELECT zasp_runtime_session_search_heartbeat($1,$2,$3,$4,$5,'legacy-worker','legacy-after50-token-0001',$6,30)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, lease.Attempt).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var first string
	for retry := 0; retry < 2; retry++ {
		if err := index.QueryRow(ctx, `SELECT zasp_runtime_session_search_finish($1,$2,$3,$4,$5,'legacy-worker','legacy-after50-token-0001',$6,decode($7,'hex'),'indexed',$8,0)`, lease.Organization, lease.Workspace, lease.Environment, lease.Batch, lease.Generation, lease.Attempt, lease.Digest, lease.IDs).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if retry == 0 {
			first = string(body)
		} else if string(body) != first {
			t.Fatal("legacy checkpoint retry changed response")
		}
	}
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal("legacy receipt replay", err)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_search_outbox WHERE state='indexed' AND attempt=1 AND indexed_at IS NOT NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatal("legacy checkpoint lost", count, err)
	}
	var after string
	if err := admin.QueryRow(ctx, `SELECT row_to_json(work)::text FROM zasp_runtime_sandbox_search_outbox work`).Scan(&after); err != nil || after != before {
		t.Fatal("legacy worker/replay changed v2 progress", err)
	}
}

func TestRuntimeSandboxSearchBackfillRejectsMissingCanonicalAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	args, _ := seedSessionProjectionCompletion(t, ctx, admin)
	var body json.RawMessage
	if err := coordinator.QueryRow(ctx, sessionProjectionFinishSQL, args...).Scan(&body); err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE zasp_runtime_stage_work SET result_digest=decode(repeat('a',64),'hex') WHERE stage='project'`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, migrations.ProductionRuntimeSandboxBinding().UpSQL())
	requireSandboxSQLState(t, err, "55000")
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.zasp_runtime_sandbox_search_outbox') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("rejected install left partial v2 queue", absent, err)
	}
}

func TestRuntimeSandboxSearchBackfillRollbackRefusesQueueContention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	other, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE zasp_runtime_sandbox_search_outbox IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(ctx, 2*time.Second)
	err = rollbackRuntimeSandboxDraft(bounded, other)
	stop()
	requireSandboxSQLState(t, err, "55P03")
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_sandbox_binding_readiness($1,$2)`, migrations.ProductionRuntimeSandboxBinding().Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatal("contention damaged installed release", ready, err)
	}
}
