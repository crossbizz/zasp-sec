package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/sandboxcutover"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func cutoverPostgresFixture(t *testing.T) (context.Context, *pgx.Conn, *sandboxcutover.PostgresDatabase, sandboxcutover.ReleaseBinding) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin := connectMigrationPostgres(t, ctx, startMigrationPostgres(t))
	t.Cleanup(func() { admin.Close(context.Background()) })
	runner, err := migrations.NewRunner(&migrationDatabase{connection: admin})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up-to-50"}); err != nil {
		t.Fatal(err)
	}
	database, err := sandboxcutover.NewPostgresDatabase(admin.Config().Copy(), "zasp_test", "owned-cutover-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return ctx, admin, database, sandboxcutover.ReleaseBinding{DatabaseIdentity: "owned-cutover-fixture"}
}

// These migration-owner rows isolate capture/fence authority. They are not
// evidence of authenticated intake, artifact publication, or worker completion.
func seedCutoverReceipt(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	seedCutoverReceiptTenant(t, ctx, conn, false)
}

func seedCutoverReceiptTenant(t *testing.T, ctx context.Context, conn *pgx.Conn, other bool) {
	t.Helper()
	otherScope := strings.NewReplacer("pid_79510001", "pid_79520001", "pid_79510002", "pid_79520002", "pid_79510003", "pid_79520003", "cutover.invalid", "cutover-other.invalid")
	for _, sql := range []string{
		`INSERT INTO zasp_organizations(id,name,domain) VALUES('pid_79510001-0000-4000-8000-000000000001','Cutover fixture','cutover.invalid')`,
		`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES('pid_79510002-0000-4000-8000-000000000002','pid_79510001-0000-4000-8000-000000000001','Fixture')`,
		`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES('pid_79510003-0000-4000-8000-000000000003','pid_79510001-0000-4000-8000-000000000001','pid_79510002-0000-4000-8000-000000000002','Fixture','production')`,
	} {
		if other {
			sql = otherScope.Replace(sql)
		}
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	org, ws, env := "pid_79510001-0000-4000-8000-000000000001", "pid_79510002-0000-4000-8000-000000000002", "pid_79510003-0000-4000-8000-000000000003"
	if other {
		org = otherScope.Replace(org)
		ws = otherScope.Replace(ws)
		env = otherScope.Replace(env)
	}
	for _, sql := range []string{
		`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,'pid_79510004-0000-4000-8000-000000000004','Fixture','tetragon')`,
		`INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,salt,token_hash,expires_at) VALUES($1,$2,$3,'pid_79510004-0000-4000-8000-000000000004','pid_79510004-0000-4000-8000-000000000004',decode(repeat('ab',16),'hex'),decode(repeat('ab',32),'hex'),now()+interval '1 day')`,
		`INSERT INTO zasp_runtime_batches(organization_id,workspace_id,environment_id,id,sensor_id,idempotency_key,payload_digest,event_count,payload_reference,payload_size_bytes,payload_media_type,payload_schema_version,state) VALUES($1,$2,$3,'pid_79510005-0000-4000-8000-000000000005','pid_79510004-0000-4000-8000-000000000004','cutover-fixture',decode(repeat('ab',32),'hex'),2,'s3://zasp-evidence/runtime/cutover.json',100,'application/json','runtime-v1','processing')`,
		`INSERT INTO zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,sensor_id,sensor_token_id,token_generation,batch_generation,idempotency_key,request_digest,content_digest,source_kind,payload_media_type,payload_schema_version,payload_size_bytes,event_count,raw_artifact_key,raw_artifact_reference,raw_artifact_version_id,raw_artifact_checksum,raw_artifact_size_bytes,raw_artifact_kms_key,finalized_at,state) VALUES($1,$2,$3,'pid_79510005-0000-4000-8000-000000000005','pid_79510004-0000-4000-8000-000000000004','pid_79510004-0000-4000-8000-000000000004',1,1,'cutover-fixture',decode(repeat('ab',32),'hex'),decode(repeat('ab',32),'hex'),'tetragon','application/json','runtime-v1',100,2,'runtime/cutover.json','s3://zasp-evidence/runtime/cutover.json','archive-v1',decode(repeat('ab',32),'hex'),100,'fixture-kms',now(),'processing')`,
		`INSERT INTO zasp_runtime_stage_work(organization_id,workspace_id,environment_id,batch_id,batch_generation,stage,stage_order,implementation_version,input_digest,state,attempt,effect_digest,result_reference,result_version_id,result_digest,completed_at) SELECT $1,$2,$3,'pid_79510005-0000-4000-8000-000000000005',1,stage,ord,version,decode(repeat('ab',32),'hex'),'succeeded',1,decode(repeat('ab',32),'hex'),'s3://zasp-evidence/projected.json','projected-v1',decode(repeat('cd',32),'hex'),now() FROM (VALUES('project',4,'runtime-projection-v2'),('complete',5,'runtime-complete-v2')) v(stage,ord,version)`,
		`INSERT INTO zasp_runtime_session_projection_receipts(organization_id,workspace_id,environment_id,batch_id,batch_generation,receipt_digest,event_ids) VALUES($1,$2,$3,'pid_79510005-0000-4000-8000-000000000005',1,decode(repeat('cd',32),'hex'),ARRAY['pid_79510007-0000-4000-8000-000000000007','pid_79510006-0000-4000-8000-000000000006'])`,
		`UPDATE zasp_runtime_sandbox_search_outbox SET state='indexed',attempt=1,worker_id='fixture-worker',lease_digest=decode(repeat('ab',32),'hex'),indexed_at=now() WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`,
	} {
		sql = strings.NewReplacer("'cutover-fixture'", "'cutover-fixture-0001'", "'runtime/cutover.json'", "'runtime/cutover-fixture-archive-0001.json'").Replace(sql)
		if other && strings.Contains(sql, "INSERT INTO zasp_sensor_tokens") {
			sql = strings.ReplaceAll(sql, "repeat('ab',32)", "repeat('ef',32)")
		}
		if _, err := conn.Exec(ctx, sql, org, ws, env); err != nil {
			t.Fatal("seed canonical capture fixture", err)
		}
	}
}

func TestSandboxCutoverPostgresCanonicalCapture(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	seedCutoverReceipt(t, ctx, admin)
	capture, err := database.Capture(ctx, binding)
	if err != nil || len(capture.Records) != 1 {
		t.Fatal("complete canonical receipt refused", capture, err)
	}
	r := capture.Records[0]
	if r.Binding.Scope.OrganizationID().String() != "pid_79510001-0000-4000-8000-000000000001" || r.Binding.Scope.WorkspaceID().String() != "pid_79510002-0000-4000-8000-000000000002" || r.Binding.Scope.EnvironmentID().String() != "pid_79510003-0000-4000-8000-000000000003" || r.Binding.BatchID.String() != "pid_79510005-0000-4000-8000-000000000005" || r.Binding.Generation != 1 || r.Binding.ReceiptDigest != [32]byte{0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd} || r.ReceiptReference != "s3://zasp-evidence/projected.json" || r.ReceiptVersion != "projected-v1" || r.ProjectVersion != "runtime-projection-v2" || r.CompleteVersion != "runtime-complete-v2" || !reflect.DeepEqual(r.EventIDs, []string{"pid_79510007-0000-4000-8000-000000000007", "pid_79510006-0000-4000-8000-000000000006"}) || len(r.DocumentIDs) != 2 {
		t.Fatal("capture changed authority", r)
	}
	cleanup, err := database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error {
		current, err := f.Capture(ctx)
		if err != nil || !reflect.DeepEqual(current, capture) {
			t.Fatal("recapture not deterministic", current, err)
		}
		return nil
	})
	if err != nil || !cleanup.CleanupConfirmed {
		t.Fatal(cleanup, err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM zasp_runtime_sandbox_search_outbox`); err != nil {
		t.Fatal(err)
	}
	if omitted, err := database.Capture(ctx, binding); err == nil {
		t.Fatal("canonical receipt missing target silently omitted", omitted)
	}
}

func TestSandboxCutoverPostgresEmptyReadinessAndFence(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	capture, err := database.Capture(ctx, binding)
	if err != nil || capture.Records == nil || len(capture.Records) != 0 || len(capture.Digest) != 64 {
		t.Fatal("empty canonical capture", capture, err)
	}
	called := 0
	cleanup, err := database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error {
		called++
		if err := f.Ready(ctx); err != nil {
			return err
		}
		current, err := f.Capture(ctx)
		if err != nil || current.Digest != capture.Digest {
			t.Fatal("fenced empty capture", current, err)
		}
		at, err := f.AliveAt(ctx)
		if err != nil || at.IsZero() || at.Location() != time.UTC {
			t.Fatal("fence time", at, err)
		}
		return errors.New("deliberate predispatch refusal")
	})
	if err == nil || called != 1 || !cleanup.CleanupConfirmed {
		t.Fatal("refusal cleanup", called, cleanup, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_runtime_sandbox_binding_checksum'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Capture(ctx, binding); err == nil {
		t.Fatal("compiled checksum drift accepted")
	}
	cleanup, err = database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error { called++; return nil })
	if err == nil || called != 1 || !cleanup.CleanupConfirmed {
		t.Fatal("drift dispatched or leaked fence", called, cleanup, err)
	}
}

func TestSandboxCutoverPostgresRejectsIncompleteAuthority(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	seedCutoverReceipt(t, ctx, admin)
	snapshot := func() string {
		t.Helper()
		var body string
		if err := admin.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(r)) FROM zasp_runtime_session_projection_receipts r),(SELECT jsonb_agg(to_jsonb(w) ORDER BY stage) FROM zasp_runtime_stage_work w),(SELECT jsonb_agg(to_jsonb(q)) FROM zasp_runtime_sandbox_search_outbox q),(SELECT jsonb_agg(to_jsonb(q)) FROM zasp_runtime_session_search_outbox q))::text`).Scan(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"queue digest", `UPDATE zasp_runtime_sandbox_search_outbox SET receipt_digest=decode(repeat('ee',32),'hex')`, `UPDATE zasp_runtime_sandbox_search_outbox SET receipt_digest=decode(repeat('cd',32),'hex')`},
		{"queue reference", `UPDATE zasp_runtime_sandbox_search_outbox SET receipt_reference='s3://zasp-evidence/wrong.json'`, `UPDATE zasp_runtime_sandbox_search_outbox SET receipt_reference='s3://zasp-evidence/projected.json'`},
		{"queue version", `UPDATE zasp_runtime_sandbox_search_outbox SET receipt_version='wrong-version'`, `UPDATE zasp_runtime_sandbox_search_outbox SET receipt_version='projected-v1'`},
		{"document order", `UPDATE zasp_runtime_sandbox_search_outbox SET document_ids=ARRAY[document_ids[2],document_ids[1]]`, `UPDATE zasp_runtime_sandbox_search_outbox SET document_ids=ARRAY[document_ids[2],document_ids[1]]`},
		{"document identity", `UPDATE zasp_runtime_sandbox_search_outbox SET document_ids=ARRAY[repeat('e',64),document_ids[2]]`, `UPDATE zasp_runtime_sandbox_search_outbox q SET document_ids=zasp_runtime_session_search_document_ids(q.organization_id,q.workspace_id,q.environment_id,q.batch_id,q.batch_generation,r.event_ids) FROM zasp_runtime_session_projection_receipts r WHERE r.batch_id=q.batch_id`},
		{"project digest", `UPDATE zasp_runtime_stage_work SET result_digest=decode(repeat('ee',32),'hex') WHERE stage='project'`, `UPDATE zasp_runtime_stage_work SET result_digest=decode(repeat('cd',32),'hex') WHERE stage='project'`},
		{"project pending", `UPDATE zasp_runtime_stage_work SET state='pending',completed_at=NULL WHERE stage='project'`, `UPDATE zasp_runtime_stage_work SET state='succeeded',completed_at=now() WHERE stage='project'`},
		{"complete failed", `UPDATE zasp_runtime_stage_work SET state='failed' WHERE stage='complete'`, `UPDATE zasp_runtime_stage_work SET state='succeeded' WHERE stage='complete'`},
		{"complete generation", `UPDATE zasp_runtime_stage_work SET batch_generation=2 WHERE stage='complete'`, `UPDATE zasp_runtime_stage_work SET batch_generation=1 WHERE stage='complete'`},
		{"mismatched implementations", `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-complete-v1' WHERE stage='complete'`, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-complete-v2' WHERE stage='complete'`},
		{"future implementation", `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-projection-v3' WHERE stage='project'`, `UPDATE zasp_runtime_stage_work SET implementation_version='runtime-projection-v2' WHERE stage='project'`},
		{"quarantined queue", `UPDATE zasp_runtime_sandbox_search_outbox SET state='quarantined',indexed_at=NULL,worker_id=NULL,lease_digest=NULL`, `UPDATE zasp_runtime_sandbox_search_outbox SET state='indexed',indexed_at=now(),worker_id='fixture-worker',lease_digest=decode(repeat('ab',32),'hex')`},
		{"pending queue", `UPDATE zasp_runtime_sandbox_search_outbox SET state='pending',indexed_at=NULL,worker_id=NULL,lease_digest=NULL`, `UPDATE zasp_runtime_sandbox_search_outbox SET state='indexed',indexed_at=now(),worker_id='fixture-worker',lease_digest=decode(repeat('ab',32),'hex')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, tc.change); err != nil {
				t.Fatal("fixture corruption", err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, tc.restore); err != nil {
					t.Fatal("restore fixture", err)
				}
			}()
			before := snapshot()
			if got, err := database.Capture(ctx, binding); err == nil {
				t.Fatal("incomplete authority accepted", got)
			}
			cleanup, err := database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error { _, err := f.Capture(ctx); return err })
			if err == nil || !cleanup.CleanupConfirmed {
				t.Fatal("incomplete fenced authority accepted or cleanup lost", cleanup, err)
			}
			if snapshot() != before {
				t.Fatal("read-only refusal changed canonical, stage or either target rows")
			}
		})
	}
}

func cutoverPeer(t *testing.T, ctx context.Context, admin *pgx.Conn) *pgx.Conn {
	t.Helper()
	conn, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func awaitCutoverLock(ctx context.Context, admin *pgx.Conn, pid uint32, relation string) error {
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation=$2::regclass AND NOT granted)`, pid, relation).Scan(&waiting); err != nil {
			return err
		}
		if waiting {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("writer was not blocked by cutover fence")
		case <-ticker.C:
		}
	}
}

func TestSandboxCutoverFenceBlocksNewReceipt(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	seedCutoverReceipt(t, ctx, admin)
	// A second completed owner fixture has no canonical receipt yet. Its INSERT
	// below is the concurrent producer boundary, not a claimed worker success.
	for _, table := range []string{"zasp_runtime_batches", "zasp_runtime_batch_authorities", "zasp_runtime_stage_work"} {
		patch := `'{"batch_id":"pid_79510008-0000-4000-8000-000000000008","batch_generation":2,"idempotency_key":"cutover-fixture-0002"}'::jsonb`
		if table == "zasp_runtime_batches" {
			patch = `'{"id":"pid_79510008-0000-4000-8000-000000000008","idempotency_key":"cutover-fixture-0002"}'::jsonb`
		}
		if _, err := admin.Exec(ctx, `INSERT INTO `+table+` SELECT (jsonb_populate_record(NULL::`+table+`,to_jsonb(original)||`+patch+`)).* FROM `+table+` original`); err != nil {
			t.Fatal("second owner fixture", err)
		}
	}
	writer := cutoverPeer(t, ctx, admin)
	writeCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	done := make(chan error, 1)
	var captured sandboxcutover.Capture
	cleanup, err := database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error {
		var err error
		captured, err = f.Capture(ctx)
		if err != nil {
			return err
		}
		// Probe before queuing the writer. A queued ROW EXCLUSIVE writer can
		// itself prevent a later SHARE lock and mask a non-self-conflicting fence.
		contenderCalled := false
		second, err := database.WithFence(ctx, binding, func(sandboxcutover.Fence) error {
			contenderCalled = true
			return errors.New("unexpected contender callback")
		})
		if contenderCalled || err == nil || !second.CleanupConfirmed {
			return errors.New("contender acquired self-conflicting fence or leaked cleanup")
		}
		go func() {
			_, err := writer.Exec(writeCtx, `INSERT INTO zasp_runtime_session_projection_receipts SELECT (jsonb_populate_record(NULL::zasp_runtime_session_projection_receipts,to_jsonb(r)||'{"batch_id":"pid_79510008-0000-4000-8000-000000000008","batch_generation":2}'::jsonb)).* FROM zasp_runtime_session_projection_receipts r`)
			done <- err
		}()
		if err := awaitCutoverLock(ctx, admin, writer.PgConn().PID(), "zasp_runtime_session_projection_receipts"); err != nil {
			return err
		}
		select {
		case err := <-done:
			return errors.New("writer finished before cleanup: " + fmt.Sprint(err))
		default:
		}
		return nil
	})
	if err != nil || !cleanup.CleanupConfirmed {
		t.Fatal("fence", cleanup, err)
	}
	if err := <-done; err != nil {
		t.Fatal("writer did not proceed after cleanup", err)
	}
	if len(captured.Records) != 1 {
		t.Fatal("late receipt entered cutoff", captured)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_runtime_session_projection_receipts`).Scan(&count); err != nil || count != 2 {
		t.Fatal("new receipt not committed", count, err)
	}
	if _, err := database.Capture(ctx, binding); err == nil {
		t.Fatal("new pending target admitted cutover")
	}
}

func TestSandboxCutoverFenceReleasesPartialLocks(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	blocker := cutoverPeer(t, ctx, admin)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `LOCK TABLE zasp_runtime_sandbox_search_outbox IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	called := false
	cleanup, err := database.WithFence(ctx, binding, func(sandboxcutover.Fence) error { called = true; return nil })
	if err == nil || called || !cleanup.CleanupConfirmed {
		t.Fatal("contended fence", called, cleanup, err)
	}
	probe, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	if _, err := probe.Exec(ctx, `LOCK TABLE zasp_schema_versions,zasp_schema_metadata,zasp_runtime_session_projection_receipts IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
		t.Fatal("partial lock set leaked after NOWAIT refusal", err)
	}
}

func TestSandboxCutoverFenceExpiresOnServer(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	writer := cutoverPeer(t, ctx, admin)
	started := time.Now()
	cleanup, err := database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error {
		done := make(chan error, 1)
		go func() {
			tx, err := writer.Begin(ctx)
			if err == nil {
				_, err = tx.Exec(ctx, `LOCK TABLE zasp_runtime_session_projection_receipts IN ROW EXCLUSIVE MODE`)
				_ = tx.Rollback(context.Background())
			}
			done <- err
		}()
		if err := awaitCutoverLock(ctx, admin, writer.PgConn().PID(), "zasp_runtime_session_projection_receipts"); err != nil {
			return err
		}
		// Intentionally do not use the expired callback context to release the
		// transaction. PostgreSQL must release its locks while this callback is
		// still waiting, before adapter rollback/close can execute.
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-time.After(18 * time.Second):
			return errors.New("server retained cutover lock beyond deadline")
		}
		if time.Since(started) < 14*time.Second {
			return errors.New("server fence expired before intended fixed window")
		}
		if _, err := f.AliveAt(ctx); err == nil {
			return errors.New("expired transaction admitted authorization cutoff")
		}
		return errors.New("expected expired callback refusal")
	})
	if err == nil || !cleanup.CleanupConfirmed {
		t.Fatal("server expiry cleanup was not confirmed", cleanup, err)
	}
}

func TestSandboxCutoverPostgresRejectsRegisteredWorker(t *testing.T) {
	ctx, admin, _, binding := cutoverPostgresFixture(t)
	for _, role := range []string{"cutover_coord", "cutover_archive", "cutover_index", "cutover_correlation", "cutover_projection", "cutover_gateway"} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	var registered bool
	if err := admin.QueryRow(ctx, `SELECT zasp_runtime_register_principals('zasp_test','cutover_coord','cutover_archive','cutover_index','cutover_correlation','cutover_projection','cutover_gateway')`).Scan(&registered); err != nil || !registered {
		t.Fatal("existing principal registration", registered, err)
	}
	config := admin.Config().Copy()
	config.User = "cutover_index"
	worker, err := sandboxcutover.NewPostgresDatabase(config, "cutover_index", binding.DatabaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Capture(ctx, binding); err == nil {
		t.Fatal("registered index worker captured owner authority")
	}
	called := false
	cleanup, err := worker.WithFence(ctx, binding, func(sandboxcutover.Fence) error { called = true; return nil })
	if err == nil || called || !cleanup.CleanupConfirmed {
		t.Fatal("registered worker fenced owner tables", called, cleanup, err)
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `SELECT * FROM zasp_runtime_session_projection_receipts`); err == nil {
		t.Fatal("test worker accidentally has direct canonical grants")
	}
}

type slowCutoverOwnerTrace struct{ delayed atomic.Bool }

func (t *slowCutoverOwnerTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "SELECT session_user=") && !t.delayed.Swap(true) {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*slowCutoverOwnerTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestSandboxCutoverFenceServerDeadlineExcludesConnectionSetup(t *testing.T) {
	ctx, admin, _, binding := cutoverPostgresFixture(t)
	config := admin.Config().Copy()
	config.Tracer = &slowCutoverOwnerTrace{}
	database, err := sandboxcutover.NewPostgresDatabase(config, "zasp_test", binding.DatabaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	writer := cutoverPeer(t, ctx, admin)
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	started := time.Now()
	var elapsed time.Duration
	cleanup, err := database.WithFence(short, binding, func(sandboxcutover.Fence) error {
		done := make(chan error, 1)
		go func() {
			tx, err := writer.Begin(ctx)
			if err == nil {
				_, err = tx.Exec(ctx, `LOCK TABLE zasp_runtime_session_projection_receipts IN ROW EXCLUSIVE MODE`)
				_ = tx.Rollback(context.Background())
			}
			done <- err
		}()
		if err := awaitCutoverLock(ctx, admin, writer.PgConn().PID(), "zasp_runtime_session_projection_receipts"); err != nil {
			return err
		}
		select {
		case err := <-done:
			elapsed = time.Since(started)
			return err
		case <-time.After(4 * time.Second):
			return errors.New("server deadline not enforced")
		}
	})
	if !errors.Is(err, context.DeadlineExceeded) || !cleanup.CleanupConfirmed {
		t.Fatal("server expiry", cleanup, err)
	}
	if elapsed < 1500*time.Millisecond || elapsed > 2700*time.Millisecond {
		t.Fatal("connection/owner setup extended transaction beyond inherited deadline", elapsed)
	}
}

func TestSandboxCutoverFenceCancellationConfirmsCleanup(t *testing.T) {
	ctx, _, database, binding := cutoverPostgresFixture(t)
	canceled, stop := context.WithCancel(ctx)
	cleanup, err := database.WithFence(canceled, binding, func(f sandboxcutover.Fence) error { stop(); return nil })
	if err == nil || !cleanup.CleanupConfirmed {
		t.Fatal("canceled callback reported successful operation or lost cleanup", cleanup, err)
	}
	called := false
	cleanup, err = database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error { called = true; return f.Ready(ctx) })
	if err != nil || !called || !cleanup.CleanupConfirmed {
		t.Fatal("canceled invocation retained fence", called, cleanup, err)
	}
}

func TestSandboxCutoverPostgresRejectsMixedReleaseState(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	var old49, checksum50 string
	if err := admin.QueryRow(ctx, `SELECT checksum FROM zasp_schema_versions WHERE version=49`).Scan(&old49); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_checksum'`).Scan(&checksum50); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, change, restore string
		args                  []any
	}{
		{"lower registry drift", `UPDATE zasp_schema_versions SET checksum=repeat('e',64) WHERE version=49`, `UPDATE zasp_schema_versions SET checksum=$1 WHERE version=49`, []any{old49}},
		{"future registry row", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(51,'unapproved_future',repeat('e',64))`, `DELETE FROM zasp_schema_versions WHERE version=51`, nil},
		{"missing compiled metadata", `DELETE FROM zasp_schema_metadata WHERE key='production_runtime_sandbox_binding_checksum'`, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_runtime_sandbox_binding_checksum',$1)`, []any{checksum50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, tc.change); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Capture(ctx, binding); err == nil {
				t.Fatal("mixed release capture accepted")
			}
			called := false
			cleanup, err := database.WithFence(ctx, binding, func(sandboxcutover.Fence) error { called = true; return nil })
			if err == nil || called || !cleanup.CleanupConfirmed {
				t.Fatal("mixed release entered callback or lost cleanup", called, cleanup, err)
			}
			if _, err := admin.Exec(ctx, tc.restore, tc.args...); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Capture(ctx, binding); err != nil {
				t.Fatal("restored exact release refused", err)
			}
		})
	}
}

func TestSandboxCutoverPostgresCannotBorrowOtherScopeStages(t *testing.T) {
	ctx, admin, database, binding := cutoverPostgresFixture(t)
	seedCutoverReceiptTenant(t, ctx, admin, false)
	seedCutoverReceiptTenant(t, ctx, admin, true)
	before, err := database.Capture(ctx, binding)
	if err != nil || len(before.Records) != 2 {
		t.Fatal("two-scope capture", before, err)
	}
	if before.Records[0].Binding.Scope.OrganizationID().String() != "pid_79510001-0000-4000-8000-000000000001" || before.Records[1].Binding.Scope.OrganizationID().String() != "pid_79520001-0000-4000-8000-000000000001" || before.Records[0].Binding.BatchID != before.Records[1].Binding.BatchID || reflect.DeepEqual(before.Records[0].DocumentIDs, before.Records[1].DocumentIDs) {
		t.Fatal("capture did not preserve tenant tuple ordering or distinct occurrence identities", before)
	}
	for _, stage := range []string{"project", "complete"} {
		t.Run(stage, func(t *testing.T) {
			var saved string
			if err := admin.QueryRow(ctx, `DELETE FROM zasp_runtime_stage_work WHERE organization_id='pid_79510001-0000-4000-8000-000000000001' AND stage=$1 RETURNING to_jsonb(zasp_runtime_stage_work)::text`, stage).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, `INSERT INTO zasp_runtime_stage_work SELECT (jsonb_populate_record(NULL::zasp_runtime_stage_work,$1::jsonb)).*`, saved); err != nil {
					t.Fatal("restore own stage", err)
				}
			}()
			snapshot := func() string {
				var body string
				if err := admin.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(r) ORDER BY organization_id) FROM zasp_runtime_session_projection_receipts r),(SELECT jsonb_agg(to_jsonb(w) ORDER BY organization_id,stage) FROM zasp_runtime_stage_work w),(SELECT jsonb_agg(to_jsonb(q) ORDER BY organization_id) FROM zasp_runtime_sandbox_search_outbox q),(SELECT jsonb_agg(to_jsonb(q) ORDER BY organization_id) FROM zasp_runtime_session_search_outbox q))::text`).Scan(&body); err != nil {
					t.Fatal(err)
				}
				return body
			}
			retained := snapshot()
			if got, err := database.Capture(ctx, binding); err == nil {
				t.Fatal("borrowed other tenant's completed stage", got)
			}
			cleanup, err := database.WithFence(ctx, binding, func(f sandboxcutover.Fence) error { _, err := f.Capture(ctx); return err })
			if err == nil || !cleanup.CleanupConfirmed {
				t.Fatal("fenced capture borrowed other tenant stage or lost cleanup", cleanup, err)
			}
			if snapshot() != retained {
				t.Fatal("cross-scope refusal mutated either tenant or target")
			}
		})
	}
	after, err := database.Capture(ctx, binding)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("restored complete set changed canonical digest/order", after, err)
	}
}
