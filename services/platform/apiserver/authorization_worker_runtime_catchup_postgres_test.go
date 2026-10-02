package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This is an explicit fixture-created historical capture gap. Both event and
// evaluation were written through signed77 HTTP; no event payload is fabricated.
// Only the unaccepted queue/reference rows are removed, before any occurrence.
func workerRuntimeHistoricalSourceGap(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, gatewayEvent string) string {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var source string
	if err := tx.QueryRow(ctx, `SELECT s.event_id FROM zasp_temporal77.source_events s JOIN zasp_temporal77.runtime_evaluations a ON(a.organization_id,a.workspace_id,a.environment_id,a.event_id)=(s.organization_id,s.workspace_id,s.environment_id,s.source_id) WHERE(s.organization_id,s.workspace_id,s.environment_id,s.source_kind,s.source_id)=($1,$2,$3,'runtime_decision',$4) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(s.organization_id,s.workspace_id,s.environment_id,s.event_id)) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_acceptances v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=(s.organization_id,s.workspace_id,s.environment_id,s.event_id))`, o, w, e, gatewayEvent).Scan(&source); err != nil {
		t.Fatal("historical-gap exact unconsumed signed source", err)
	}
	if tag, err := tx.Exec(ctx, `DELETE FROM zasp_temporal77.source_pending WHERE(organization_id,workspace_id,environment_id,event_id)=($1,$2,$3,$4)`, o, w, e, source); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("historical-gap exact pending row", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE zasp_temporal77.source_events DISABLE TRIGGER immutable`); err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(ctx, `DELETE FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,event_id)=($1,$2,$3,$4)`, o, w, e, source); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("historical-gap exact reference row", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE zasp_temporal77.source_events ENABLE TRIGGER immutable`); err != nil {
		t.Fatal(err)
	}
	var restored bool
	if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND EXISTS(SELECT 1 FROM zasp_runtime_gateway_events v JOIN zasp_temporal77.runtime_evaluations a USING(organization_id,workspace_id,environment_id,event_id) WHERE(v.organization_id,v.workspace_id,v.environment_id,v.event_id)=($1,$2,$3,$4)) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_events WHERE event_id=$5)`, o, w, e, gatewayEvent, source).Scan(&restored); err != nil || !restored {
		t.Fatal("historical-gap restored catalog or signed evidence", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("fixture-created historical source gap; actual signed event/evaluation retained, all catalog guards restored")
	return source
}

func assertWorkerRuntimeCatchup(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run, definition, source string) {
	t.Helper()
	config := owner.Config().Copy()
	config.User = "worker_test_executor"
	executor, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())
	var revision int64
	var capturedDigest, originalMatch string
	if err := owner.QueryRow(ctx, `SELECT org.desired,a.digest,encode(occ.snapshot_digest,'hex') FROM zasp_authorization80_worker.runtime_associations a JOIN zasp_authorization80_worker.test_state s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal77.occurrences occ USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_authorization79.organizations org USING(organization_id) WHERE a.run_id=$1 AND s.target_current AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_events WHERE event_id=$2)`, run, source).Scan(&revision, &capturedDigest, &originalMatch); err != nil {
		t.Fatal("catch-up prior valid captured task", err)
	}
	assertWorkerRuntimeCatchupWait(t, ctx, owner, executor, o, w, e, run, source)
	var found bool
	for page := 0; page < 20; page++ {
		var raw json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.scan_sources(100)`).Scan(&raw); err != nil {
			t.Fatal("actual registered source catch-up", err)
		}
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal77.source_events WHERE event_id=$1)`, source).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("bounded actual catch-up did not restore canonical source")
	}
	var invalidated bool
	if err := owner.QueryRow(ctx, `SELECT NOT s.target_current AND org.desired>$2 AND a.digest=$3 AND encode(occ.snapshot_digest,'hex')=$4 AND (zasp_temporal77.source_match(a.organization_id,a.workspace_id,a.environment_id,occ.event_id,d.body,clock_timestamp())->>'digest' IS DISTINCT FROM $4) AND EXISTS(SELECT 1 FROM zasp_temporal77.source_pending WHERE event_id=$5) AND NOT EXISTS(SELECT 1 FROM zasp_authorization79.current_grants WHERE task_id=$1 AND kind IN('session','gateway_device')) FROM zasp_authorization80_worker.runtime_associations a JOIN zasp_authorization80_worker.test_state s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal77.occurrences occ USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(a.organization_id,a.workspace_id,a.environment_id,$6) JOIN zasp_authorization79.organizations org ON org.organization_id=a.organization_id WHERE a.run_id=$1`, run, revision, capturedDigest, originalMatch, source, definition).Scan(&invalidated); err != nil || !invalidated {
		t.Fatal("catch-up did not revoke changed match while preserving immutable capture", err)
	}
	request, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 5})
	var ignored json.RawMessage
	err = executor.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning74_source('state',$1::jsonb)`, request).Scan(&ignored)
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != "40001" {
		t.Fatal("catch-up changed source did not refuse native forward read", err)
	}
}

func assertWorkerRuntimeCatchupWait(t *testing.T, ctx context.Context, owner, executor *pgx.Conn, o, w, e, run, source string) {
	t.Helper()
	// Seed only discovery progress, never source/admission authority. The real
	// scanner still resolves every row and inserts through its retained writer.
	if _, err := owner.Exec(ctx, `UPDATE zasp_temporal77.source_scan SET source_kind='runtime_decision',after_o=$1,after_w=$2,after_e=$3,after_id='',runtime_at=NULL,runtime_active=true WHERE singleton`, o, w, e); err != nil {
		t.Fatal("owned runtime catch-up cursor setup", err)
	}
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	var ignored string
	if err := lock.QueryRow(ctx, `SELECT organization_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, o).Scan(&ignored); err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tx, err := executor.BeginTx(operation, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback(context.Background())
		var result json.RawMessage
		err = tx.QueryRow(operation, `SELECT zasp_temporal77.scan_sources(100)`).Scan(&result)
		if rollbackErr := tx.Rollback(context.Background()); err == nil {
			err = rollbackErr
		}
		done <- err
	}()
	joined := false
	defer func() {
		cancel()
		_ = lock.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	var blocked bool
	for !blocked && time.Now().Before(deadline) {
		select {
		case err := <-done:
			joined = true
			t.Fatal("registered catch-up crossed held organization lock", err)
		default:
		}
		if err := lock.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, owner.PgConn().PID(), executor.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if !blocked {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !blocked {
		t.Fatal("runtime source scanner did not reach actual organization wait")
	}
	var unchanged bool
	if err := lock.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_events WHERE event_id=$1) AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state WHERE run_id=$2 AND target_current)`, source, run).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("waiting catch-up inserted source or invalidated capture early", err)
	}
	// The retained scanner holds its cursor before asking for the org row. Prove
	// that exact ordering so review cannot accidentally assume org -> cursor.
	observer, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	probe, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var singleton bool
	err = probe.QueryRow(ctx, `SELECT singleton FROM zasp_temporal77.source_scan WHERE singleton FOR UPDATE NOWAIT`).Scan(&singleton)
	var native *pgconn.PgError
	if rollbackErr := probe.Rollback(context.Background()); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if !errors.As(err, &native) || native.Code != "55P03" {
		t.Fatal("catch-up cursor lock order was not observed", err)
	}
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	if err != nil {
		t.Fatal("registered catch-up after organization release", err)
	}
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_events WHERE event_id=$1) AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state WHERE run_id=$2 AND target_current)`, source, run).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("rollback-only catch-up changed committed capture", err)
	}
}
