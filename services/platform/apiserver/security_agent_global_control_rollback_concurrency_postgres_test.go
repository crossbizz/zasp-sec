package apiserver

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Gate the real runner immediately before commit, without replacing SQL,
// readiness, grants or pins. This only chooses a reproducible transaction order.
type globalRollbackGateDatabase struct {
	*integrationMigrationDatabase
	ready   chan struct{}
	release chan struct{}
}

func (d *globalRollbackGateDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.integrationMigrationDatabase.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &globalRollbackGateTransaction{Transaction: tx, ready: d.ready, release: d.release}, nil
}

type globalRollbackGateTransaction struct {
	migrations.Transaction
	ready   chan struct{}
	release chan struct{}
}

func (tx *globalRollbackGateTransaction) Commit(ctx context.Context) error {
	close(tx.ready)
	select {
	case <-tx.release:
		return tx.Transaction.Commit(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NOWAIT is intentional: when an operator owns the fence, unused rollback
// refuses immediately. It must also refuse after durable operator use commits.
func TestSecurityAgentGlobalControlRollbackUseFirstPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		caller := globalRaceConnect(t, ctx, owner, "")
		if _, err := caller.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer caller.Exec(context.Background(), "ROLLBACK")
		globalRaceSet(t, ctx, caller, false, 1, 70)
		var fence bool
		if err := owner.QueryRow(ctx, `SELECT count(DISTINCT relation)=3 FROM pg_locks WHERE pid=$1 AND granted AND relation IN('zasp_security_agent_global_control_receipts'::regclass,'zasp_security_agent_kill_switches'::regclass,'zasp_security_agent_audit'::regclass) AND mode IN('RowExclusiveLock','RowShareLock')`, caller.PgConn().PID()).Scan(&fence); err != nil || !fence {
			t.Fatalf("operator transaction fence: %t %v", fence, err)
		}
		before := globalControlSnapshot(t, ctx, owner)
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("unused rollback crossed in-flight operator fence")
		}
		if !equalIntegrationJSON(before, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("NOWAIT rollback changed committed authority")
		}
		if _, err := caller.Exec(ctx, "COMMIT"); err != nil {
			t.Fatal(err)
		}
		used := globalControlSnapshot(t, ctx, owner)
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("rollback erased committed operator use")
		}
		if !equalIntegrationJSON(used, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("used rollback changed retained operator history")
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_security_agent_global_control_receipts WHERE request_id=$1 AND resulting_version=2 AND NOT enabled) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE audit_id=$1 AND organization_id='*') AND (SELECT version=2 AND NOT execution_enabled FROM zasp_security_agent_kill_switches`+globalRaceRow+`)`, globalRaceID(70)).Scan(&exact); err != nil || !exact {
			t.Fatalf("use-first durable result: %t %v", exact, err)
		}
		globalRaceReady(t, ctx, owner)
	})
}

// If unused rollback owns its fences first, the queued operator cannot use a
// stale compiled55 identity after the runner commits the exact54 predecessor.
func TestSecurityAgentGlobalControlRollbackFirstPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		globalRaceReady(t, ctx, owner)
		caller := globalRaceConnect(t, ctx, owner, "")
		down := globalRaceConnect(t, ctx, owner, "")
		var receiptOID, controlOID, auditOID uint32
		if err := owner.QueryRow(ctx, `SELECT 'zasp_security_agent_global_control_receipts'::regclass::oid,'zasp_security_agent_kill_switches'::regclass::oid,'zasp_security_agent_audit'::regclass::oid`).Scan(&receiptOID, &controlOID, &auditOID); err != nil {
			t.Fatal(err)
		}
		gate := &globalRollbackGateDatabase{integrationMigrationDatabase: &integrationMigrationDatabase{connection: down}, ready: make(chan struct{}), release: make(chan struct{})}
		gated, err := migrations.NewRunner(gate)
		if err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		release := func() { once.Do(func() { close(gate.release) }) }
		defer release()
		done := make(chan error, 1)
		go func() { done <- gated.DownProductionSecurityAgentExistingTests(ctx) }()
		joined := false
		defer func() {
			release()
			if !joined {
				<-done
			}
		}()
		select {
		case <-gate.ready:
		case err := <-done:
			joined = true
			t.Fatalf("rollback failed before commit gate: %v", err)
		case <-time.After(15 * time.Second):
			t.Fatal("rollback did not reach commit gate")
		}
		var fenced bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=3 FROM pg_locks WHERE pid=$1 AND granted AND mode='AccessExclusiveLock' AND relation IN($2,$3,$4)`, down.PgConn().PID(), receiptOID, controlOID, auditOID).Scan(&fenced); err != nil || !fenced {
			t.Fatalf("rollback lost exact relation fences: %t %v", fenced, err)
		}
		operatorDone := make(chan error, 1)
		go func() {
			var raw json.RawMessage
			operatorDone <- caller.QueryRow(ctx, globalControlSetSQL, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint(), false, int64(1), globalRaceID(71), "rollback-first-operator").Scan(&raw)
		}()
		operatorJoined := false
		defer func() {
			release()
			if !operatorJoined {
				<-operatorDone
			}
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			select {
			case err := <-operatorDone:
				operatorJoined = true
				t.Fatalf("operator returned before rollback fence observation: %v", err)
			default:
			}
			var waiting bool
			var locks json.RawMessage
			// PostgreSQL opens the control-row composite type while preparing the
			// PL/pgSQL call, before its first receipt-table LOCK statement.
			if err := owner.QueryRow(ctx, `SELECT $2::int=ANY(pg_blocking_pids($1::int)) AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted AND locktype='relation' AND mode='AccessShareLock' AND relation=$3),COALESCE((SELECT jsonb_agg(jsonb_build_object('type',locktype,'relation',relation::regclass::text,'transaction',transactionid::text,'class',classid,'object',objid,'mode',mode)) FROM pg_locks WHERE pid=$1 AND NOT granted),'[]'::jsonb)`, caller.PgConn().PID(), down.PgConn().PID(), controlOID).Scan(&waiting, &locks); err != nil {
				t.Fatal(err)
			}
			if waiting {
				t.Logf("observed operator wait caller=%d rollback=%d locks=%s", caller.PgConn().PID(), down.PgConn().PID(), locks)
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("operator rollback relation wait not observed")
			}
			time.Sleep(10 * time.Millisecond)
		}
		release()
		err = <-done
		joined = true
		if err != nil {
			t.Fatalf("unused rollback commit: %v", err)
		}
		err = <-operatorDone
		operatorJoined = true
		globalRaceRefused(t, err, "42P01")
		t.Logf("operator refused after committed rollback: %v", err)
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_readiness($1,$2) AND to_regprocedure('zasp_production_security_agent_existing_tests_global_set(text,text,boolean,bigint,text,text)') IS NULL AND to_regclass('zasp_security_agent_global_control_receipts') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_security_agent_global_operator') AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE audit_id=$3) AND (SELECT version=1 AND execution_enabled FROM zasp_security_agent_kill_switches`+globalRaceRow+`)`, migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint(), globalRaceID(71)).Scan(&exact); err != nil || !exact {
			t.Fatalf("rollback-first exact54/absent-use result: %t %v", exact, err)
		}
	})
}
