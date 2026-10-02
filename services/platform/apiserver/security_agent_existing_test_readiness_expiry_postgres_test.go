package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Removing (or moving before readiness) the wrapper's final expiry guard must
// fail this acceptance: execution cannot commit after its captured authority
// expires while the final readiness call is blocked, even with a cleared lease.
func TestSecurityAgentExistingTestFinalReadinessExpiryPostgres(t *testing.T) {
	t.Setenv("ZASP_EXISTING_TEST_LEGACY_EXECUTION", "true")
	for _, mode := range []string{"lease", "approval"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ZASP_EXISTING_TEST_FINAL_READINESS_EXPIRY", mode)
			TestProductionSecurityAgentBudgetStopsNewPreparationAndDispatch(t)
		})
	}
}

func assertExistingTestFinalReadinessExpiry(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, claim SecurityAgentRunClaim, workerID, lease, mode string) {
	t.Helper()
	const readinessSignature = "zasp_production_security_agent_existing_tests_readiness(text,text)"
	const executionSignature = "zasp_production_security_agent_existing_tests_execute_run(text,text,text,text,text,text,text,text,text,text)"
	var readiness, execution string
	if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure),pg_get_functiondef($2::regprocedure)`, readinessSignature, executionSignature).Scan(&readiness, &execution); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, definition := range []string{execution, readiness} {
			if _, err := owner.Exec(ctx, definition); err != nil {
				t.Errorf("restore owned timing instrumentation: %v", err)
			}
		}
		var restored bool
		if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_client_ready($1,$2)`, existingTestReadPins(nil)...).Scan(&restored); err != nil || !restored {
			t.Errorf("restored release readiness: ready=%t err=%v", restored, err)
		}
	}()

	// RED control mutates only the installed owned-database function. Source SQL,
	// compiled release pins, grants, and all execution writes stay unchanged.
	if os.Getenv("ZASP_EXISTING_TEST_FINAL_READINESS_CONTROL") == "without_final_guard" {
		const guard = " IF result_value->>'state'<>'needs_human' AND (deadline_value IS NULL OR deadline_value<=clock_timestamp()) THEN\n  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test execution authority expired';\n END IF;"
		if strings.Count(execution, guard) != 1 {
			t.Fatal("installed final expiry guard did not match the bounded RED mutation")
		}
		if _, err := owner.Exec(ctx, strings.Replace(execution, guard, "", 1)); err != nil {
			t.Fatal(err)
		}
	}

	// Timing instrumentation, not release-integrity proof. Readiness is replaced
	// only in this owned fixture because its genuine body has no deterministic
	// wait point. The hook never writes execution data. Its advisory wait can be
	// reached only after the actual dispatcher writes and clears its lease.
	var hook string
	if err := owner.QueryRow(ctx, `SELECT format($ddl$
CREATE OR REPLACE FUNCTION zasp_production_security_agent_existing_tests_readiness(expected_checksum text,expected_fingerprint text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $hook$
BEGIN
 IF EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=%1$L AND state='running') THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs r
   JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id)
   JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id)
   JOIN zasp_security_agent_audit a USING(organization_id,workspace_id,environment_id,run_id,step_id)
   WHERE r.run_id=%1$L AND r.state='running' AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL
    AND s.state='executing' AND f.action_key='create_temporary_policy' AND f.state='pending'
    AND a.audit_id='pid_89f00e00-0000-4000-8000-00000000000e' AND a.event_kind='effect_dispatched') THEN
   RAISE EXCEPTION 'final readiness reached without actual dispatch effects and cleared lease';
  END IF;
  PERFORM pg_advisory_xact_lock(895533::bigint);
 END IF;
 RETURN true;
END $hook$;
$ddl$,$1::text)`, claim.RunID).Scan(&hook); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, hook); err != nil {
		t.Fatal(err)
	}
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock(895533::bigint)`); err != nil {
		t.Fatal(err)
	}

	query := `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '4 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
	if mode == "approval" {
		query = `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()+interval '4 seconds' WHERE run_id=$1 RETURNING expires_at`
	}
	var deadline time.Time
	if err := owner.QueryRow(ctx, query, claim.RunID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		return existingTestDispatchSnapshot(t, ctx, owner, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID) + existingTestAcceptanceSnapshot(t, ctx, owner, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID)
	}
	before := snapshot()
	executeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		var raw json.RawMessage
		args := existingTestReadPins([]any{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, lease, "pid_89f00e00-0000-4000-8000-00000000000e", "pid_89f00f00-0000-4000-8000-00000000000f"})
		done <- worker.QueryRow(executeCtx, postgresSecurityAgentExistingTestExecuteSQL, args...).Scan(&raw)
	}()
	joined := false
	defer func() {
		cancel()
		if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock(895533::bigint)`); err != nil {
			t.Errorf("release final-readiness blocker: %v", err)
		}
		if !joined {
			<-done
		}
	}()
	for {
		var observed, expired bool
		if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))
 AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=0 AND objid=895533 AND objsubid=1 AND NOT granted),clock_timestamp()>=$2::timestamptz`, worker.PgConn().PID(), deadline).Scan(&observed, &expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			t.Fatal("final-readiness advisory waiter was not observed before authority expiry")
		}
		if observed {
			t.Logf("observed final-readiness waiter after effect, audit, executing step and cleared lease; %s deadline=%s", mode, deadline.Format(time.RFC3339Nano))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		var expired bool
		if err := blocker.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock(895533::bigint)`); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "40001" || pg.Message != "existing test execution authority expired" {
		t.Fatalf("final-readiness %s expiry did not roll back: %v", mode, err)
	}
	if before != snapshot() {
		t.Fatal("expired final readiness left durable effects")
	}
	t.Logf("database clock passed %s deadline; exact 40001 expiry and unchanged durable snapshot verified", mode)
}
