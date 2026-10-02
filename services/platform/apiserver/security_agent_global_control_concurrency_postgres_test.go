package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const globalRaceRow = ` WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*')`

func globalRaceID(n int) string { return fmt.Sprintf("pid_7f570000-0000-4000-8000-%012d", n) }

func globalRaceConnect(t *testing.T, ctx context.Context, owner *pgx.Conn, user string) *pgx.Conn {
	t.Helper()
	cfg := owner.Config().Copy()
	if user != "" {
		cfg.User = user
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func globalRaceSet(t *testing.T, ctx context.Context, conn *pgx.Conn, enabled bool, version int64, n int) {
	t.Helper()
	var raw json.RawMessage
	err := conn.QueryRow(ctx, globalControlSetSQL, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint(), enabled, version, globalRaceID(n), fmt.Sprintf("global-race-%d", n)).Scan(&raw)
	want := fmt.Sprintf(`{"enabled":%t,"version":%d,"replayed":false}`, enabled, version+1)
	if err != nil || !equalIntegrationJSON(raw, json.RawMessage(want)) {
		t.Fatalf("operator transition: %s %v", raw, err)
	}
}

func globalRaceReady(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	var ready bool
	err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_readiness($1,$2)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_global_control_receipts r LEFT JOIN zasp_security_agent_audit a ON (a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=('*','*','*',r.request_id) WHERE a.audit_id IS NULL OR a.actor_id<>r.caller_session OR a.correlation_id<>r.correlation_id OR a.body<>zasp_production_security_agent_existing_tests_global_intent(r) OR a.event_digest<>digest(convert_to(a.body::text,'UTF8'),'sha256'))
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit a LEFT JOIN zasp_security_agent_global_control_receipts r ON r.request_id=a.audit_id WHERE a.organization_id='*' AND r.request_id IS NULL)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_global_control_receipts r WHERE r.resulting_version=(SELECT max(resulting_version) FROM zasp_security_agent_global_control_receipts) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.action_key)=('*','*','*','*') AND c.version=r.resulting_version AND c.execution_enabled=r.enabled))`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready)
	if err != nil || !ready {
		t.Fatalf("exact55 identity after wait: %t %v", ready, err)
	}
}

// The blocker owns only the exact global tuple. Polling proves the caller's
// transaction-ID wait and its control-table row lock, never elapsed time alone.
func globalRaceWait(t *testing.T, ctx context.Context, observer, blocker, caller *pgx.Conn, call func() error, release func()) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- call() }()
	joined := false
	defer func() {
		if !joined {
			blocker.Exec(context.Background(), "ROLLBACK")
			<-done
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-done:
			joined = true
			t.Fatalf("caller returned before observed global row wait: %v", err)
		default:
		}
		var waiting bool
		err := observer.QueryRow(ctx, `SELECT $2::int=ANY(pg_blocking_pids($1::int)) AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='transactionid' AND NOT granted) AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.zasp_security_agent_kill_switches'::regclass AND mode='RowShareLock' AND granted)`, caller.PgConn().PID(), blocker.PgConn().PID()).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			t.Logf("observed global tuple wait caller=%d blocker=%d", caller.PgConn().PID(), blocker.PgConn().PID())
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("global tuple wait not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	release()
	err := <-done
	joined = true
	return err
}

func globalRaceRefused(t *testing.T, err error, code string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code {
		t.Fatalf("want SQLSTATE %s, got %v", code, err)
	}
}

type globalRaceWork struct{ o, w, e, actor, definition, run, finding, testID string }

// Only target inventory/provenance is controlled fixture input. Definitions,
// runs, approval, budgets, reservations, links and leases use public entrypoints.
func globalRaceDraft(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) globalRaceWork {
	t.Helper()
	f := globalRaceWork{o: o, w: w, e: e, actor: actor, definition: globalRaceID(1), run: globalRaceID(2), finding: globalRaceID(3), testID: testID}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Global stop fixture','high','open')`, o, w, e, f.finding); err != nil {
		t.Fatal(err)
	}
	lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, "run_test", 1)
	createExistingTestLifecycleDraft(t, ctx, api, o, w, e, f.definition, testID, actor, "run_test")
	lifecycleActivateDraft(t, ctx, api, o, w, e, f.definition, actor, 1)
	return f
}

func (f globalRaceWork) admit(ctx context.Context, api *pgx.Conn) error {
	var raw json.RawMessage
	err := api.QueryRow(ctx, postgresExistingTestRunSQL, f.o, f.w, f.e, f.definition, f.actor, "global-race-admit", int64(3), f.run, "finding", f.finding, globalRaceID(4), globalRaceID(5), globalRaceID(6), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
	if err != nil {
		return err
	}
	var run SecurityAgentRunResult
	if json.Unmarshal(raw, &run) != nil || run.ID != f.run || run.State != "queued" || run.Replayed {
		return fmt.Errorf("unexpected public admission: %s", raw)
	}
	return nil
}

func globalRaceSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn) string {
	t.Helper()
	// Whole disposable fixture tables include orphan receipts, budgets and outbox
	// entries as well as linked state. Exclude only the operator's own audit rows.
	var snapshot string
	err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'runs',(SELECT jsonb_agg(to_jsonb(x) ORDER BY run_id) FROM zasp_security_agent_runs x),
 'budgets',(SELECT jsonb_agg(to_jsonb(x) ORDER BY run_id) FROM zasp_security_agent_run_budgets x),
 'admissions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY organization_id) FROM zasp_security_agent_org_admissions x),
 'execution_state',(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_execution_state x),
 'triggers',(SELECT jsonb_agg(to_jsonb(x) ORDER BY run_id) FROM zasp_security_agent_trigger_receipts x),
 'receipts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY receipt_id) FROM zasp_security_agent_request_receipts x),
 'audit',(SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE organization_id<>'*'),
 'approvals',(SELECT jsonb_agg(to_jsonb(x) ORDER BY approval_id) FROM zasp_security_agent_approvals x),
 'steps',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x),
 'reservations',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_step_reservations x),
 'effects',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x),
 'links',(SELECT jsonb_agg(to_jsonb(x) ORDER BY test_run_id) FROM zasp_security_agent_test_links x),
 'test_runs',(SELECT jsonb_agg(to_jsonb(x) ORDER BY run_id) FROM zasp_red_team_runs x),
 'test_receipts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY receipt_id) FROM zasp_red_team_request_receipts x),
 'outbox',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM zasp_red_team_outbox x),
 'invocations',(SELECT jsonb_agg(to_jsonb(x) ORDER BY test_run_id,category) FROM zasp_security_agent_test_invocations x))::text`).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// Missing/released-too-early global authority locks would let this public run
// create a receipt, budget or queue row after the stop transaction commits.
func TestSecurityAgentGlobalControlAdmissionBarrierPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		f := globalRaceDraft(t, ctx, owner, api, o, w, e, testID, actor)
		before := globalRaceSnapshot(t, ctx, owner)
		stop := globalRaceConnect(t, ctx, owner, "")
		if _, err := stop.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer stop.Exec(context.Background(), "ROLLBACK")
		globalRaceSet(t, ctx, stop, false, 1, 10)
		err := globalRaceWait(t, ctx, owner, stop, api, func() error { return f.admit(ctx, api) }, func() {
			if _, err := stop.Exec(ctx, "COMMIT"); err != nil {
				t.Fatal(err)
			}
		})
		globalRaceRefused(t, err, "55000")
		if before != globalRaceSnapshot(t, ctx, owner) {
			t.Fatal("post-stop admission changed durable tenant authority")
		}
		globalRaceReady(t, ctx, owner)
		globalRaceSet(t, ctx, owner, true, 2, 11)
		if err := f.admit(ctx, api); err != nil {
			t.Fatalf("re-enabled public admission: %v", err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,state)=($4,$5,$6,$1,$2,'queued')) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id)=($4,$5,$6,$1,$2)) AND (SELECT count(*)=1 FROM zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,resource_id,operation,receipt_id)=($4,$5,$6,$7,$2,'runSecurityAgent',$3) AND response->>'id'=$1)`, f.run, f.definition, globalRaceID(6), o, w, e, actor).Scan(&exact); err != nil || !exact {
			t.Fatalf("public admission lost durable associations: %t %v", exact, err)
		}
	})
}

func globalRaceDispatch(t *testing.T, ctx context.Context, owner, api, worker *pgx.Conn, f globalRaceWork) (string, string) {
	t.Helper()
	if err := f.admit(ctx, api); err != nil {
		t.Fatal(err)
	}
	lifecyclePrepareAdmitted(t, ctx, worker, f.o, f.w, f.e, f.run, f.testID, "run_test")
	var approval, step string
	if err := owner.QueryRow(ctx, `SELECT approval_id,step_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND state='pending'`, f.run).Scan(&approval, &step); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_decide_approval($1,$2,$3,$4,$5,$6,1,'approved',clock_timestamp(),$7,$8,$9,$10,$11)`, f.o, f.w, f.e, approval, globalRaceID(20), "global-race-approve", globalRaceID(21), globalRaceID(22), globalRaceID(23), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, "global-race-worker", "global-race-dispatch-lease", 120, 1).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Items []SecurityAgentRunClaim `json:"items"`
	}
	if json.Unmarshal(raw, &claims) != nil || len(claims.Items) != 1 || claims.Items[0].RunID != f.run || !claims.Items[0].Prepared {
		t.Fatalf("public prepared claim: %s", raw)
	}
	if err := worker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.o, f.w, f.e, f.run, "global-race-worker", "global-race-dispatch-lease", globalRaceID(24), globalRaceID(25), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var testRun string
	if err := owner.QueryRow(ctx, `SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1 AND step_id=$2`, f.run, step).Scan(&testRun); err != nil {
		t.Fatal(err)
	}
	return testRun, step
}

func globalRaceProvenance(t *testing.T, ctx context.Context, owner *pgx.Conn, f globalRaceWork) {
	t.Helper()
	seedExistingTestSimulationEvidence(t, ctx, owner, f.o, f.w, f.e, f.actor)
	if _, err := owner.Exec(ctx, `UPDATE zasp_discovery_snapshots SET state='complete',complete=true,is_last_good=true,apply_result='{}',committed_at=clock_timestamp() WHERE id='pid_89e23800-0000-4000-8000-000000000003';
 UPDATE zasp_inventory_evidence SET source='kubernetes',generation=1 WHERE id='pid_89e23800-0000-4000-8000-000000000004';
 UPDATE zasp_inventory_entities SET winning_integration_id='pid_89e23800-0000-4000-8000-000000000001',winning_snapshot_id='pid_89e23800-0000-4000-8000-000000000003',winning_evidence_id='pid_89e23800-0000-4000-8000-000000000004',winning_provider='kubernetes',winning_source='kubernetes',winning_source_native_id='invocation-agent',winning_generation=1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_89000011-0000-4000-8000-000000000001');
 INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000001','kubernetes','pid_89000011-0000-4000-8000-000000000001','invocation-agent','pid_89e23800-0000-4000-8000-000000000003','present','{}',clock_timestamp(),clock_timestamp(),'kubernetes','kubernetes_agent','Invocation target','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),'pid_89e23800-0000-4000-8000-000000000004',9500,clock_timestamp(),clock_timestamp()+interval '1 hour',1,80,1)`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e); err != nil {
		t.Fatal(err)
	}
}

// The started journal is the authorization boundary. A committed start can
// initiate I/O later; global stop is not external cancellation.
func TestSecurityAgentGlobalControlInvocationBarrierPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		f := globalRaceDraft(t, ctx, owner, api, o, w, e, testID, actor)
		globalRaceProvenance(t, ctx, owner, f)
		worker := globalRaceConnect(t, ctx, owner, "security_agent_v33_worker_login")
		testRun, _ := globalRaceDispatch(t, ctx, owner, api, worker, f)
		if _, err := owner.Exec(ctx, `CREATE ROLE global_race_red_worker LOGIN INHERIT; CREATE ROLE global_race_red_outbox LOGIN INHERIT; CREATE ROLE global_race_red_adapter LOGIN INHERIT; SELECT zasp_red_team_register_principals(session_user,'global_race_red_worker','global_race_red_outbox','global_race_red_adapter')`); err != nil {
			t.Fatal(err)
		}
		redWorker := globalRaceConnect(t, ctx, owner, "global_race_red_worker")
		adapter := globalRaceConnect(t, ctx, owner, "global_race_red_adapter")
		var raw json.RawMessage
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		if err := redWorker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_worker_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)`, o, w, e, testRun, "global-race-red-worker", []byte(strings.Repeat("a", 32)), 120, pins[0], pins[1]).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		start := func() error {
			return adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,'prompt_injection',decode(repeat('ab',32),'hex'),$6,$7)`, o, w, e, testRun, []byte(strings.Repeat("a", 32)), pins[0], pins[1]).Scan(&raw)
		}
		before := globalRaceSnapshot(t, ctx, owner)
		stop := globalRaceConnect(t, ctx, owner, "")
		if _, err := stop.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer stop.Exec(context.Background(), "ROLLBACK")
		globalRaceSet(t, ctx, stop, false, 1, 30)
		err := globalRaceWait(t, ctx, owner, stop, adapter, start, func() {
			if _, err := stop.Exec(ctx, "COMMIT"); err != nil {
				t.Fatal(err)
			}
		})
		globalRaceRefused(t, err, "40001")
		if before != globalRaceSnapshot(t, ctx, owner) {
			t.Fatal("post-stop invocation changed durable authority")
		}
		globalRaceReady(t, ctx, owner)
		globalRaceSet(t, ctx, owner, true, 2, 31)
		if err := start(); err != nil {
			t.Fatalf("re-enabled invocation: %v", err)
		}
		var result struct {
			State   string `json:"state"`
			Attempt int    `json:"attempt"`
		}
		if json.Unmarshal(raw, &result) != nil || result.State != "started" || result.Attempt != 1 {
			t.Fatalf("committed start: %s", raw)
		}
		committed := globalRaceSnapshot(t, ctx, owner)
		globalRaceSet(t, ctx, owner, false, 3, 32)
		if committed != globalRaceSnapshot(t, ctx, owner) {
			t.Fatal("stop rewrote pre-stop invocation authorization")
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT i.state='started' AND i.started_at IS NOT NULL AND NOT r.cancel_requested AND i.attempt=r.attempt AND i.request_digest=decode(repeat('ab',32),'hex') FROM zasp_security_agent_test_invocations i JOIN zasp_red_team_runs r ON (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(i.organization_id,i.workspace_id,i.environment_id,i.test_run_id) WHERE i.test_run_id=$1`, testRun).Scan(&exact); err != nil || !exact {
			t.Fatalf("committed-before-stop boundary lost: %t %v", exact, err)
		}
		globalRaceRefused(t, start(), "40001")
		if committed != globalRaceSnapshot(t, ctx, owner) {
			t.Fatal("disabled retry changed committed invocation history")
		}
		t.Log("committed-before-stop start retained; later external I/O is allowed, not exercised by this database fixture")
	})
}

// A principal check only before FOR UPDATE would miss this binding deletion.
func TestSecurityAgentGlobalControlBindingLostDuringWaitPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		caller := globalRaceConnect(t, ctx, owner, "")
		blocker := globalRaceConnect(t, ctx, owner, "")
		var binding json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(b) FROM zasp_discovery_principal_bindings b WHERE principal_name=session_user AND authority_role='zasp_discovery_authority'`).Scan(&binding); err != nil {
			t.Fatal(err)
		}
		restore := func() {
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_discovery_principal_bindings SELECT * FROM jsonb_populate_record(NULL::zasp_discovery_principal_bindings,$1::jsonb) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role,registered_at=excluded.registered_at`, binding); err != nil {
				t.Fatal(err)
			}
		}
		defer restore()
		before := globalControlSnapshot(t, ctx, owner)
		if _, err := blocker.Exec(ctx, `BEGIN; SELECT 1 FROM zasp_security_agent_kill_switches`+globalRaceRow+` FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		defer blocker.Exec(context.Background(), "ROLLBACK")
		var raw json.RawMessage
		call := func() error {
			return caller.QueryRow(ctx, globalControlSetSQL, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint(), false, int64(1), globalRaceID(40), "binding-lost-during-wait").Scan(&raw)
		}
		err := globalRaceWait(t, ctx, owner, blocker, caller, call, func() {
			if _, err := owner.Exec(ctx, `DELETE FROM zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority'`); err != nil {
				t.Fatal(err)
			}
			if _, err := blocker.Exec(ctx, "COMMIT"); err != nil {
				t.Fatal(err)
			}
		})
		globalRaceRefused(t, err, "42501")
		if !equalIntegrationJSON(before, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("revoked waiting operator changed control, receipt or audit")
		}
		restore()
		globalRaceReady(t, ctx, owner)
		if err := call(); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":false,"version":2,"replayed":false}`)) {
			t.Fatalf("restored binding positive control: %s %v", raw, err)
		}
	})
}

// Stop/re-enable cannot clear a hold or alter tenant/environment/action controls.
func TestSecurityAgentGlobalControlRecoveryHoldPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, "run_test", 1)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state,held_at) VALUES($1,$2,$3,1,$4,'held',clock_timestamp())`, o, w, e, globalRaceID(50)); err != nil {
			t.Fatal(err)
		}
		snapshot := func() string {
			var raw string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('controls',(SELECT jsonb_agg(to_jsonb(c) ORDER BY action_key) FROM zasp_security_agent_kill_switches c WHERE organization_id<>'*'),'holds',(SELECT jsonb_agg(to_jsonb(h) ORDER BY organization_id,workspace_id,environment_id) FROM zasp_recovery_holds h))::text`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		before, beforeTenant := snapshot(), globalRaceSnapshot(t, ctx, owner)
		var raw json.RawMessage
		mutate := func() error {
			return api.QueryRow(ctx, lifecycleSetControlSQL, o, w, e, actor, "held-action-disable", "action", "run_test", false, int64(1), time.Now().UTC().Add(4*time.Minute), globalRaceID(51), globalRaceID(52), globalRaceID(53), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
		}
		for phase := 0; phase < 3; phase++ {
			if phase == 1 {
				globalRaceSet(t, ctx, owner, false, 1, 54)
			}
			if phase == 2 {
				globalRaceSet(t, ctx, owner, true, 2, 55)
			}
			globalRaceRefused(t, mutate(), "55000")
			if snapshot() != before || globalRaceSnapshot(t, ctx, owner) != beforeTenant {
				t.Fatalf("phase %d changed held tenant state or control/hold", phase)
			}
		}
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_recovery_holds WHERE (organization_id,workspace_id,environment_id,operation_id)=($1,$2,$3,$4)`, o, w, e, globalRaceID(50)); err != nil {
			t.Fatal(err)
		}
		if err := mutate(); err != nil {
			t.Fatalf("released hold same-scope mutation: %v", err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT NOT execution_enabled AND version=2 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'run_test')) AND (SELECT count(*)=1 FROM zasp_security_agent_request_receipts WHERE receipt_id=$4) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE audit_id=$5)`, o, w, e, globalRaceID(53), globalRaceID(51)).Scan(&exact); err != nil || !exact {
			t.Fatalf("released hold mutation not durable: %t %v", exact, err)
		}
		globalRaceReady(t, ctx, owner)
	})
}

// A stop must block new execution without blocking cancellation, reconciliation
// or the registered API's scoped retained-history reads.
func TestSecurityAgentGlobalControlDisabledHistoryPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		f := globalRaceDraft(t, ctx, owner, api, o, w, e, testID, actor)
		worker := globalRaceConnect(t, ctx, owner, "security_agent_v33_worker_login")
		testRun, step := globalRaceDispatch(t, ctx, owner, api, worker, f)
		before := globalRaceSnapshot(t, ctx, owner)
		globalRaceSet(t, ctx, owner, false, 1, 60)
		if before != globalRaceSnapshot(t, ctx, owner) {
			t.Fatal("stop changed queued approved work")
		}
		read := func() {
			t.Helper()
			before := globalRaceSnapshot(t, ctx, owner)
			var raw json.RawMessage
			args := existingTestReadPins([]any{o, w, e, f.run})
			if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSecurityAgentRunContextEnvelope(raw, f.run); err != nil {
				t.Fatalf("disabled history consumer: %v", err)
			}
			for i := 0; i < 3; i++ {
				bad := append([]any(nil), args...)
				bad[i] = globalRaceID(99)
				if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, bad...).Scan(&raw); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("foreign history scope %d: %s %v", i, raw, err)
				}
			}
			if before != globalRaceSnapshot(t, ctx, owner) {
				t.Fatal("history read changed authority")
			}
		}
		read()
		var version int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, f.run).Scan(&version); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		// The inherited parent endpoint cannot cancel a dispatched effect. Keep
		// its refusal; use the public linked-test endpoint for the queued child.
		globalRaceRefused(t, api.QueryRow(ctx, postgresSecurityAgentCancelRunSQL, o, w, e, f.run, actor, "global-disabled-cancel", version, globalRaceID(61), globalRaceID(62), globalRaceID(63)).Scan(&raw), "40001")
		if before != globalRaceSnapshot(t, ctx, owner) {
			t.Fatal("unsupported parent cancellation changed dispatched state")
		}
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_red_team_runs WHERE run_id=$1`, testRun).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, postgresRedTeamCancelRunSQL, o, w, e, actor, "global-disabled-child-cancel", testRun, version, globalRaceID(62)).Scan(&raw); err != nil {
			t.Fatalf("public child cancellation while disabled: %v", err)
		}
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		token := []byte(strings.Repeat("r", 32))
		if err := worker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,$4,$5,60,1,$6,$7)`, o, w, e, "global-disabled-reconciler", token, pins[0], pins[1]).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var claims []struct {
			Run        string `json:"run_id"`
			Step       string `json:"step_id"`
			Version    int64  `json:"version"`
			Generation string `json:"generation"`
		}
		if json.Unmarshal(raw, &claims) != nil || len(claims) != 1 || claims[0].Run != f.run || claims[0].Step != step {
			t.Fatalf("disabled reconcile claim: %s", raw)
		}
		guard := []any{o, w, e, f.run, step, "global-disabled-reconciler", token, claims[0].Version, claims[0].Generation, pins[0], pins[1]}
		if err := worker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, guard...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, guard...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var evidence struct {
			Snapshot json.RawMessage `json:"snapshot"`
		}
		if json.Unmarshal(raw, &evidence) != nil || len(evidence.Snapshot) == 0 {
			t.Fatalf("disabled evidence: %s", raw)
		}
		proof := []byte(`{"schema_version":"security-agent-test-verification-v1","outcome":"cancelled","reason":"test_run_cancelled"}`)
		settle := append(append([]any(nil), guard[:9]...), string(evidence.Snapshot), proof, pins[0], pins[1])
		const query = `SELECT zasp_production_security_agent_existing_tests_reconcile_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`
		if err := worker.QueryRow(ctx, query, settle...).Scan(&raw); err != nil {
			t.Fatalf("disabled reconciliation settlement: %v", err)
		}
		settled := globalRaceSnapshot(t, ctx, owner)
		if err := worker.QueryRow(ctx, query, settle...).Scan(&raw); err != nil || settled != globalRaceSnapshot(t, ctx, owner) {
			t.Fatalf("disabled settlement replay: %v", err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT r.state='cancelled' AND s.state='cancelled' AND t.state='cancelled' AND t.cancel_requested AND l.reconcile_state='settled' AND l.cancellation_outcome='cancelled_before_execution' AND l.reconcile_settlement->'receipt'->>'outcome'='cancelled' AND x.state='known_failure' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$3) AND (SELECT count(*)=1 FROM zasp_red_team_request_receipts WHERE (organization_id,workspace_id,environment_id,resource_id,operation)=(r.organization_id,r.workspace_id,r.environment_id,$3,'cancelTestRun')) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='test_reconciled') FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_effects x USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE r.run_id=$1 AND s.step_id=$2`, f.run, step, testRun).Scan(&exact); err != nil || !exact {
			t.Fatalf("disabled cancellation/settlement durability: %t %v", exact, err)
		}
		read()
		globalRaceReady(t, ctx, owner)
	})
}

func TestSecurityAgentGlobalControlDisabledQueuedCancellationPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		f := globalRaceDraft(t, ctx, owner, api, o, w, e, testID, actor)
		if err := f.admit(ctx, api); err != nil {
			t.Fatal(err)
		}
		globalRaceSet(t, ctx, owner, false, 1, 80)
		var raw json.RawMessage
		args := []any{o, w, e, f.run, actor, "global-disabled-queued-cancel", int64(1), globalRaceID(81), globalRaceID(82), globalRaceID(83)}
		if err := api.QueryRow(ctx, postgresSecurityAgentCancelRunSQL, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var result SecurityAgentRunResult
		if json.Unmarshal(raw, &result) != nil || result.ID != f.run || result.State != "cancelled" || result.Version != 2 || result.Replayed {
			t.Fatalf("disabled queued cancellation: %s", raw)
		}
		before := globalRaceSnapshot(t, ctx, owner)
		if err := api.QueryRow(ctx, postgresSecurityAgentCancelRunSQL, args...).Scan(&raw); err != nil || json.Unmarshal(raw, &result) != nil || !result.Replayed || before != globalRaceSnapshot(t, ctx, owner) {
			t.Fatalf("disabled queued cancellation replay: %s %v", raw, err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT state='cancelled' AND version=2 AND completed_at IS NOT NULL FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) AND (SELECT count(*)=1 FROM zasp_security_agent_request_receipts WHERE receipt_id=$5 AND resource_id=$4 AND operation='cancelSecurityAgentRun') AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE audit_id=$6 AND run_id=$4 AND event_kind='run_cancelled') AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links)`, o, w, e, f.run, globalRaceID(83), globalRaceID(81)).Scan(&exact); err != nil || !exact {
			t.Fatalf("disabled cancellation durable association: %t %v", exact, err)
		}
		globalRaceReady(t, ctx, owner)
	})
}
