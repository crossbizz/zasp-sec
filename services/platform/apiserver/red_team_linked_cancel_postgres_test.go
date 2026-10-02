package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentExistingTestCancellationPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true, false, false, false, true, false, true)
}

func TestSecurityAgentExistingTestStoppedLeasedPostgres(t *testing.T) {
	t.Setenv("ZASP_RECONCILE_STOPPED_LEASED", "true")
	TestSecurityAgentExistingTestCancellationPostgres(t)
}

func TestSecurityAgentExistingTestComposedStoppedPostgres(t *testing.T) {
	if os.Getenv("ZASP_RECONCILE_CLIENT_BINARY") == "" {
		t.Fatal("requires registered worker binary")
	}
	t.Setenv("ZASP_RECONCILE_COMPOSE_STOPPED", "true")
	TestSecurityAgentExistingTestStoppedLeasedPostgres(t)
}

func exerciseLinkedRedTeamCancellation(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, scope domain.Scope, run string, mode int) {
	t.Helper()
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	checksum, fingerprint := migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()
	connect := func(role string) *pgx.Conn {
		config := owner.Config().Copy()
		config.User = role
		conn, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close(context.Background()) })
		return conn
	}
	adapter := connect("existing_test_red_adapter")
	api := connect("security_agent_v33_api_login")
	lease := []byte(strings.Repeat("b", 32))
	var raw json.RawMessage
	if mode >= 2 || mode == 0 {
		if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,'prompt_injection',decode(repeat('ab',32),'hex'),$6,$7)`, o, w, e, run, lease, checksum, fingerprint).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if mode == 2 {
			if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,3,$5,'prompt_injection',decode(repeat('ab',32),'hex'),200,decode(repeat('cd',32),'hex'),true,decode(repeat('dd',32),'hex'),$6,$7)`, o, w, e, run, lease, checksum, fingerprint).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	if mode == 1 {
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='queued',attempt=0,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,started_at=NULL WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run); err != nil {
			t.Fatal(err)
		}
	}
	var version int64
	var actor string
	var digest []byte
	if err := owner.QueryRow(ctx, `SELECT version,requested_by,input_digest FROM zasp_red_team_runs WHERE run_id=$1`, run).Scan(&version, &actor, &digest); err != nil {
		t.Fatal(err)
	}
	journal := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY attempt,category),'[]'::jsonb)::text FROM zasp_security_agent_test_invocations j WHERE test_run_id=$1`, run).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := journal()
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository := &PostgresRepository{database: db, schema: ProductionRecoverySchemaVersion}
	identity := fixtureRequestIdentity(t)
	identity.Scope = scope
	identity.PrincipalID, err = domain.ParseProductID(actor)
	if err != nil {
		t.Fatal(err)
	}
	const human = `SELECT zasp_red_team_cancel_run($1,$2,$3,$4,'linked-cancel-'||$5,$5,$6,'pid_99400006-0000-4000-8000-000000000006')`
	const cancelQuery = `SELECT zasp_production_security_agent_existing_tests_worker_cancel($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	reconcile := os.Getenv("ZASP_RECONCILE_STOPPED_LEASED") == "true"
	if reconcile {
		exerciseStoppedLinkedCancellation(t, ctx, owner, connect("security_agent_v33_worker_login"), o, w, e, run, mode)
	} else if mode < 2 {
		handler, err := NewRedTeamPublicHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		request := workflowRequest(t, identity, "pid_99400006-0000-4000-8000-000000000006", "cancelTestRun", map[string]string{"id": run}, http.MethodPost, "/api/v1/test-runs/"+run+"/cancel", "")
		request.Header.Set("Idempotency-Key", "linked-cancel-"+run)
		request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || mode == 0 && !strings.Contains(response.Body.String(), `"error_code":"outcome_unknown"`) {
			t.Fatalf("human linked cancellation HTTP: %d %s", response.Code, response.Body.String())
		}
	} else {
		args := []any{o, w, e, run, "existing-test-linked-worker", lease, digest, checksum, fingerprint}
		for _, conn := range []*pgx.Conn{owner, adapter, api} {
			err := conn.QueryRow(ctx, cancelQuery, args...).Scan(&raw)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("worker cancellation role refusal: %v", err)
			}
		}
		bad := append([]any(nil), args...)
		bad[5] = []byte(strings.Repeat("c", 32))
		err := worker.QueryRow(ctx, cancelQuery, bad...).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("foreign lease cancellation: %v", err)
		}
		// Worker finalization requires an actual cancellation request. This
		// fixture seeds only that request, not the resulting cancellation state.
		err = worker.QueryRow(ctx, cancelQuery, args...).Scan(&raw)
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("unrequested worker cancellation: %v", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		if mode == 2 {
			var original, deadline time.Time
			if err := owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_red_team_runs WHERE run_id=$1`, run).Scan(&original); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING lease_expires_at`, run).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			snapshot := func() string {
				var value string
				if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',to_jsonb(r),'link',to_jsonb(l))::text FROM zasp_red_team_runs r JOIN zasp_security_agent_test_links l ON l.test_run_id=r.run_id WHERE r.run_id=$1`, run).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			prior := snapshot()
			err := existingTestAcceptanceWait(t, ctx, owner, worker, run, "link_cancel_lease", func() error { return worker.QueryRow(ctx, cancelQuery, args...).Scan(&raw) }, deadline)
			after := snapshot()
			if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=$2 WHERE run_id=$1`, run, original); err != nil {
				t.Fatal(err)
			}
			if !errors.As(err, &pg) || pg.Code != "40001" || prior != after {
				t.Fatalf("cancel crossed old lease: err=%v unchanged=%t", err, prior == after)
			}
		}
		workerDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		linkedRepository, err := NewLinkedRedTeamExecutionRepository(workerDB)
		if err != nil {
			t.Fatal(err)
		}
		var inputDigest [sha256.Size]byte
		copy(inputDigest[:], digest)
		if result, err := linkedRepository.CancelLinkedRedTeamRun(ctx, scope, run, "existing-test-linked-worker", string(lease), inputDigest); err != nil || !result.CancelRequested || mode == 3 && (result.Status != "failed" || result.ErrorCode != "outcome_unknown") {
			t.Fatalf("worker linked cancellation client: %#v %v", result, err)
		}
	}
	state, code, outcome := "cancelled", "cancelled", "cancelled_before_execution"
	if mode == 2 {
		outcome = "cancelled_after_partial_execution"
	}
	if mode == 3 || mode == 0 {
		state, code, outcome = "failed", "outcome_unknown", "outcome_unknown"
	}
	var actualState, actualCode string
	var actualOutcome *string
	var stopped bool
	if err := owner.QueryRow(ctx, `SELECT r.state,r.error_code,to_jsonb(l)->>'cancellation_outcome',r.cancel_requested AND r.lease_token IS NULL AND r.worker_id IS NULL AND r.lease_expires_at IS NULL AND r.completed_at IS NOT NULL FROM zasp_red_team_runs r JOIN zasp_security_agent_test_links l ON (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) WHERE r.run_id=$1`, run).Scan(&actualState, &actualCode, &actualOutcome, &stopped); err != nil || actualOutcome == nil || actualState != state || actualCode != code || *actualOutcome != outcome || !stopped {
		t.Fatalf("cancellation classification mode%d: state=%s code=%s outcome=%v stopped=%t err=%v", mode, actualState, actualCode, actualOutcome, stopped, err)
	}
	if before != journal() {
		t.Fatal("cancellation rewrote invocation history")
	}
	if result, err := repository.GetRedTeamRun(ctx, identity, run); err != nil || result.Status != state || result.ErrorCode != code || !result.CancelRequested {
		t.Fatalf("registered repository cancellation read: %#v %v", result, err)
	}
	if mode == 1 {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, updateErr := tx.Exec(ctx, `UPDATE zasp_security_agent_test_links SET cancellation_outcome=NULL WHERE test_run_id=$1`, run)
		_ = tx.Rollback(ctx)
		var pg *pgconn.PgError
		if !errors.As(updateErr, &pg) || pg.Code != "23514" {
			t.Fatalf("cancellation receipt accepted a missing outcome: %v", updateErr)
		}
	}
	if mode < 2 && !reconcile {
		var auditsBefore, auditsAfter int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_audit`).Scan(&auditsBefore); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, human, o, w, e, actor, run, version).Scan(&raw); err != nil {
			t.Fatalf("cancel replay: %v", err)
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_red_team_audit`).Scan(&auditsAfter); err != nil || auditsBefore != auditsAfter || !strings.Contains(string(raw), `"replayed": true`) {
			t.Fatalf("cancel replay changed audit: %s %v", raw, err)
		}
	}
	if mode == 3 {
		// A late known response can be recorded, but cannot erase the cancellation
		// decision's uncertainty or authorize any new request.
		var settledBefore string
		if os.Getenv("ZASP_RECONCILE_COMPOSE_STOPPED") == "true" {
			if err := owner.QueryRow(ctx, `SELECT reconcile_settlement::text FROM zasp_security_agent_test_links WHERE test_run_id=$1`, run).Scan(&settledBefore); err != nil {
				t.Fatal(err)
			}
		}
		if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,3,$5,'prompt_injection',decode(repeat('ab',32),'hex'),200,decode(repeat('cd',32),'hex'),true,decode(repeat('dd',32),'hex'),$6,$7)`, o, w, e, run, lease, checksum, fingerprint).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT cancellation_outcome FROM zasp_security_agent_test_links WHERE test_run_id=$1`, run).Scan(&actualOutcome); err != nil || actualOutcome == nil || *actualOutcome != "outcome_unknown" {
			t.Fatal("late response erased uncertainty")
		}
		if settledBefore != "" {
			var settledAfter string
			if err := owner.QueryRow(ctx, `SELECT reconcile_settlement::text FROM zasp_security_agent_test_links WHERE test_run_id=$1`, run).Scan(&settledAfter); err != nil || settledBefore != settledAfter {
				t.Fatalf("late observation changed immutable settlement: %v", err)
			}
		}
	}
	err = adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,'prompt_injection',decode(repeat('ab',32),'hex'),$6,$7)`, o, w, e, run, lease, checksum, fingerprint).Scan(&raw)
	if err == nil {
		t.Fatal("cancelled linked run admitted a new request")
	}
}

// Reuses real invocation start/completion fixtures. The owner controls only the
// parent stop and deadline; cancellation itself runs under registered authority.
func exerciseStoppedLinkedCancellation(t *testing.T, ctx context.Context, owner, reconciler *pgx.Conn, o, w, e, testRun string, mode int) {
	t.Helper()
	if mode == 1 {
		// The separate stopped-queued batch covers attempt zero. Here a failed
		// attempt is scheduled for retry, without any recorded target invocation.
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='retryable',attempt=1,started_at=queued_at,error_code='retryable',next_attempt_at=clock_timestamp()+interval '1 hour' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, testRun); err != nil {
			t.Fatal(err)
		}
	}
	stopped := []string{"cancelled", "failed", "inconclusive", "needs_human"}[mode]
	var run, step string
	if err := owner.QueryRow(ctx, `SELECT run_id,step_id FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4)`, o, w, e, testRun).Scan(&run, &step); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state=$5,completed_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run, stopped); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_RECONCILE_COMPOSE_STOPPED") == "true" {
		state := "leased"
		if mode == 1 {
			state = "retryable"
		}
		runExistingTestClientChild(t, ctx, owner, o, w, e, run, step, state, mode == 0 || mode == 3)
		outcome, reason, effect, stepState := "cancelled", "test_run_cancelled", "known_failure", "inconclusive"
		if mode == 0 || mode == 3 {
			outcome, reason, effect = "inconclusive", "test_outcome_unknown", "unknown_outcome"
		}
		if mode == 0 {
			stepState = "cancelled"
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT l.reconcile_state='settled' AND l.reconcile_worker IS NULL AND l.reconcile_token IS NULL AND l.reconcile_expires_at IS NULL AND l.reconcile_settlement->'receipt'->>'outcome'=$6 AND l.reconcile_settlement->'receipt'->>'reason'=$7 AND l.reconcile_settlement->'proof'->>'outcome'=$6 AND r.state=$8 AND s.state=$9 AND f.state=$10 AND encode(f.result_digest,'hex')=l.reconcile_settlement->'receipt'->>'proof_sha256' AND (SELECT count(*) FROM zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,'test_reconciled'))=1 FROM zasp_security_agent_test_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step, outcome, reason, stopped, stepState, effect).Scan(&exact); err != nil || !exact {
			t.Fatalf("registered stopped reconciliation not durable mode%d: %t %v", mode, exact, err)
		}
		if os.Getenv("ZASP_EXISTING_TEST_PUBLIC_PROOF") == "true" {
			assertExistingTestPublicProof(t, ctx, owner, o, w, e, run, step, true)
		}
		return
	}
	token := []byte(strings.Repeat("q", 32))
	checksum, pin := migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()
	var raw json.RawMessage
	if err := reconciler.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,'stopped-reconciler',$4,60,1,$5,$6)`, o, w, e, token, checksum, pin).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claims []struct {
		Run        string `json:"run_id"`
		Step       string `json:"step_id"`
		Version    int64  `json:"version"`
		Generation string `json:"generation"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 || claims[0].Run != run || claims[0].Step != step {
		t.Fatalf("stopped cancellation claim: %s %v", raw, err)
	}
	const query = `SELECT zasp_production_security_agent_existing_tests_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	args := []any{o, w, e, run, step, "stopped-reconciler", token, claims[0].Version, claims[0].Generation, checksum, pin}
	snapshot := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('test',to_jsonb(t),'link',to_jsonb(l),'parent',to_jsonb(r))::text FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) JOIN zasp_security_agent_runs r ON (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=($1,$2,$3,$4)`, o, w, e, testRun).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if mode == 2 {
		beforeDrift := snapshot()
		assertReconcileAuthorityAfterWait(t, ctx, owner, reconciler, query, args, o, w, e, run, step, true)
		if snapshot() != beforeDrift {
			t.Fatal("release drift during cancellation changed test/link/parent")
		}
		var original, deadline time.Time
		if err := owner.QueryRow(ctx, `SELECT reconcile_expires_at FROM zasp_security_agent_test_links WHERE test_run_id=$1`, testRun).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_expires_at=clock_timestamp()+interval '2 seconds' WHERE test_run_id=$1 RETURNING reconcile_expires_at`, testRun).Scan(&deadline); err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		err := existingTestAcceptanceWait(t, ctx, owner, reconciler, testRun, "link_reconcile_cancel", func() error { return reconciler.QueryRow(ctx, query, args...).Scan(&raw) }, deadline)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" || snapshot() != before {
			t.Fatalf("expired cancellation write did not roll back: %v", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_expires_at=$2 WHERE test_run_id=$1`, testRun, original); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		before := snapshot()
		if err := reconciler.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			Run     string `json:"test_run_id"`
			Changed *bool  `json:"changed"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil || receipt.Run != testRun || receipt.Changed == nil || *receipt.Changed != (attempt == 0) {
			t.Fatalf("cancellation transition/retry: %s %v", raw, err)
		}
		if attempt == 1 && before != snapshot() {
			t.Fatal("terminal cancellation retry changed durable state")
		}
	}
	var parent string
	if err := owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&parent); err != nil || parent != stopped {
		t.Fatalf("cancellation changed stopped parent: %s %v", parent, err)
	}
}
