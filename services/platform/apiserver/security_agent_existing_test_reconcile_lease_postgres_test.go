package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentExistingTestStoppedQueuedPostgres(t *testing.T) {
	if os.Getenv("ZASP_RECONCILE_CLIENT_BINARY") == "" {
		t.Fatal("requires registered worker child binary")
	}
	t.Setenv("ZASP_RECONCILE_STOPPED_QUEUED", "true")
	TestSecurityAgentExistingTestReconcileLeasePostgres(t)
}

func TestSecurityAgentExistingTestReconcileVersionBoundaryPostgres(t *testing.T) {
	t.Setenv("ZASP_RECONCILE_VERSION_BOUNDARY", "true")
	TestSecurityAgentExistingTestReconcileLeasePostgres(t)
}

func assertExistingTestReconcileLease(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, o, w, e, run, step string) {
	t.Helper()
	if os.Getenv("ZASP_RECONCILE_SCOPE_DISCOVERY") == "true" && strings.HasPrefix(run, "pid_89c00100-") {
		assertExistingTestScopeDiscovery(t, ctx, owner, worker, o, w, e, run, step)
	}
	const claim = `SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	const read = `SELECT zasp_production_security_agent_existing_tests_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	const cancelStopped = `SELECT zasp_production_security_agent_existing_tests_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	const heartbeat = `SELECT zasp_production_security_agent_existing_tests_reconcile_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	const release = `SELECT zasp_production_security_agent_existing_tests_reconcile_release($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	checksum, pin := migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()
	lease := []byte(strings.Repeat("r", 32))
	name := "existing-test-reconciler"
	args := []any{o, w, e, name, lease, 30, 1, checksum, pin}
	var raw json.RawMessage
	assertReconcileAuthorityAfterWait(t, ctx, owner, worker, claim, args, o, w, e, run, step, true)
	if err := worker.QueryRow(ctx, claim, args...).Scan(&raw); err != nil {
		t.Fatalf("registered reconciler claim unavailable: %v", err)
	}
	var claims []struct {
		Run        string `json:"run_id"`
		Step       string `json:"step_id"`
		Version    int64  `json:"version"`
		Generation string `json:"generation"`
		Expires    string `json:"lease_expires_at"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 || claims[0].Run != run || claims[0].Step != step || claims[0].Version != 2 || claims[0].Expires == "" {
		t.Fatalf("claim receipt=%s %v", raw, err)
	}
	if err := worker.QueryRow(ctx, claim, args...).Scan(&raw); err != nil || string(raw) != "[]" {
		t.Fatalf("duplicate claim acquired live lease: %s %v", raw, err)
	}
	guard := []any{o, w, e, run, step, name, lease, int64(2), claims[0].Generation, checksum, pin}
	deny := func(conn *pgx.Conn, query string, values []any, code string) {
		t.Helper()
		var pg *pgconn.PgError
		err := conn.QueryRow(ctx, query, values...).Scan(&raw)
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("expected%s got%v", code, err)
		}
	}
	// A cancellation call on an active parent must neither revoke its queued
	// test nor consume reconciliation ownership. Repeating it is also a no-op.
	for attempt := 0; attempt < 2; attempt++ {
		if err := worker.QueryRow(ctx, cancelStopped, guard...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			State   string  `json:"state"`
			Changed *bool   `json:"changed"`
			Outcome *string `json:"cancellation_outcome"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil || receipt.State != "queued" || receipt.Changed == nil || *receipt.Changed || receipt.Outcome != nil {
			t.Fatalf("active parent cancellation was not a no-op: %s %v", raw, err)
		}
		var intact bool
		if err := owner.QueryRow(ctx, `SELECT t.state='queued' AND NOT t.cancel_requested AND l.cancellation_outcome IS NULL AND l.reconcile_version=2 AND l.reconcile_state='leased' FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&intact); err != nil || !intact {
			t.Fatalf("active cancellation changed durable work: %t %v", intact, err)
		}
	}
	if err := worker.QueryRow(ctx, read, guard...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	assertReconcileAuthorityAfterWait(t, ctx, owner, worker, read, guard, o, w, e, run, step, false)
	var evidence struct {
		Snapshot struct {
			Run   string `json:"run_id"`
			After struct {
				State string `json:"state"`
			} `json:"after"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(raw, &evidence); err != nil || evidence.Snapshot.Run != run || evidence.Snapshot.After.State != "queued" {
		t.Fatalf("guarded evidence=%s %v", raw, err)
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		bad := append([]any(nil), guard...)
		code := "40001"
		switch index {
		case 0, 1, 2, 3, 4:
			bad[index] = "pid_ffffffff-0000-4000-8000-000000000001"
		case 5:
			bad[index] = "different-reconciler"
		case 6:
			bad[index] = []byte(strings.Repeat("x", 32))
		case 7:
			bad[index] = int64(1)
		case 8:
			bad[index] = "99400010-0000-4000-8000-000000000010"
		case 9, 10:
			bad[index] = "wrong"
			code = "55000"
		}
		deny(worker, read, bad, code)
		deny(worker, cancelStopped, bad, code)
	}
	deny(owner, read, guard, "42501")
	deny(owner, cancelStopped, guard, "42501")
	// Renewal preserves the ownership version; defer consumes it and schedules
	// another poll. Neither operation can acknowledge stale work.
	renew := append(append([]any(nil), guard[:9]...), 60, checksum, pin)
	assertReconcileAuthorityAfterWait(t, ctx, owner, worker, heartbeat, renew, o, w, e, run, step, false)
	assertReconcileAuthorityAfterWait(t, ctx, owner, worker, release, renew, o, w, e, run, step, false)
	if err := worker.QueryRow(ctx, heartbeat, renew...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(run, "pid_89c00100-") {
		assertReconcileAuthorityAfterWait(t, ctx, owner, worker, heartbeat, renew, o, w, e, run, step, true, true)
		assertReconcileAuthorityAfterWait(t, ctx, owner, worker, release, renew, o, w, e, run, step, true, true)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_expires_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step); err != nil {
		t.Fatal(err)
	}
	deny(worker, read, guard, "40001")
	deny(worker, heartbeat, renew, "40001")
	deny(worker, cancelStopped, guard, "40001")
	if err := worker.QueryRow(ctx, claim, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 || claims[0].Version != 3 || claims[0].Generation == guard[8] || claims[0].Generation == "" {
		t.Fatalf("expired lease not reclaimed: %s %v", raw, err)
	}
	deny(worker, read, guard, "40001")
	guard[7] = int64(3)
	guard[8] = claims[0].Generation
	deferArgs := append(append([]any(nil), guard[:9]...), 60, checksum, pin)
	if err := worker.QueryRow(ctx, release, deferArgs...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	deny(worker, release, deferArgs, "40001")
	if err := worker.QueryRow(ctx, claim, args...).Scan(&raw); err != nil || string(raw) != "[]" {
		t.Fatalf("deferred work busy-polled: %s %v", raw, err)
	}
	var scheduled bool
	if err := owner.QueryRow(ctx, `SELECT reconcile_version=4 AND reconcile_state='pending' AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL AND reconcile_next_at>clock_timestamp()+interval '50 seconds' FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&scheduled); err != nil || !scheduled {
		t.Fatalf("defer not persisted: %t %v", scheduled, err)
	}
	if os.Getenv("ZASP_RECONCILE_VERSION_BOUNDARY") == "true" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_version=999999,reconcile_next_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, claim, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 || claims[0].Version != 1000000 || claims[0].Run != run || claims[0].Step != step {
			t.Fatalf("boundary ownership not issued: %s %v", raw, err)
		}
		guard[7] = int64(1000000)
		guard[8] = claims[0].Generation
		boundaryRelease := append(append([]any(nil), guard[:9]...), 10, checksum, pin)
		if err := worker.QueryRow(ctx, release, boundaryRelease...).Scan(&raw); err != nil {
			t.Fatalf("issued boundary claim cannot release pending work: %v", err)
		}
		deny(worker, read, guard, "40001")
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_next_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step); err != nil {
			t.Fatal(err)
		}
		fresh := append([]any(nil), args...)
		// Deliberately reuse the same worker and raw token across rollover.
		if err := worker.QueryRow(ctx, claim, fresh...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 || claims[0].Run != run || claims[0].Step != step || claims[0].Version != 1 || claims[0].Generation == guard[8] || claims[0].Generation == "" {
			t.Fatalf("boundary release stranded pending work: %s %v", raw, err)
		}
		deny(worker, read, guard, "40001")
		freshGuard := append([]any(nil), guard...)
		freshGuard[7], freshGuard[8] = claims[0].Version, claims[0].Generation
		if err := worker.QueryRow(ctx, read, freshGuard...).Scan(&raw); err != nil {
			t.Fatalf("fresh rolled claim cannot read: %v", err)
		}
		staleGeneration := append([]any(nil), freshGuard...)
		staleGeneration[8] = guard[8]
		deny(worker, read, staleGeneration, "40001")
		deny(worker, cancelStopped, staleGeneration, "40001")
		staleMutation := append(append([]any(nil), staleGeneration[:9]...), 30, checksum, pin)
		deny(worker, heartbeat, staleMutation, "40001")
		deny(worker, release, staleMutation, "40001")
		freshRelease := append(append([]any(nil), freshGuard[:9]...), 30, checksum, pin)
		if err := worker.QueryRow(ctx, release, freshRelease...).Scan(&raw); err != nil {
			t.Fatalf("fresh rolled claim cannot release: %v", err)
		}
	}
	if binary := os.Getenv("ZASP_RECONCILE_CLIENT_BINARY"); binary != "" {
		if os.Getenv("ZASP_RECONCILE_STOPPED_QUEUED") == "true" {
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='cancelled',completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_steps SET state='cancelled' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_next_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step); err != nil {
			t.Fatal(err)
		}
		runExistingTestClientChild(t, ctx, owner, o, w, e, run, step, "queued", false)
	}
}

func runExistingTestClientChild(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run, step, state string, unknown bool) {
	t.Helper()
	binary := os.Getenv("ZASP_RECONCILE_CLIENT_BINARY")
	if binary == "" {
		return
	}
	unknownText := "false"
	if unknown {
		unknownText = "true"
	}
	command := exec.CommandContext(ctx, binary, "-test.run=^TestExistingTestClientOwnedPostgres$", "-test.v")
	command.Env = append(os.Environ(), "ZASP_RECONCILE_CLIENT_DSN="+owner.Config().ConnString(), "ZASP_RECONCILE_ORG="+o, "ZASP_RECONCILE_WORKSPACE="+w, "ZASP_RECONCILE_ENVIRONMENT="+e, "ZASP_RECONCILE_RUN="+run, "ZASP_RECONCILE_STEP="+step, "ZASP_RECONCILE_STATE="+state, "ZASP_RECONCILE_UNKNOWN="+unknownText)
	if os.Getenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS") == "true" && state == "complete" {
		var testRun string
		if err := owner.QueryRow(ctx, `SELECT test_run_id FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&testRun); err != nil {
			t.Fatal(err)
		}
		command.Env = append(command.Env, "ZASP_RECONCILE_TEST_RUN="+testRun)
	}
	if os.Getenv("ZASP_RECONCILE_SETTLEMENT_PROCESS") == "true" && state == "complete" {
		assertExistingTestSettlementProcessRestart(t, ctx, owner, command, o, w, e, run, step)
	} else {
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "--- PASS: TestExistingTestClientOwnedPostgres") {
			t.Fatalf("registered reconciliation client: %s %v", output, err)
		}
		t.Log(string(output))
	}
	if os.Getenv("ZASP_RECONCILE_STOPPED_QUEUED") == "true" && state == "queued" {
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT l.reconcile_state='settled' AND l.cancellation_outcome='cancelled_before_execution' AND r.state='cancelled' AND s.state='cancelled' AND t.state='cancelled' AND t.cancel_requested AND t.worker_id IS NULL AND t.lease_token IS NULL AND l.reconcile_settlement->'receipt'->>'outcome'='cancelled' AND f.state='known_failure' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)) FROM zasp_security_agent_test_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&exact); err != nil || !exact {
			t.Fatalf("stopped parent stranded queued test or lost cancellation: %t %v", exact, err)
		}
		return
	}
	if os.Getenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS") == "true" && state == "complete" {
		var outcome, reason, parent, stepState string
		if err := owner.QueryRow(ctx, `SELECT l.reconcile_settlement->'receipt'->>'outcome',l.reconcile_settlement->'receipt'->>'reason',r.state,s.state FROM zasp_security_agent_test_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.reconcile_state)=($1,$2,$3,$4,$5,'settled')`, o, w, e, run, step).Scan(&outcome, &reason, &parent, &stepState); err != nil {
			t.Fatal(err)
		}
		wantOutcome, wantReason, wantStep := "needs_human", "test_baseline_unavailable", "succeeded"
		if strings.Contains(run, "pid_89c00101-") {
			wantReason = "test_condition_persists"
		}
		if unknown {
			wantOutcome, wantReason, wantStep = "inconclusive", "test_outcome_unknown", "inconclusive"
		}
		if strings.Contains(run, "pid_89c00103-") {
			wantOutcome, wantReason, wantStep = "inconclusive", "test_evidence_unavailable", "inconclusive"
			if os.Getenv("ZASP_RECONCILE_INCLUDE_BASELINE") == "true" {
				wantOutcome, wantReason, wantStep = "remediated", "test_condition_changed", "succeeded"
				var exact bool
				if err := owner.QueryRow(ctx, `SELECT l.reconcile_settlement->'proof'->'before'->>'run_id'=l.baseline->>'run_id' AND l.reconcile_settlement->'proof'->'before'->>'attempt'=l.baseline->>'attempt' AND jsonb_array_length(l.reconcile_settlement->'proof'->'checks')=3 AND e.state='verified' AND encode(e.result_digest,'hex')=l.reconcile_settlement->'receipt'->>'proof_sha256' AND (SELECT count(*)=1 FROM zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,'test_reconciled')) FROM zasp_security_agent_test_links l JOIN zasp_security_agent_effects e USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&exact); err != nil || !exact {
					t.Fatalf("registered remediation proof/effect/audit: %t %v", exact, err)
				}
			}
			var verifiedAfter bool
			if err := owner.QueryRow(ctx, `SELECT reconcile_settlement->'proof'->'after'->>'run_id'=test_run_id AND reconcile_settlement->'proof'->'after'->>'attempt'='3' FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&verifiedAfter); err != nil || !verifiedAfter {
				t.Fatalf("baseline refusal lost verified after proof: %t %v", verifiedAfter, err)
			}
		}
		if outcome != wantOutcome || reason != wantReason || parent != wantOutcome || stepState != wantStep {
			t.Fatalf("composed classification %s/%s/%s/%s want%s/%s/%s", outcome, reason, parent, stepState, wantOutcome, wantReason, wantStep)
		}
		if os.Getenv("ZASP_EXISTING_TEST_PUBLIC_PROOF") == "true" {
			assertExistingTestPublicProof(t, ctx, owner, o, w, e, run, step, true)
		}
		return
	}
	if os.Getenv("ZASP_RECONCILE_CLIENT_SETTLE") == "true" && state == "complete" {
		var persisted bool
		if err := owner.QueryRow(ctx, `SELECT l.reconcile_state='settled' AND l.reconcile_worker IS NULL AND l.reconcile_token IS NULL AND l.reconcile_expires_at IS NULL AND r.state='inconclusive' AND s.state='inconclusive' AND l.reconcile_settlement->'receipt'->>'proof_sha256'=encode(e.result_digest,'hex') AND l.reconcile_settlement->'receipt'->>'outcome'='inconclusive' FROM zasp_security_agent_test_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_effects e USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&persisted); err != nil || !persisted {
			t.Fatalf("client settlement not durable: %t %v", persisted, err)
		}
	}
}

func assertReconcileAuthorityAfterWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, query string, args []any, o, w, e, run, step string, claim bool, expiry ...bool) {
	t.Helper()
	expire := len(expiry) > 0 && expiry[0]
	if expire {
		var original time.Time
		if err := owner.QueryRow(ctx, `SELECT reconcile_expires_at FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_expires_at=clock_timestamp()+interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(context.Background(), `UPDATE zasp_security_agent_test_links SET reconcile_expires_at=$6 WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step, original)
	}
	var before, after string
	const snapshot = `SELECT to_jsonb(l)::text FROM zasp_security_agent_test_links l WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`
	if err := owner.QueryRow(ctx, snapshot, o, w, e, run, step).Scan(&before); err != nil {
		t.Fatal(err)
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if claim {
		_, err = tx.Exec(ctx, `LOCK TABLE zasp_security_agent_test_links IN SHARE MODE`)
	} else {
		_, err = tx.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) FOR UPDATE`, o, w, e, run)
	}
	if err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	joined := false
	go func() { var raw json.RawMessage; done <- worker.QueryRow(callCtx, query, args...).Scan(&raw) }()
	defer func() {
		if !joined {
			cancel()
			_ = tx.Rollback(context.Background())
			<-done
		}
	}()
	observed := false
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, worker.PgConn().PID()).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("reconciler didn't reach the controlled lock wait")
	}
	if expire {
		var expired bool
		const elapsed = `SELECT reconcile_expires_at<=clock_timestamp() FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`
		if err := tx.QueryRow(ctx, elapsed, o, w, e, run, step).Scan(&expired); err != nil || expired {
			t.Fatalf("write not observed before original expiry: %t %v", expired, err)
		}
		for !expired {
			if err := tx.QueryRow(callCtx, elapsed, o, w, e, run, step).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if !expired {
				time.Sleep(10 * time.Millisecond)
			}
		}
	} else if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value='controlled-reconcile-drift' WHERE key='production_security_agent_existing_tests_checksum'`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	callErr := <-done
	joined = true
	if _, err := owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_existing_tests_checksum'`, migrations.ProductionSecurityAgentExistingTests().Checksum()); err != nil {
		t.Fatal(err)
	}
	var pg *pgconn.PgError
	code := "55000"
	if expire {
		code = "40001"
	}
	if !errors.As(callErr, &pg) || pg.Code != code {
		t.Fatalf("authority drift during observed wait accepted: %v", callErr)
	}
	if err := owner.QueryRow(ctx, snapshot, o, w, e, run, step).Scan(&after); err != nil || after != before {
		t.Fatalf("rejected stale authority changed claim: %v", err)
	}
}

func assertReconcileBatchBound(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, o, w, e string) {
	t.Helper()
	var total int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total < 2 {
		return
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_next_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,reconcile_state)=($1,$2,$3,'pending')`, o, w, e); err != nil {
		t.Fatal(err)
	}
	const query = `SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,'bounded-reconciler',$4,30,$5,$6,$7)`
	args := []any{o, w, e, []byte(strings.Repeat("b", 32)), 2, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	var raw json.RawMessage
	for _, limit := range []int{0, 26} {
		bad := append([]any(nil), args...)
		bad[4] = limit
		var pg *pgconn.PgError
		err := worker.QueryRow(ctx, query, bad...).Scan(&raw)
		if !errors.As(err, &pg) || pg.Code != "22023" {
			t.Fatalf("unbounded batch accepted: %v", err)
		}
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := worker.QueryRow(bounded, query, args...).Scan(&raw); err != nil || string(raw) != "[]" {
		t.Fatalf("busy organization not skipped: %s %v", raw, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	expected := []int{2, total - 2, 0}
	if os.Getenv("ZASP_RECONCILE_STOPPED_QUEUED") == "true" {
		expected = []int{0, 0, 0}
	}
	for _, want := range expected {
		if err := worker.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var claims []struct {
			Run string `json:"run_id"`
		}
		if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != want {
			t.Fatalf("bounded claim=%s want%d: %v", raw, want, err)
		}
		for _, claim := range claims {
			if seen[claim.Run] {
				t.Fatal("batch duplicated live owner")
			}
			seen[claim.Run] = true
		}
		args[4] = 25
	}
}
