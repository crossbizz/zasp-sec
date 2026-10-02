package apiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentExistingTestWorkerClaimPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true, false, false, false, true)
}

func exerciseExistingTestWorkerClaim(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, org, ws, env, run string, finish ...int) {
	t.Helper()
	const query = `SELECT zasp_production_security_agent_existing_tests_worker_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	const signature = `public.zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text)`
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT to_regprocedure($1) IS NOT NULL`, signature).Scan(&exists); err != nil || !exists {
		t.Fatalf("linked worker claim authority missing: %v", err)
	}
	// Reset only the fixture's owner-seeded legacy lease. Admission below is real.
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='queued',attempt=0,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,started_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
		t.Fatal(err)
	}
	args := []any{org, ws, env, run, "existing-test-linked-worker", []byte(strings.Repeat("b", 32)), 60, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	snapshot := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',to_jsonb(r),'journal',(SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY category),'[]'::jsonb) FROM zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id)))::text FROM zasp_red_team_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	var raw json.RawMessage
	deny := func(conn *pgx.Conn, values []any, code string) {
		t.Helper()
		before := snapshot()
		var pg *pgconn.PgError
		err := conn.QueryRow(ctx, query, values...).Scan(&raw)
		if !errors.As(err, &pg) || pg.Code != code || snapshot() != before {
			t.Fatalf("claim refusal %s missing or mutated state: %s %v", code, raw, err)
		}
	}
	for _, role := range []string{"existing_test_red_adapter", "security_agent_v33_worker_login", "security_agent_v33_api_login"} {
		config := owner.Config().Copy()
		config.User = role
		conn, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		deny(conn, args, "42501")
		conn.Close(ctx)
	}
	deny(owner, args, "42501")
	for i := range args {
		bad := append([]any(nil), args...)
		bad[i] = nil
		code := "22023"
		if i >= 7 {
			code = "55000"
		}
		deny(worker, bad, code)
	}
	for i, value := range map[int]any{0: "pid_89ffffff-0000-4000-8000-000000000001", 1: "pid_89ffffff-0000-4000-8000-000000000001", 2: "pid_89ffffff-0000-4000-8000-000000000001", 3: "pid_89ffffff-0000-4000-8000-000000000001", 4: "BAD WORKER", 5: []byte("short"), 6: 29, 7: strings.Repeat("a", 64), 8: strings.Repeat("b", 64)} {
		bad := append([]any(nil), args...)
		bad[i] = value
		code := "40001"
		if i >= 4 && i <= 6 {
			code = "22023"
		}
		if i >= 7 {
			code = "55000"
		}
		deny(worker, bad, code)
	}
	for _, mutation := range []struct{ stop, restore string }{
		{`UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id=$1`, `UPDATE zasp_red_team_runs SET cancel_requested=false WHERE run_id=$1`},
		{`UPDATE zasp_red_team_runs SET definition_version=2 WHERE run_id=$1`, `UPDATE zasp_red_team_runs SET definition_version=1 WHERE run_id=$1`},
		{`UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_cost_exceeded' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_run_budgets SET stop_reason=NULL WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
		{`UPDATE zasp_security_agent_runs SET state='needs_human' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_runs SET state='running' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
		{`UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=(SELECT organization_id,workspace_id,environment_id,action_key FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE (organization_id,workspace_id,environment_id,action_key)=(SELECT organization_id,workspace_id,environment_id,action_key FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
		{`UPDATE zasp_discovery_snapshots SET is_last_good=false WHERE id='pid_89e23800-0000-4000-8000-000000000003' AND EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_discovery_snapshots SET is_last_good=true WHERE id='pid_89e23800-0000-4000-8000-000000000003' AND EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
	} {
		if _, err := owner.Exec(ctx, mutation.stop, run); err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		err := worker.QueryRow(ctx, query, args...).Scan(&raw)
		after := snapshot()
		if _, restoreErr := owner.Exec(ctx, mutation.restore, run); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" || before != after {
			t.Fatalf("stopped claim authority mutated run: %s %v", raw, err)
		}
	}
	for _, mutation := range []string{`UPDATE zasp_red_team_runs SET attempt=5 WHERE run_id=$1`, `UPDATE zasp_red_team_runs SET state='retryable',error_code='outcome_unknown' WHERE run_id=$1`} {
		if _, err := owner.Exec(ctx, mutation, run); err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		err := worker.QueryRow(ctx, query, args...).Scan(&raw)
		var result struct {
			Disposition string `json:"disposition"`
		}
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Disposition != "reconcile_required" || before != snapshot() {
			t.Fatalf("unstarted exhausted/unknown claim: %s %v", raw, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='queued',attempt=0,error_code=NULL WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
	}
	var originalDeadline, deadline time.Time
	if err := owner.QueryRow(ctx, `SELECT deadline_at FROM zasp_security_agent_run_budgets WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run).Scan(&originalDeadline); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1) RETURNING deadline_at`, run).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	before := snapshot()
	err := existingTestAcceptanceWait(t, ctx, owner, worker, run, "claim_budget", func() error { return worker.QueryRow(ctx, query, args...).Scan(&raw) }, deadline)
	if _, restoreErr := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=$2 WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run, originalDeadline); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "40001" || snapshot() != before {
		t.Fatalf("claim crossed budget deadline after observed lock wait: %s %v", raw, err)
	}
	// A granted lease cannot extend the parent budget. No journal or target I/O yet.
	if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '40 seconds' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1) RETURNING deadline_at`, run).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	client, err := NewLinkedRedTeamExecutionRepository(existingTestJournalDatabase{worker})
	if err != nil {
		t.Fatalf("registered linked claim client unavailable: %v", err)
	}
	o, _ := domain.ParseProductID(org)
	w, _ := domain.ParseProductID(ws)
	e, _ := domain.ParseProductID(env)
	scope, err := domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(want string, attempt int) {
		t.Helper()
		before := snapshot()
		result, err := client.ClaimRedTeamRun(ctx, scope, run, args[4].(string), string(args[5].([]byte)), args[6].(int))
		if err != nil {
			t.Fatalf("claim %s: %v", want, err)
		}
		if result.Disposition != want {
			t.Fatalf("claim %s: %#v", want, result)
		}
		if want == "claimed" {
			if result.Run.ErrorCode != "" {
				t.Errorf("reclaimed lease retained prior error: %s", result.Run.ErrorCode)
			}
			if result.EvidenceVersion != "red-team-v2" || result.Run.ID != run || result.Run.Attempt != attempt || result.Definition.ID != "pid_89000012-0000-4000-8000-000000000002" || result.Definition.Version != 1 || !result.LeaseExpiresAt.Equal(deadline) {
				t.Fatalf("claim lost linked identity or budget cap: %s", raw)
			}
			var live bool
			if err := owner.QueryRow(ctx, `SELECT state='leased' AND worker_id=$5 AND lease_token=$6 AND attempt=$7 AND lease_expires_at=$8 AND encode(input_digest,'hex')=$9 FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run, args[4], args[5], attempt, deadline, hex.EncodeToString(result.InputDigest[:])).Scan(&live); err != nil || !live {
				t.Fatalf("claim not durable: %t %v", live, err)
			}
		} else if snapshot() != before {
			t.Fatal("non-claim changed durable state")
		}
	}
	claim("claimed", 1)
	claim("retry_later", 0)
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	claim("claimed", 2)
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='retryable',error_code='rate_limited',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	claim("claimed", 3)
	if len(finish) > 0 && finish[0] >= 4 {
		exerciseLinkedRedTeamCancellation(t, ctx, owner, worker, scope, run, finish[0]-4)
		return
	}
	if len(finish) > 0 && finish[0] >= 0 {
		exerciseLinkedRedTeamFinish(t, ctx, owner, worker, scope, run, finish[0])
		return
	}
	exerciseLinkedRedTeamHeartbeat(t, ctx, owner, worker, client, scope, run, deadline)
	config := owner.Config().Copy()
	config.User = "existing_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close(ctx)
	if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,'prompt_injection',decode(repeat('ab',32),'hex'),$6,$7)`, org, ws, env, run, args[5], args[7], args[8]).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	exerciseLinkedHeartbeatJournal(t, ctx, owner, client, scope, run)
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	claim("reconcile_required", 0)
	if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,3,$5,'prompt_injection',decode(repeat('ab',32),'hex'),200,decode(repeat('cd',32),'hex'),true,decode(repeat('dd',32),'hex'),$6,$7)`, org, ws, env, run, args[5], args[7], args[8]).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	claim("reconcile_required", 0)
	// A terminal receipt is acknowledgement only. A stopped parent must not trap
	// duplicate deliveries; this owner-seeded state is not cancellation proof.
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state='cancelled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1;
 UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_cost_exceeded' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, pgx.QueryExecModeSimpleProtocol, run); err != nil {
		t.Fatal(err)
	}
	claim("ack_terminal", 0)
	for _, state := range []string{"complete", "failed"} {
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET state=$2 WHERE run_id=$1`, run, state); err != nil {
			t.Fatal(err)
		}
		claim("ack_terminal", 0)
	}
	bad := append([]any(nil), args...)
	bad[2] = "pid_89ffffff-0000-4000-8000-000000000001"
	deny(worker, bad, "40001")
}
