package apiserver

import (
	"context"
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

func exerciseLinkedRedTeamHeartbeat(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, client *LinkedRedTeamExecutionRepository, scope domain.Scope, run string, deadline time.Time) {
	t.Helper()
	const query = `SELECT zasp_production_security_agent_existing_tests_worker_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	const signature = `public.zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text)`
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT to_regprocedure($1) IS NOT NULL`, signature).Scan(&exists); err != nil || !exists {
		t.Fatalf("linked heartbeat authority missing: %v", err)
	}
	org, ws, env := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	args := []any{org, ws, env, run, "existing-test-linked-worker", []byte(strings.Repeat("b", 32)), 60, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	snapshot := func() string {
		var raw string
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM zasp_red_team_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var raw json.RawMessage
	for _, role := range []string{"existing_test_red_adapter", "security_agent_v33_worker_login"} {
		config := owner.Config().Copy()
		config.User = role
		conn, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		err = conn.QueryRow(ctx, query, args...).Scan(&raw)
		conn.Close(ctx)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" || snapshot() != before {
			t.Fatalf("wrong heartbeat principal: %s %v", raw, err)
		}
	}
	for _, i := range []int{4, 5, 7, 8} {
		bad := append([]any(nil), args...)
		bad[i] = strings.Repeat("a", 64)
		if i == 4 {
			bad[i] = "wrong-worker"
		}
		if i == 5 {
			bad[i] = []byte(strings.Repeat("c", 32))
		}
		before := snapshot()
		err := worker.QueryRow(ctx, query, bad...).Scan(&raw)
		if i >= 7 {
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "55000" {
				t.Fatalf("stale heartbeat pins: %s %v", raw, err)
			}
		} else {
			var result RedTeamRunHeartbeat
			if err != nil || json.Unmarshal(raw, &result) != nil || result.Renewed || result.CancelRequested {
				t.Fatalf("wrong heartbeat lease: %s %v", raw, err)
			}
		}
		if snapshot() != before {
			t.Fatal("refused heartbeat mutated run")
		}
	}
	renew := func() RedTeamRunHeartbeat {
		t.Helper()
		result, err := client.HeartbeatRedTeamRun(ctx, scope, run, args[4].(string), string(args[5].([]byte)), 60)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '5 seconds' WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	result := renew()
	if !result.Renewed || result.CancelRequested || result.LeaseExpiresAt == nil || !result.LeaseExpiresAt.Equal(deadline) {
		t.Fatalf("heartbeat lost budget cap: %#v", result)
	}
	var durable bool
	if err := owner.QueryRow(ctx, `SELECT lease_expires_at=$2 AND attempt=3 AND worker_id='existing-test-linked-worker' AND lease_token=convert_to(repeat('b',32),'UTF8') FROM zasp_red_team_runs WHERE run_id=$1`, run, deadline).Scan(&durable); err != nil || !durable {
		t.Fatalf("heartbeat changed lease identity: %t %v", durable, err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	before := snapshot()
	result = renew()
	if result.Renewed || !result.CancelRequested || result.LeaseExpiresAt != nil || snapshot() != before {
		t.Fatalf("heartbeat manufactured cancellation/renewal: %#v", result)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=false WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ stop, restore string }{
		{`UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_cost_exceeded' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_run_budgets SET stop_reason=NULL WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
		{`UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=(SELECT organization_id,workspace_id,environment_id,action_key FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE (organization_id,workspace_id,environment_id,action_key)=(SELECT organization_id,workspace_id,environment_id,action_key FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
		{`UPDATE zasp_discovery_snapshots SET is_last_good=false WHERE id='pid_89e23800-0000-4000-8000-000000000003' AND EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_discovery_snapshots SET is_last_good=true WHERE id='pid_89e23800-0000-4000-8000-000000000003' AND EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
	} {
		if _, err := owner.Exec(ctx, mutation.stop, run); err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		_, err := client.HeartbeatRedTeamRun(ctx, scope, run, args[4].(string), string(args[5].([]byte)), 60)
		after := snapshot()
		if _, restoreErr := owner.Exec(ctx, mutation.restore, run); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if err == nil || before != after {
			t.Fatalf("stopped heartbeat renewed: %v", err)
		}
	}
	for _, column := range []string{"lease", "budget"} {
		var expires time.Time
		set := `UPDATE zasp_red_team_runs SET lease_expires_at=$2 WHERE run_id=$1 RETURNING lease_expires_at`
		if column == "budget" {
			set = `UPDATE zasp_security_agent_run_budgets SET deadline_at=$2 WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1) RETURNING deadline_at`
		}
		if err := owner.QueryRow(ctx, set, run, time.Now().UTC().Add(2*time.Second)).Scan(&expires); err != nil {
			t.Fatal(err)
		}
		before := snapshot()
		err := existingTestAcceptanceWait(t, ctx, owner, worker, run, "claim_heartbeat", func() error { return worker.QueryRow(ctx, query, args...).Scan(&raw) }, expires)
		after := snapshot()
		if _, restoreErr := owner.Exec(ctx, set, run, deadline); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" || before != after {
			t.Fatalf("heartbeat crossed %s expiry during observed UPDATE wait: %s %v", column, raw, err)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	result = renew()
	if result.Renewed || result.LeaseExpiresAt != nil || snapshot() != before {
		t.Fatal("heartbeat resurrected expired lease")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=$2 WHERE run_id=$1`, run, deadline); err != nil {
		t.Fatal(err)
	}
}

func exerciseLinkedHeartbeatJournal(t *testing.T, ctx context.Context, owner *pgx.Conn, client *LinkedRedTeamExecutionRepository, scope domain.Scope, run string) {
	t.Helper()
	var before, after string
	const journal = `SELECT to_jsonb(j)::text FROM zasp_security_agent_test_invocations j WHERE test_run_id=$1 AND category='prompt_injection'`
	if err := owner.QueryRow(ctx, journal, run).Scan(&before); err != nil {
		t.Fatal(err)
	}
	renew, err := client.HeartbeatRedTeamRun(ctx, scope, run, "existing-test-linked-worker", strings.Repeat("b", 32), 60)
	if err != nil || !renew.Renewed {
		t.Fatalf("in-flight journal blocked valid renewal: %#v %v", renew, err)
	}
	var original json.RawMessage
	const target = `(organization_id,workspace_id,environment_id,id)=(SELECT organization_id,workspace_id,environment_id,target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`
	if err := owner.QueryRow(ctx, `SELECT winning_attributes FROM zasp_inventory_entities WHERE `+target, run).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=jsonb_set(winning_attributes,'{model}','"changed-heartbeat-model"') WHERE `+target, run); err != nil {
		t.Fatal(err)
	}
	var runBefore, runAfter string
	const current = `SELECT to_jsonb(r)::text FROM zasp_red_team_runs r WHERE run_id=$1`
	if err := owner.QueryRow(ctx, current, run).Scan(&runBefore); err != nil {
		t.Fatal(err)
	}
	result, callErr := client.HeartbeatRedTeamRun(ctx, scope, run, "existing-test-linked-worker", strings.Repeat("b", 32), 60)
	if err := owner.QueryRow(ctx, current, run).Scan(&runAfter); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=$2::jsonb WHERE `+target, run, original); err != nil {
		t.Fatal(err)
	}
	if callErr == nil || result != (RedTeamRunHeartbeat{}) || runBefore != runAfter {
		t.Fatalf("changed target renewed in-flight execution: %#v %v", result, callErr)
	}
	if err := owner.QueryRow(ctx, journal, run).Scan(&after); err != nil || before != after {
		t.Fatalf("heartbeat changed invocation evidence: %v", err)
	}
}
