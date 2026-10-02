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
)

// Tests persistence, not complete admission or provider invocation. The lease
// is owner-seeded by the legacy fence helper; the journal core stays private.
func exerciseExistingTestInvocationStart(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, run string, terminal bool) {
	t.Helper()
	const signature = "public.zasp_production_security_agent_existing_tests_invocation_start_core(text,text,text,text,bytea,text,bytea)"
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT to_regprocedure($1) IS NOT NULL`, signature).Scan(&exists); err != nil || !exists {
		t.Fatalf("durable invocation start authority missing: %v", err)
	}
	config := owner.Config().Copy()
	config.User = "existing_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close(context.Background())
	const query = `SELECT zasp_production_security_agent_existing_tests_invocation_start_core($1,$2,$3,$4,convert_to(repeat('a',32),'UTF8'),'prompt_injection',decode(repeat('ab',32),'hex'))`
	var raw json.RawMessage
	var pg *pgconn.PgError
	if err := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "42501" {
		t.Fatalf("unfinished start exposed: %s %v", raw, err)
	}
	if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+signature+` TO existing_test_red_adapter`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `REVOKE ALL ON FUNCTION `+signature+` FROM existing_test_red_adapter`)
	// The dedicated start test owns admission-negative and observed-wait cases.
	// Terminal tests share only the committed-start setup, avoiding duplicate waits.
	if !terminal {
		blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = blocker.Exec(ctx, `BEGIN; SELECT 1 FROM zasp_inventory_source_observations WHERE entity_id='pid_89000011-0000-4000-8000-000000000001' FOR UPDATE`); err != nil {
			blocker.Close(ctx)
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		busyErr := adapter.QueryRow(bounded, query, org, ws, env, run).Scan(&raw)
		cancel()
		_, releaseErr := blocker.Exec(ctx, "ROLLBACK")
		blocker.Close(ctx)
		if releaseErr != nil {
			t.Fatal(releaseErr)
		}
		if !errors.As(busyErr, &pg) || pg.Code != "55P03" {
			t.Fatalf("provenance contention did not fail immediately: %s %v", raw, busyErr)
		}
		// Parent authority must still be live after dispatch; a Red Team lease alone
		// cannot outlive a sticky budget stop or stopped Security Agent run.
		for _, mutation := range []struct{ stop, restore string }{
			{`UPDATE zasp_discovery_snapshots SET is_last_good=false WHERE id='pid_89e23800-0000-4000-8000-000000000003' AND EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_discovery_snapshots SET is_last_good=true WHERE id='pid_89e23800-0000-4000-8000-000000000003' AND EXISTS(SELECT 1 FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
			{`UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1))`, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1))`},
			{`UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE (organization_id,workspace_id,environment_id,target_id)=(SELECT organization_id,workspace_id,environment_id,target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE (organization_id,workspace_id,environment_id,target_id)=(SELECT organization_id,workspace_id,environment_id,target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
			{`UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=(SELECT organization_id,workspace_id,environment_id,action_key FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE (organization_id,workspace_id,environment_id,action_key)=(SELECT organization_id,workspace_id,environment_id,action_key FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
			{`UPDATE zasp_security_agent_step_reservations SET input_digest=decode(repeat('ef',32),'hex') WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(SELECT organization_id,workspace_id,environment_id,run_id,step_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_step_reservations s SET input_digest=l.input_digest FROM zasp_security_agent_test_links l WHERE l.test_run_id=$1 AND (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)`},
			{`UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_cost_exceeded' WHERE (organization_id,workspace_id,environment_id,run_id)=(SELECT organization_id,workspace_id,environment_id,run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_run_budgets SET stop_reason=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=(SELECT organization_id,workspace_id,environment_id,run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
			{`UPDATE zasp_security_agent_runs SET state='needs_human' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, `UPDATE zasp_security_agent_runs SET state='running' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`},
		} {
			if _, err := owner.Exec(ctx, mutation.stop, run); err != nil {
				t.Fatal(err)
			}
			callErr := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw)
			if _, err := owner.Exec(ctx, mutation.restore, run); err != nil {
				t.Fatal(err)
			}
			if !errors.As(callErr, &pg) || pg.Code != "40001" {
				t.Fatalf("stopped authority allowed target invocation: %s %v", raw, callErr)
			}
		}
		for _, wrong := range []string{strings.Replace(query, "repeat('a',32)", "repeat('b',32)", 1), strings.Replace(query, "'prompt_injection'", "'sensitive_information'", 1)} {
			if err := adapter.QueryRow(ctx, wrong, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("wrong invocation lease/category accepted: %s %v", raw, err)
			}
		}
		var supervised bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_approvals WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1))`, run).Scan(&supervised); err != nil {
			t.Fatal(err)
		}
		if supervised {
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET plan_hash=decode(repeat('ef',32),'hex') WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run); err != nil {
				t.Fatal(err)
			}
			callErr := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw)
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals a SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE a.run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1) AND (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id)`, run); err != nil {
				t.Fatal(err)
			}
			if !errors.As(callErr, &pg) || pg.Code != "40001" {
				t.Fatalf("changed approval accepted: %s %v", raw, callErr)
			}
		}
		var deadline time.Time
		if err := owner.QueryRow(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) RETURNING lease_expires_at`, org, ws, env, run).Scan(&deadline); err != nil {
			t.Fatal(err)
		}
		err = existingTestAcceptanceWait(t, ctx, owner, adapter, run, "invocation_start", func() error { return adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw) }, deadline)
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("journal INSERT wait bypassed lease expiry: %s %v", raw, err)
		}
		var empty bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4))`, org, ws, env, run).Scan(&empty); err != nil || !empty {
			t.Fatalf("refused starts left journal rows: %t %v", empty, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
			t.Fatal(err)
		}
		var parentDeadline time.Time
		if err := owner.QueryRow(ctx, `SELECT deadline_at FROM zasp_security_agent_run_budgets WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run).Scan(&parentDeadline); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1) RETURNING deadline_at`, run).Scan(&deadline); err != nil {
			t.Fatal(err)
		}
		err = existingTestAcceptanceWait(t, ctx, owner, adapter, run, "invocation_parent_deadline", func() error { return adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw) }, deadline)
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("journal INSERT wait bypassed parent budget expiry: %s %v", raw, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=$2 WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run, parentDeadline); err != nil {
			t.Fatal(err)
		}
		for _, expiry := range []struct{ table, column, key string }{
			{"zasp_inventory_entities", "fresh_until", "id"},
			{"zasp_attack_lab_credential_bindings", "valid_until", "target_id"},
		} {
			predicate := ` WHERE (organization_id,workspace_id,environment_id,` + expiry.key + `)=(SELECT organization_id,workspace_id,environment_id,target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`
			var original time.Time
			if err := owner.QueryRow(ctx, `SELECT `+expiry.column+` FROM `+expiry.table+predicate, run).Scan(&original); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `UPDATE `+expiry.table+` SET `+expiry.column+`=clock_timestamp()+interval '2 seconds'`+predicate+` RETURNING `+expiry.column, run).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			err = existingTestAcceptanceWait(t, ctx, owner, adapter, run, "invocation_"+expiry.column, func() error { return adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw) }, deadline)
			if _, restoreErr := owner.Exec(ctx, `UPDATE `+expiry.table+` SET `+expiry.column+`=$2`+predicate, run, original); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("journal INSERT wait bypassed %s expiry: %s %v", expiry.column, raw, err)
			}
		}
		for _, table := range []string{"zasp_security_agent_plans", "zasp_security_agent_approvals"} {
			if table == "zasp_security_agent_approvals" && !supervised {
				continue
			}
			predicate := ` WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`
			var original time.Time
			if err := owner.QueryRow(ctx, `SELECT expires_at FROM `+table+predicate, run).Scan(&original); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, `UPDATE `+table+` SET expires_at=clock_timestamp()+interval '2 seconds'`+predicate+` RETURNING expires_at`, run).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			err = existingTestAcceptanceWait(t, ctx, owner, adapter, run, "invocation_"+table, func() error { return adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw) }, deadline)
			if _, restoreErr := owner.Exec(ctx, `UPDATE `+table+` SET expires_at=$2`+predicate, run, original); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("journal INSERT wait bypassed %s expiry: %s %v", table, raw, err)
			}
		}
	}
	if err := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); err != nil {
		t.Fatalf("persist started before network I/O: %v", err)
	}
	var result struct {
		State         string `json:"state"`
		Attempt       int    `json:"attempt"`
		TargetBinding struct {
			Endpoint string `json:"endpoint"`
			TargetID string `json:"target_id"`
			Version  int64  `json:"version"`
		} `json:"target_binding"`
		Provenance struct {
			SnapshotID string `json:"snapshot_id"`
			EvidenceID string `json:"evidence_id"`
		} `json:"target_provenance"`
	}
	if json.Unmarshal(raw, &result) != nil || result.State != "started" || result.Attempt != 1 || result.TargetBinding.Endpoint != "https://adapter.customer.example/v1/evaluate" || result.TargetBinding.TargetID != "pid_89000011-0000-4000-8000-000000000001" || result.TargetBinding.Version < 1 {
		t.Fatalf("start receipt: %s", raw)
	}
	if result.Provenance.SnapshotID != "pid_89e23800-0000-4000-8000-000000000003" || result.Provenance.EvidenceID != "pid_89e23800-0000-4000-8000-000000000004" {
		t.Fatalf("missing winning provenance: %s", raw)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(i.attempt=1 AND i.category='prompt_injection' AND i.state='started' AND i.request_digest=decode(repeat('ab',32),'hex') AND i.input_digest=r.input_digest AND i.started_at IS NOT NULL) FROM zasp_security_agent_test_invocations i JOIN zasp_red_team_runs r ON (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(i.organization_id,i.workspace_id,i.environment_id,i.test_run_id) WHERE (i.organization_id,i.workspace_id,i.environment_id,i.test_run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&exact); err != nil || !exact {
		t.Fatalf("missing durable invocation receipt: %t %v", exact, err)
	}
	// A restarted adapter must not interpret a committed start as permission to
	// send again. Closing this connection models response loss after commit.
	if err := adapter.Close(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if err := second.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "55000" {
		t.Fatalf("unknown invocation outcome allowed duplicate start: %s %v", raw, err)
	}
	if terminal {
		exerciseExistingTestInvocationTerminal(t, ctx, owner, second, org, ws, env, run, query)
		return
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET attempt=2 WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "55000" {
		t.Fatalf("new attempt bypassed unknown invocation: %s %v", raw, err)
	}
	var count int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate journal rows: %d %v", count, err)
	}
}
