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

func TestSecurityAgentExistingTestBindingPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const ws = "pid_6a000002-0000-4000-8000-000000000002"
		const env = "pid_6a000003-0000-4000-8000-000000000003"
		const target = "pid_89000001-0000-4000-8000-000000000001"
		const testID = "pid_89000002-0000-4000-8000-000000000002"
		var agentID string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT definition_id,version FROM zasp_security_agent_definitions WHERE organization_id=$1`, org).Scan(&agentID, &version); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3);
   INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
   VALUES($1,$2,$3,$4,'agent_endpoint','Existing test target','active',now(),now(),'agent',now(),now()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/existing_test_0001","target_kinds":["agent_endpoint"]}}');
   SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,'pid_89000003-0000-4000-8000-000000000003',$4,'ref:red-team/existing_test_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
   INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
   VALUES($1,$2,$3,$5,'Existing test',$4,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}','pid_89000004-0000-4000-8000-000000000004');
   UPDATE zasp_security_agent_definitions SET body=body||jsonb_build_object('allowed_actions',jsonb_build_array('run_test'),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$5,'definition_version',1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, target, testID); err != nil {
			t.Fatal(err)
		}
		read := func() (json.RawMessage, error) {
			var raw json.RawMessage
			err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_test_binding($1,$2,$3,$4,$5)`, org, ws, env, agentID, version).Scan(&raw)
			return raw, err
		}
		raw, err := read()
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			DefinitionID      string `json:"definition_id"`
			DefinitionVersion int64  `json:"definition_version"`
			TargetID          string `json:"target_id"`
			TargetKind        string `json:"target_kind"`
		}
		if decodeStrictDiscovery(raw, &value) != nil || value.DefinitionID != testID || value.DefinitionVersion != 1 || value.TargetID != target || value.TargetKind != "agent_endpoint" {
			t.Fatalf("binding=%s", raw)
		}
		for _, role := range []string{"public", "security_agent_v33_api_login", "security_agent_v33_worker_login"} {
			for _, signature := range []string{
				"public.zasp_production_security_agent_run_context_test_binding(text,text,text,text,bigint)",
				"public.zasp_production_security_agent_run_context_lock_env(text,text,text)",
				"public.zasp_production_security_agent_run_context_lock_target(text,text,text,text)",
			} {
				var permitted bool
				if err := owner.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE')`, role, signature).Scan(&permitted); err != nil || permitted {
					t.Fatalf("private reader=%s role=%s executable=%v err=%v", signature, role, permitted, err)
				}
			}
		}
		for _, tc := range []struct{ name, sql string }{
			{"disabled", `UPDATE zasp_red_team_definitions SET enabled=false`},
			{"stale_version", `UPDATE zasp_red_team_definitions SET version=version+1`},
			{"foreign_test", `UPDATE zasp_red_team_definitions SET organization_id='pid_9a000001-0000-4000-8000-000000000001',workspace_id='pid_9a000002-0000-4000-8000-000000000002',environment_id='pid_9a000003-0000-4000-8000-000000000003'`},
			{"production", `UPDATE zasp_environments SET environment_class='production'`},
			{"revoked_credential", `UPDATE zasp_attack_lab_credential_bindings SET state='revoked'`},
			{"expired_target", `UPDATE zasp_inventory_entities SET observed_at=now()-interval '2 seconds',fresh_until=now()-interval '1 second' WHERE id='pid_89000001-0000-4000-8000-000000000001'`},
			{"agent_changed", `UPDATE zasp_security_agent_definitions SET version=version+1`},
			{"missing_binding", `UPDATE zasp_security_agent_definitions SET body=body-'existing_test'`},
			{"deleted_agent", `UPDATE zasp_security_agent_definitions SET deleted_at=now()`},
			{"wrong_action", `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{allowed_actions}','["update_finding_response"]')`},
			{"wrong_verification", `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{verification_kind}','"finding_state"')`},
			{"extra_prompt", `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{existing_test,prompt}','"override"')`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(context.Background(), "ROLLBACK")
				if _, err := owner.Exec(ctx, tc.sql); err != nil {
					t.Fatal(err)
				}
				_, err := read()
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "40001" {
					t.Fatalf("unsafe binding err=%v", err)
				}
			})
		}
		other, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(context.Background(), "ROLLBACK")
		if _, err := read(); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"zasp_security_agent_definitions", "zasp_red_team_definitions", "zasp_environments", "zasp_inventory_entities", "zasp_attack_lab_credential_bindings"} {
			if _, err := other.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			_, lockErr := other.Exec(ctx, "SELECT 1 FROM "+pgx.Identifier{table}.Sanitize()+" WHERE organization_id=$1 FOR UPDATE NOWAIT", org)
			if _, err := other.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			var pg *pgconn.PgError
			if !errors.As(lockErr, &pg) || pg.Code != "55P03" {
				t.Fatalf("binding authority not held table=%s err=%v", table, lockErr)
			}
		}
		if _, err := owner.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		// Removing the final wall-clock checks must allow a binding that expires
		// during the credential lock wait. Observe that wait before releasing it.
		for _, expiring := range []string{"target", "credential"} {
			t.Run("expires_while_waiting_"+expiring, func(t *testing.T) {
				if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '1 hour' WHERE id=$1;
 UPDATE zasp_attack_lab_credential_bindings SET valid_until=clock_timestamp()+interval '1 hour' WHERE target_id=$1`, pgx.QueryExecModeSimpleProtocol, target); err != nil {
					t.Fatal(err)
				}
				expirySQL := `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING fresh_until`
				if expiring == "credential" {
					expirySQL = `UPDATE zasp_attack_lab_credential_bindings SET valid_until=clock_timestamp()+interval '2 seconds' WHERE target_id=$1 RETURNING valid_until`
				}
				var deadline time.Time
				if err := owner.QueryRow(ctx, expirySQL, target).Scan(&deadline); err != nil {
					t.Fatal(err)
				}
				if _, err := other.Exec(ctx, `BEGIN; SELECT 1 FROM zasp_attack_lab_credential_bindings WHERE target_id=$1 FOR UPDATE`, pgx.QueryExecModeSimpleProtocol, target); err != nil {
					t.Fatal(err)
				}
				defer other.Exec(context.Background(), "ROLLBACK")
				done := make(chan error, 1)
				pid := owner.PgConn().PID()
				go func() { _, err := read(); done <- err }()
				// Ensure the connection is joined even when an observation fails.
				defer func() { other.Exec(context.Background(), "ROLLBACK"); <-done }()
				observed := false
				for time.Now().Before(deadline) {
					if err := other.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND clock_timestamp()<$2::timestamptz`, pid, deadline).Scan(&observed); err != nil {
						t.Fatal(err)
					}
					if observed {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !observed {
					t.Fatal("resolver never observed waiting before expiry")
				}
				for {
					var expired bool
					if err := other.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
						t.Fatal(err)
					}
					if expired {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if _, err := other.Exec(ctx, "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				err := <-done
				done <- err // Retain the joined result for deferred cleanup.
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "40001" {
					t.Fatalf("expired binding accepted: %v", err)
				}
			})
		}
	})
}
