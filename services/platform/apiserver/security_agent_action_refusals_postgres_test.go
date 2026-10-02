package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Removing the SQL content-hash, positional binding, scope or ambiguity guards
// must make these real API-role reads expose corrupted data and fail this test.
// Mutations affect only the owned fixture and are restored before the next case.
func exerciseActionDetailAuthorityRefusals(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	const org = "pid_6a000001-0000-4000-8000-000000000001"
	const workspace = "pid_6a000002-0000-4000-8000-000000000002"
	const environment = "pid_6a000003-0000-4000-8000-000000000003"
	const selectPlan = `SELECT plan,plan_hash FROM zasp_security_agent_plans WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`
	var original json.RawMessage
	var hash []byte
	if err := owner.QueryRow(ctx, selectPlan, org, workspace, environment, runContextTestRunID).Scan(&original, &hash); err != nil {
		t.Fatal(err)
	}
	read := func() error {
		var raw json.RawMessage
		return api.QueryRow(ctx, `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)`, org, workspace, environment, runContextTestRunID).Scan(&raw)
	}
	restore := func(t *testing.T) {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=$5,plan_hash=$6 WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, org, workspace, environment, runContextTestRunID, original, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET plan_hash=$5 WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, org, workspace, environment, runContextTestRunID, hash); err != nil {
			t.Fatal(err)
		}
		if err := read(); err != nil {
			t.Fatal("restored authority was not readable", err)
		}
	}
	refused := func(t *testing.T) {
		t.Helper()
		var pgerr *pgconn.PgError
		if err := read(); !errors.As(err, &pgerr) || pgerr.Code != "55000" || pgerr.Message != "security agent action detail authority unavailable" {
			t.Fatalf("expected fixed authority refusal, got %v", err)
		}
	}
	for _, tc := range []struct {
		name, path, value string
		rehash            bool
	}{
		{"tampered_content", "{steps,0,expected_version}", "9", false},
		{"foreign_step_id", "{steps,0,step_id}", `"pid_79000010-0000-4000-8000-000000000010"`, true},
		{"wrong_action", "{steps,0,action}", `"revoke_integration_connection"`, true},
		{"wrong_index", "{steps,0,index}", "1", true},
		{"foreign_environment", "{steps,1,scope}", `"pid_9a000003-0000-4000-8000-000000000003"`, true},
		{"empty_steps", "{steps}", "[]", true},
		{"malformed_steps", "{steps}", "{}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer restore(t)
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,$5::text[],$6::jsonb) WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, org, workspace, environment, runContextTestRunID, tc.path, tc.value); err != nil {
				t.Fatal(err)
			}
			if tc.rehash {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan_hash=digest(convert_to(plan::text,'UTF8'),'sha256') WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4`, org, workspace, environment, runContextTestRunID); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id) AND (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$3,$4)`, org, workspace, environment, runContextTestRunID); err != nil {
					t.Fatal(err)
				}
			}
			refused(t)
		})
	}
	t.Run("ambiguous_controls", func(t *testing.T) {
		defer func() {
			if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4 AND control_id IN ('pid_78000081-0000-4000-8000-000000000081','pid_78000082-0000-4000-8000-000000000082')`, org, workspace, environment, runContextTestRunID); err != nil {
				t.Fatal(err)
			}
			if err := read(); err != nil {
				t.Fatal("control fixture cleanup did not restore readable authority", err)
			}
		}()
		for _, id := range []string{"pid_78000081-0000-4000-8000-000000000081", "pid_78000082-0000-4000-8000-000000000082"} {
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_controls(organization_id,workspace_id,environment_id,control_id,run_id,step_id,action_key,target_id,state,expires_at) VALUES($1,$2,$3,$5,$4,'pid_78000011-0000-4000-8000-000000000011','create_temporary_policy',$3,'active',clock_timestamp()+interval '2 minutes')`, org, workspace, environment, runContextTestRunID, id); err != nil {
				t.Fatal(err)
			}
		}
		refused(t)
	})
}
