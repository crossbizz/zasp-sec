package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Dropping environment_id from plan/effect/control joins must not quietly mix
// histories sharing organization, workspace, run and step identifiers.
func exerciseActionDetailEnvironmentCollision(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	const org = "pid_6a000001-0000-4000-8000-000000000001"
	const workspace = "pid_6a000002-0000-4000-8000-000000000002"
	const primary = "pid_6a000003-0000-4000-8000-000000000003"
	const other = "pid_6a000083-0000-4000-8000-000000000083"
	for _, statement := range []string{
		`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,attempt)
SELECT organization_id,workspace_id,$4,run_id,definition_id,definition_version,trigger_id,'environment-collision-fixture',state,attempt FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
		`INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
SELECT organization_id,workspace_id,$4,run_id,definition_id,definition_version,trigger_digest,catalog_version,body,digest(convert_to(body::text,'UTF8'),'sha256'),expires_at
FROM zasp_security_agent_plans CROSS JOIN LATERAL (SELECT jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(plan,'{steps,0,expected_version}','7'),'{steps,1,target_id}',to_jsonb($4::text)),'{steps,1,scope}',to_jsonb($4::text)),'{steps,1,ttl_seconds}','240'),'{steps,2,scope}',to_jsonb($4::text)),'{steps,2,ttl_seconds}','600') body) changed
WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
		`UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id) AND (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$4,$5) AND $3::text<>$4`,
		`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
SELECT organization_id,workspace_id,environment_id,run_id,s->>'step_id',(s->>'index')::integer,s->>'action',plan_hash,'allow','authorized' FROM zasp_security_agent_plans CROSS JOIN LATERAL jsonb_array_elements(plan->'steps') s WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$4,$5) AND $3::text<>$4`,
		`INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state)
SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,CASE WHEN step_index=0 THEN 'unknown_outcome' ELSE 'pending' END FROM zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$4,$5) AND step_index IN(0,1) AND $3::text<>$4`,
		`INSERT INTO zasp_security_agent_controls(organization_id,workspace_id,environment_id,control_id,run_id,step_id,action_key,target_id,state,expires_at)
VALUES($1,$2,$4,'pid_78000084-0000-4000-8000-000000000084',$5,'pid_78000011-0000-4000-8000-000000000011','create_temporary_policy',$4,'active','2030-01-02T03:04:05Z')`,
	} {
		// All statements use the same five scope parameters; the control insert
		// has no source environment, so execute it with a harmless typed CTE.
		if strings.HasPrefix(statement, "INSERT INTO zasp_security_agent_controls") {
			statement = "WITH source_scope AS (SELECT $3::text) " + statement
		}
		if _, err := owner.Exec(ctx, statement, org, workspace, primary, other, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
	}
	for _, environment := range []string{primary, other} {
		var raw json.RawMessage
		if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)`, org, workspace, environment, runContextTestRunID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		got, err := decodeSecurityAgentRunContextEnvelope(raw, runContextTestRunID)
		if err != nil || len(got.ActionDetails) != 4 {
			t.Fatal("colliding environment projection unreadable", err)
		}
		a := got.ActionDetails
		if strings.Contains(string(raw), "protected-action-sentinel") || a[1].Arguments.Scope != environment || a[2].Arguments.Scope != environment {
			t.Fatal("protected or cross-environment arguments returned")
		}
		if environment == primary {
			if a[0].Arguments.ExpectedVersion != 2 || *a[1].TTLSeconds != 120 || *a[2].TTLSeconds != 300 || a[0].Result != nil || a[1].Result != nil || a[1].ControlExpiresAt != nil {
				t.Fatal("other environment contaminated primary evidence")
			}
		} else if a[0].Arguments.ExpectedVersion != 7 || *a[1].TTLSeconds != 240 || *a[2].TTLSeconds != 600 || a[0].Result == nil || a[0].Result.State != "unknown_outcome" || a[0].Verification.State != "inconclusive" || a[1].Result == nil || a[1].Result.State != "pending" || a[1].ControlExpiresAt == nil || a[1].ControlExpiresAt.Format("2006-01-02T15:04:05Z07:00") != "2030-01-02T03:04:05Z" {
			t.Fatal("other environment lost its distinct recorded evidence")
		}
	}
}
