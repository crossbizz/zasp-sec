package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Bounded local database characterization, not reference-load API p95 proof.
func exerciseApprovalContextFullPage(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	const org = "pid_6a000001-0000-4000-8000-000000000001"
	const workspace = "pid_6a000002-0000-4000-8000-000000000002"
	const environment = "pid_6a000003-0000-4000-8000-000000000003"
	const run = "pid_79000001-0000-4000-8000-000000000001"
	var forbidden json.RawMessage
	var permissionError *pgconn.PgError
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval_assemble($1,$2,$3,$4,'{}','{}')`, org, workspace, environment, run).Scan(&forbidden); !errors.As(err, &permissionError) || permissionError.Code != "42501" {
		t.Fatal("API can invoke private context assembly", err)
	}
	for _, query := range []string{
		`INSERT INTO zasp_security_agent_runs SELECT (jsonb_populate_record(NULL::zasp_security_agent_runs,to_jsonb(r)||jsonb_build_object('run_id',$4::text))).* FROM zasp_security_agent_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
		`INSERT INTO zasp_security_agent_plans SELECT (jsonb_populate_record(NULL::zasp_security_agent_plans,to_jsonb(p)||jsonb_build_object('run_id',$4::text,'plan',body,'plan_hash',digest(convert_to(body::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_plans p CROSS JOIN LATERAL (SELECT jsonb_build_object('steps',jsonb_agg(jsonb_build_object('index',i-1,'step_id','pid_'||lpad(to_hex(79000000+i),8,'0')||'-0000-4000-8000-'||lpad(i::text,12,'0'),'action','update_finding_response','target_id','pid_6a000005-0000-4000-8000-000000000005','expected_version',1,'target_status','under_review') ORDER BY i)) body FROM generate_series(1,100) i) fixture WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
		`UPDATE zasp_security_agent_runs SET plan_hash=(SELECT plan_hash FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) AND $5::text IS NOT NULL`,
		`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) SELECT organization_id,workspace_id,environment_id,run_id,s->>'step_id',(s->>'index')::integer,'update_finding_response',plan_hash,'approval_required','waiting_approval' FROM zasp_security_agent_plans CROSS JOIN LATERAL jsonb_array_elements(plan->'steps') s WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) AND $5::text IS NOT NULL`,
		`INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) SELECT s.organization_id,s.workspace_id,s.environment_id,s.step_id,s.run_id,s.step_id,p.plan_hash,'pending','page-fixture',p.expires_at FROM zasp_security_agent_steps s JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=($1,$2,$3,$4) AND $5::text IS NOT NULL`,
	} {
		if _, err := owner.Exec(ctx, query, org, workspace, environment, run, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		started := time.Now()
		var raw json.RawMessage
		if err := api.QueryRow(ctx, postgresApprovalContextPageSQL, org, workspace, environment, "pending", run, nil, "", 100).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		page, err := decodeApprovalContextPage(raw, SecurityAgentApprovalPageRequest{State: "pending", RunID: run, Limit: 100})
		elapsed := time.Since(started)
		if err != nil || len(page.Items) != 100 || page.NextID != "" {
			t.Fatal("full approval page lost authority", err)
		}
		for _, item := range page.Items {
			if item.Context == nil || item.Context.Action != "update_finding_response" || item.Context.TargetID == nil || *item.Context.TargetID != "pid_6a000005-0000-4000-8000-000000000005" || item.ID != item.StepID {
				t.Fatal("full page changed selected step")
			}
		}
		t.Logf("owned PostgreSQL approval page: items=100 shared_run_steps=100 sample=%d duration=%s bytes=%d", attempt+1, elapsed, len(raw))
		if elapsed > 750*time.Millisecond {
			t.Errorf("local shared-run approval page exceeded 750ms sanity budget: %s", elapsed)
		}
	}
	// Put this fixture behind the earlier four approvals, yielding two run IDs
	// on one page while preserving each row's original authority.
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET created_at='2000-01-01Z' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, workspace, environment, run); err != nil {
		t.Fatal(err)
	}
	var mixed json.RawMessage
	if err := api.QueryRow(ctx, postgresApprovalContextPageSQL, org, workspace, environment, "pending", "", nil, "", 6).Scan(&mixed); err != nil {
		t.Fatal(err)
	}
	page, err := decodeApprovalContextPage(mixed, SecurityAgentApprovalPageRequest{State: "pending", Limit: 6})
	if err != nil || len(page.Items) != 6 {
		t.Fatal("mixed run page unavailable", err)
	}
	runs := map[string]bool{}
	for _, item := range page.Items {
		runs[item.RunID] = true
		var direct json.RawMessage
		if err := api.QueryRow(ctx, postgresApprovalContextSQL, org, workspace, environment, item.ID).Scan(&direct); err != nil {
			t.Fatal(err)
		}
		detail, err := decodeApprovalContextEnvelope(direct, item.ID)
		if err != nil || !reflect.DeepEqual(item, detail) {
			t.Fatal("cached mixed-run page differs from direct detail", err)
		}
	}
	if len(runs) != 2 {
		t.Fatal("mixed-run fixture did not exercise separate cache entries")
	}
}
