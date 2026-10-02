package apiserver

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Catches decision routing/receipt replay regressions after optional context was
// added. These are committed database decisions on seeded runs, not provider actions.
func exerciseRegisteredApprovalDecisions(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	const org = "pid_6a000001-0000-4000-8000-000000000001"
	const workspace = "pid_6a000002-0000-4000-8000-000000000002"
	const environment = "pid_6a000003-0000-4000-8000-000000000003"
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	o, _ := domain.ParseProductID(org)
	w, _ := domain.ParseProductID(workspace)
	e, _ := domain.ParseProductID(environment)
	identity.Scope, err = domain.NewScope(o, w, e)
	if err != nil {
		t.Fatal(err)
	}
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	for actionIndex, action := range []string{"update_finding_response", "create_temporary_policy", "isolate_session", "revoke_integration_connection"} {
		step := fmt.Sprintf("pid_780000%d-0000-4000-8000-0000000000%d", 10+actionIndex, 10+actionIndex)
		for index, decision := range []string{"approved", "rejected", "cancelled"} {
			run := fmt.Sprintf("pid_79000%03d-0000-4000-8000-000000000%03d", 100+actionIndex*3+index, 100+actionIndex*3+index)
			for _, statement := range []string{
				`INSERT INTO zasp_security_agent_runs SELECT (jsonb_populate_record(NULL::zasp_security_agent_runs,to_jsonb(r)||jsonb_build_object('run_id',$4::text,'state','waiting_approval','completed_at',NULL))).* FROM zasp_security_agent_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
				`INSERT INTO zasp_security_agent_plans SELECT (jsonb_populate_record(NULL::zasp_security_agent_plans,to_jsonb(p)||jsonb_build_object('run_id',$4::text,'plan',body,'plan_hash',digest(convert_to(body::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_plans p CROSS JOIN LATERAL (SELECT p.plan||jsonb_build_object('run_id',$4::text,'evidence_ids',jsonb_build_array('pid_6a000005-0000-4000-8000-000000000005')) body) fixture WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
				`INSERT INTO zasp_security_agent_steps SELECT (jsonb_populate_record(NULL::zasp_security_agent_steps,to_jsonb(s)||jsonb_build_object('run_id',$4::text,'authorization_result','approval_required','state','waiting_approval'))).* FROM zasp_security_agent_steps s WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$5)`,
				fmt.Sprintf(`INSERT INTO zasp_security_agent_approvals SELECT (jsonb_populate_record(NULL::zasp_security_agent_approvals,to_jsonb(a)||jsonb_build_object('run_id',$4::text,'approval_id',$4::text))).* FROM zasp_security_agent_approvals a WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$5,'%s')`, step),
				`UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$3,$4) AND (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) AND $5::text IS NOT NULL`,
				`UPDATE zasp_security_agent_steps s SET input_digest=p.plan_hash FROM zasp_security_agent_plans p WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=($1,$2,$3,$4) AND (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(s.organization_id,s.workspace_id,s.environment_id,s.run_id) AND $5::text IS NOT NULL`,
				`UPDATE zasp_security_agent_approvals a SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=($1,$2,$3,$4) AND (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) AND $5::text IS NOT NULL`,
			} {
				if _, err := owner.Exec(ctx, statement, org, workspace, environment, run, runContextTestRunID); err != nil {
					t.Fatal(err)
				}
			}
			before, err := repository.GetSecurityAgentApproval(ctx, identity, run)
			if err != nil || before.Context == nil || before.Context.Action != action || before.State != "pending" {
				t.Fatal("seeded pending context unavailable", err)
			}
			input := SecurityAgentApprovalDecisionRequest{ApprovalID: run, IdempotencyKey: "context-" + action + "-" + decision, Decision: decision, ExpectedVersion: 1, FreshAuthAt: time.Now().UTC(), AuditID: run, CorrelationID: run, ReceiptID: run}
			result, err := repository.DecideSecurityAgentApproval(ctx, identity, input)
			if err != nil || result.State != decision || result.Version != 2 || result.Replayed || result.ReceiptID != run {
				t.Fatalf("committed %s decision: %+v %v", decision, result, err)
			}
			replay, err := repository.DecideSecurityAgentApproval(ctx, identity, input)
			if err != nil || !replay.Replayed {
				t.Fatal("committed decision did not replay", err)
			}
			replay.Replayed = false
			if !reflect.DeepEqual(result, replay) {
				t.Fatal("replay changed receipt authority")
			}
			after, err := repository.GetSecurityAgentApproval(ctx, identity, run)
			if err != nil || after.State != decision || after.Version != 2 || !reflect.DeepEqual(before.Context, after.Context) {
				t.Fatal("context read changed committed decision", err)
			}
			var state, stepState string
			var audits, receipts int
			err = owner.QueryRow(ctx, `SELECT r.state,s.state,(SELECT count(*) FROM zasp_security_agent_audit WHERE organization_id=$1 AND audit_id=$4),(SELECT count(*) FROM zasp_security_agent_request_receipts WHERE organization_id=$1 AND receipt_id=$4) FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,s.step_id)=($1,$2,$3,$4,$5)`, org, workspace, environment, run, step).Scan(&state, &stepState, &audits, &receipts)
			wantRun := map[string]string{"approved": "queued", "rejected": "needs_human", "cancelled": "cancelled"}[decision]
			wantStep := "cancelled"
			if decision == "approved" {
				wantStep = "authorized"
			}
			if err != nil || state != wantRun || stepState != wantStep || audits != 1 || receipts != 1 {
				t.Fatalf("decision/replay persisted state: %s %s audits=%d receipts=%d %v", state, stepState, audits, receipts, err)
			}
			t.Logf("registered committed decision: action=%s decision=%s exact_replay=true audits=1 receipts=1", action, decision)
		}
	}
}
