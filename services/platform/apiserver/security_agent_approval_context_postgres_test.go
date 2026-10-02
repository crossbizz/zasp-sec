package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func exerciseApprovalContextProjection(t *testing.T, ctx context.Context, owner, api *pgx.Conn) {
	t.Helper()
	const org = "pid_6a000001-0000-4000-8000-000000000001"
	const workspace = "pid_6a000002-0000-4000-8000-000000000002"
	const environment = "pid_6a000003-0000-4000-8000-000000000003"
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_steps SET authorization_result='approval_required' WHERE run_id=$1;
`, pgx.QueryExecModeSimpleProtocol, runContextTestRunID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at)
SELECT s.organization_id,s.workspace_id,s.environment_id,s.step_id,s.run_id,s.step_id,p.plan_hash,'pending',CASE WHEN s.organization_id=$2 THEN 'pid_78000091-0000-4000-8000-000000000091' ELSE 'password=protected-requester-sentinel' END,p.expires_at FROM zasp_security_agent_steps s JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE s.run_id=$1`, runContextTestRunID, org); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"6a", "9a"} {
		for _, step := range []string{"10", "11", "12", "13"} {
			id := "pid_780000" + step + "-0000-4000-8000-0000000000" + step
			var raw json.RawMessage
			if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)`, "pid_"+prefix+"000001-0000-4000-8000-000000000001", "pid_"+prefix+"000002-0000-4000-8000-000000000002", "pid_"+prefix+"000003-0000-4000-8000-000000000003", id).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Detail  SecurityAgentApproval `json:"detail"`
				Context json.RawMessage       `json:"context"`
			}
			if json.Unmarshal(raw, &envelope) != nil {
				t.Fatal("invalid SQL envelope")
			}
			got, err := decodeSecurityAgentApprovalContext(envelope.Context, envelope.Detail)
			if err != nil || got.TargetID == nil || envelope.Detail.ID != id {
				t.Fatal("scoped approval projection missing", err)
			}
			wantAction := map[string]string{"10": "update_finding_response", "11": "create_temporary_policy", "12": "isolate_session", "13": "revoke_integration_connection"}[step]
			wantTarget := map[string]string{"10": "pid_6a000005-0000-4000-8000-000000000005", "11": "pid_" + prefix + "000003-0000-4000-8000-000000000003", "12": "pid_78000020-0000-4000-8000-000000000020", "13": "pid_78000022-0000-4000-8000-000000000022"}[step]
			if got.Action != wantAction || *got.TargetID != wantTarget {
				t.Fatal("wrong persisted action or target")
			}
			if prefix == "6a" && (got.Requester.ID == nil || *got.Requester.ID != "pid_78000091-0000-4000-8000-000000000091") || prefix == "9a" && (got.Requester.State != "withheld" || got.Requester.ID != nil) {
				t.Fatal("requester scope or withholding wrong")
			}
			public, _ := json.Marshal(got)
			if strings.Contains(string(public), "sentinel") {
				t.Fatal("public approval leaked private input")
			}
		}
	}
	var page struct {
		Items         []json.RawMessage `json:"items"`
		NextID        *string           `json:"next_id"`
		NextCreatedAt *string           `json:"next_created_at"`
	}
	var raw json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval_page($1,$2,$3,'pending',$4,NULL,NULL,2)`, org, workspace, environment, runContextTestRunID).Scan(&raw); err != nil || json.Unmarshal(raw, &page) != nil || len(page.Items) != 2 || page.NextID == nil || page.NextCreatedAt == nil {
		t.Fatal("approval page lost limit/cursor", err)
	}
	seen := map[string]bool{}
	for index := 0; index < 2; index++ {
		for _, item := range page.Items {
			var envelope struct {
				Detail  SecurityAgentApproval `json:"detail"`
				Context json.RawMessage       `json:"context"`
			}
			if json.Unmarshal(item, &envelope) != nil {
				t.Fatal("invalid page envelope")
			}
			if _, err := decodeSecurityAgentApprovalContext(envelope.Context, envelope.Detail); err != nil || seen[envelope.Detail.ID] {
				t.Fatal("invalid/duplicate approval page item", err)
			}
			seen[envelope.Detail.ID] = true
		}
		if index == 0 {
			if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval_page($1,$2,$3,'pending',$4,$5::timestamptz,$6,2)`, org, workspace, environment, runContextTestRunID, *page.NextCreatedAt, *page.NextID).Scan(&raw); err != nil || json.Unmarshal(raw, &page) != nil || len(page.Items) != 2 || page.NextID != nil || page.NextCreatedAt != nil {
				t.Fatal("cursor traversal lost boundary", err)
			}
		}
	}
	if len(seen) != 4 {
		t.Fatal("approval page traversal incomplete")
	}
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)`, org, workspace, "pid_9a000003-0000-4000-8000-000000000003", "pid_78000010-0000-4000-8000-000000000010").Scan(&raw); err != pgx.ErrNoRows {
		t.Fatal("foreign environment returned approval", err)
	}
	const approvalID = "pid_78000010-0000-4000-8000-000000000010"
	exerciseRegisteredApprovalContextRepository(t, ctx, api)
	exerciseApprovalContextFullPage(t, ctx, owner, api)
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET plan_hash=decode(repeat('b',64),'hex') WHERE (organization_id,workspace_id,environment_id,approval_id)=($1,$2,$3,$4)`, org, workspace, environment, approvalID); err != nil {
		t.Fatal(err)
	}
	var pgerr *pgconn.PgError
	// The existing v24 detail reader binds the approval hash with SELECT INTO
	// STRICT before the context projection runs, so it refuses with P0002.
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)`, org, workspace, environment, approvalID).Scan(&raw); !errors.As(err, &pgerr) || pgerr.Code != "P0002" {
		t.Fatal("approval plan mismatch did not refuse", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals a SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=($1,$2,$3,$4) AND (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id)`, org, workspace, environment, approvalID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_steps SET authorization_result='allow' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, org, workspace, environment, runContextTestRunID, approvalID); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)`, org, workspace, environment, approvalID).Scan(&raw); !errors.As(err, &pgerr) || pgerr.Code != "55000" {
		t.Fatal("approval authorization mismatch did not refuse", err)
	}
	exerciseRegisteredApprovalDecisions(t, ctx, owner, api)
}

// Real release probing and repository decoding over an owned API-role
// connection. Identities and persisted histories are fixtures, not live users.
func exerciseRegisteredApprovalContextRepository(t *testing.T, ctx context.Context, api *pgx.Conn) {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"6a", "9a"} {
		identity := fixtureRequestIdentity(t)
		identity.CredentialKind = CredentialBrowserSession
		org, _ := domain.ParseProductID("pid_" + prefix + "000001-0000-4000-8000-000000000001")
		workspace, _ := domain.ParseProductID("pid_" + prefix + "000002-0000-4000-8000-000000000002")
		environment, _ := domain.ParseProductID("pid_" + prefix + "000003-0000-4000-8000-000000000003")
		identity.Scope, err = domain.NewScope(org, workspace, environment)
		if err != nil {
			t.Fatal(err)
		}
		page, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{State: "pending", RunID: runContextTestRunID, Limit: 100})
		if err != nil || len(page.Items) != 4 || page.NextID != "" {
			t.Fatal("registered approval page unavailable", err)
		}
		first, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{Limit: 2})
		if err != nil || len(first.Items) != 2 || first.NextCreatedAt == nil || first.NextID == "" {
			t.Fatal("unfiltered registered page unavailable", err)
		}
		second, err := repository.ListSecurityAgentApprovals(ctx, identity, SecurityAgentApprovalPageRequest{Limit: 2, BeforeCreatedAt: *first.NextCreatedAt, BeforeID: first.NextID})
		if err != nil || len(second.Items) != 2 || second.NextID != "" || second.NextCreatedAt != nil {
			t.Fatal("registered cursor boundary unavailable", err)
		}
		seen := map[string]bool{}
		for _, item := range append(first.Items, second.Items...) {
			if seen[item.ID] {
				t.Fatal("registered cursor repeated item")
			}
			seen[item.ID] = true
		}
		actions := map[string]bool{}
		for _, item := range page.Items {
			detail, err := repository.GetSecurityAgentApproval(ctx, identity, item.ID)
			if err != nil || detail.Context == nil || item.Context == nil || detail.Context.Action != item.Context.Action || detail.Context.TargetID == nil {
				t.Fatal("registered detail lost context", err)
			}
			actions[detail.Context.Action] = true
			if prefix == "9a" && (detail.Context.Requester.State != "withheld" || detail.Context.Requester.ID != nil) {
				t.Fatal("unsafe requester returned")
			}
			if detail.Context.Action == "create_temporary_policy" && *detail.Context.TargetID != environment.String() {
				t.Fatal("registered repository crossed environment")
			}
			raw, _ := json.Marshal(detail)
			if strings.Contains(string(raw), "sentinel") {
				t.Fatal("registered repository leaked private text")
			}
		}
		for _, action := range []string{"update_finding_response", "create_temporary_policy", "isolate_session", "revoke_integration_connection"} {
			if !actions[action] {
				t.Fatal("registered repository omitted action", action)
			}
		}
	}
}
