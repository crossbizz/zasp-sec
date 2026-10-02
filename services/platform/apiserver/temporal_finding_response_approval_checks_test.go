package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func assertFindingApprovalDecisions(t *testing.T, ctx context.Context, f findingResponseFixture, approval SecurityAgentApproval) {
	t.Helper()
	assertFindingApprovalRequestRefusals(t, ctx, f, approval)
	assertFindingApprovalApplyRefusals(t, ctx, f, approval, false)
	for _, header := range []string{"", "v1"} {
		req := workflowRequest(t, f.identity, testCorrelationID, "listSecurityAgentApprovals", nil, http.MethodGet, "/api/v1/security-agent-approvals?run_id="+approval.RunID, "")
		if header != "" {
			req.Header.Set("X-Zasp-Approval-Context", header)
		}
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		var page struct {
			Items []SecurityAgentApproval `json:"items"`
		}
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &page) != nil || len(page.Items) != 1 || !requiredFindingApprovalContext(page.Items[0]) {
			t.Fatal("finding approval list context", res.Code)
		}
		a, _ := json.Marshal(approval.Context)
		b, _ := json.Marshal(page.Items[0].Context)
		assertAutomaticRuleJSON(t, "list/detail concrete changes", a, b)
	}
	read := workflowRequest(t, f.identity, testCorrelationID, "getSecurityAgentRun", map[string]string{"id": approval.RunID}, http.MethodGet, "/api/v1/security-agent-runs/"+approval.RunID, "")
	read.Header.Set("X-Zasp-Action-Details", "v1")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, read)
	var detail SecurityAgentRunDetail
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &detail) != nil || len(detail.Approvals) != 1 || !requiredFindingApprovalContext(detail.Approvals[0]) {
		t.Fatal("finding run approval context", response.Code)
	}
	expected, _ := json.Marshal(approval.Context)
	actual, _ := json.Marshal(detail.Approvals[0].Context)
	assertAutomaticRuleJSON(t, "run/detail concrete changes", expected, actual)
	for _, state := range []string{"source", "grant", "plan"} {
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		switch state {
		case "source":
			_, err = tx.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, approval.Context.FindingResponse.TargetID)
		case "grant":
			_, err = tx.Exec(ctx, `INSERT INTO zasp_temporal78.grant_revocations SELECT organization_id,workspace_id,environment_id,definition_id,definition_version,clock_timestamp(),grantor_id,$2 FROM zasp_temporal78.service_grants WHERE definition_id=$1 AND definition_version=3`, f.definition, f.next())
		case "plan":
			_, err = tx.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,note}','"Changed after display"') WHERE run_id=$1`, approval.RunID)
		}
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal("approval refusal prerequisite", state, err)
		}
		if _, err = tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{f.api.Config().User}.Sanitize()); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		var raw json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_temporal78.decide_approval($1,$2,$3,$4,$5,$6,1,'approved',$7,$8,$9,$10)`, f.o, f.w, f.e, approval.ID, f.actor, "finding78-denied-"+state, time.Now().UTC(), f.next(), f.next(), f.next()).Scan(&raw)
		tx.Rollback(ctx)
		if err == nil {
			t.Fatal("approval admitted stale authority", state)
		}
	}
	call := func() *httptest.ResponseRecorder {
		t.Helper()
		req := workflowRequest(t, f.identity, testCorrelationID, "decideSecurityAgentApproval", map[string]string{"id": approval.ID}, http.MethodPost, "/api/v1/security-agent-approvals/"+approval.ID+"/decision", `{"decision":"approved"}`)
		req.Header.Set("If-Match", `"1"`)
		req.Header.Set("Idempotency-Key", "finding78-approved")
		req.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		return res
	}
	if _, err := f.api.Exec(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	rolled := call()
	_, captureErr := f.api.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	_, rollbackErr := f.api.Exec(ctx, `ROLLBACK`)
	if rolled.Code != 200 || captureErr != nil || rollbackErr != nil {
		t.Fatal("approval rollback boundary", rolled.Code, captureErr, rollbackErr)
	}
	var unchanged bool
	if err := f.owner.QueryRow(ctx, `SELECT state='pending' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.control_intents WHERE run_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE operation='decideSecurityAgentApproval' AND resource_id=$1) FROM zasp_security_agent_approvals WHERE approval_id=$1`, approval.ID, approval.RunID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("rolled approval persisted", unchanged, err)
	}
	committed := call()
	var got SecurityAgentApproval
	if committed.Code != 200 || json.Unmarshal(committed.Body.Bytes(), &got) != nil || got.State != "approved" || got.Version != 2 || !requiredFindingApprovalContext(got) {
		t.Fatal("enriched committed decision", committed.Code)
	}
	actual, _ = json.Marshal(got.Context)
	assertAutomaticRuleJSON(t, "decision/detail concrete changes", expected, actual)
	replay := call()
	if replay.Code != 200 {
		t.Fatal("finding approval replay", replay.Code)
	}
	assertAutomaticRuleJSON(t, "committed finding approval replay", committed.Body.Bytes(), replay.Body.Bytes())
	assertFindingApprovalApplyRefusals(t, ctx, f, got, true)
	if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(c.response_digest=digest(convert_to(rc.response::text,'UTF8'),'sha256') AND rc.response->'approval_context'=$2::jsonb AND c.kind='approval') FROM zasp_temporal78.control_intents c JOIN zasp_security_agent_request_receipts rc USING(organization_id,workspace_id,environment_id,receipt_id) WHERE c.run_id=$1`, approval.RunID, expected).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("final enriched control receipt", unchanged, err)
	}
	var pending json.RawMessage
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.pending_controls()`).Scan(&pending); err != nil {
		t.Fatal("approval delivery", err)
	}
	var items []struct {
		Kind string `json:"kind"`
		ID   string `json:"control_id"`
	}
	if json.Unmarshal(pending, &items) != nil || len(items) != 1 || items[0].Kind != "approval" || items[0].ID == "" {
		t.Fatal("approved notification missing")
	}
}
