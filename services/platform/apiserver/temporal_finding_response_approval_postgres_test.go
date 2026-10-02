package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTemporalFindingResponseApprovalPostgres(t *testing.T) {
	runFindingResponseFixtureMode(t, nil, func(ctx context.Context, f findingResponseFixture, run, finding string) {
		var approval string
		if err := f.owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND state='pending'`, run).Scan(&approval); err != nil {
			t.Fatal("actual supervised approval", err)
		}
		req := workflowRequest(t, f.identity, testCorrelationID, "getSecurityAgentApproval", map[string]string{"id": approval}, http.MethodGet, "/api/v1/security-agent-approvals/"+approval, "")
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		var got SecurityAgentApproval
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ExpectedEffect != findingResponseApprovalEffect || got.Context == nil || got.Context.FindingResponse == nil {
			t.Fatal("concrete supervised approval HTTP projection", res.Code, got.ExpectedEffect)
		}
		changes := got.Context.FindingResponse
		if got.ID != approval || got.RunID != run || changes.TargetID != finding || changes.ExpectedVersion != 1 || changes.AssigneeID != f.assignee || changes.ResponseStatus != "investigating" || changes.TargetStatus != "under_review" || changes.Note != "Investigate the credential exposure" {
			t.Fatal("supervised approval changes mismatch")
		}
		assertFindingApprovalDecisions(t, ctx, f, got)
	})
}
