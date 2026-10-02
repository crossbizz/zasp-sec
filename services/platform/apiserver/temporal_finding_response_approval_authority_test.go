package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertFindingApprovalRequestRefusals(t *testing.T, ctx context.Context, f findingResponseFixture, approval SecurityAgentApproval) {
	t.Helper()
	for _, kind := range []string{"fresh", "cas"} {
		id := f.identity
		version := `"1"`
		if kind == "fresh" {
			id.FreshAuthExpiresAt = time.Now().UTC().Add(-time.Minute)
		} else {
			version = `"2"`
		}
		req := workflowRequest(t, id, testCorrelationID, "decideSecurityAgentApproval", map[string]string{"id": approval.ID}, http.MethodPost, "/api/v1/security-agent-approvals/"+approval.ID+"/decision", `{"decision":"approved"}`)
		req.Header.Set("If-Match", version)
		req.Header.Set("Idempotency-Key", "finding78-refused-"+kind)
		req.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		want := 401
		if kind == "cas" {
			want = 409
		}
		if res.Code != want {
			t.Fatal("finding approval request authority", kind, res.Code, want)
		}
	}
	var absent bool
	err := f.api.QueryRow(ctx, `SELECT zasp_temporal78.decide_approval($1,$2,$3,$4,$5,$6,1,'approved',$7,$8,$9,$10) IS NULL`, f.o, f.next(), f.e, approval.ID, f.actor, "finding78-foreign-scope", time.Now().UTC(), f.next(), f.next(), f.next()).Scan(&absent)
	if err != nil || !absent {
		t.Fatal("foreign finding approval returned authority", absent, err)
	}
	var unchanged bool
	if err := f.owner.QueryRow(ctx, `SELECT state='pending' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_request_receipts WHERE resource_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.control_intents WHERE run_id=$2) FROM zasp_security_agent_approvals WHERE approval_id=$1`, approval.ID, approval.RunID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("refused approval request changed state", unchanged, err)
	}
}

func assertFindingApprovalApplyRefusals(t *testing.T, ctx context.Context, f findingResponseFixture, approval SecurityAgentApproval, approved bool) {
	t.Helper()
	cases := []string{"pending", "rejected"}
	if approved {
		cases = []string{"expired", "inactive_assignee"}
	}
	for _, kind := range cases {
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var start json.RawMessage
		if err = tx.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, approval.RunID).Scan(&start); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		switch kind {
		case "expired":
			_, err = tx.Exec(ctx, `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE approval_id=$1`, approval.ID)
		case "inactive_assignee":
			_, err = tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, approval.Context.FindingResponse.AssigneeID)
		case "rejected":
			if _, err = tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{f.api.Config().User}.Sanitize()); err == nil {
				var raw json.RawMessage
				err = tx.QueryRow(ctx, `SELECT zasp_temporal78.decide_approval($1,$2,$3,$4,$5,$6,1,'rejected',$7,$8,$9,$10)`, f.o, f.w, f.e, approval.ID, f.actor, "finding78-rejected", time.Now().UTC(), f.next(), f.next(), f.next()).Scan(&raw)
				if err == nil {
					_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE;RESET SESSION AUTHORIZATION`)
				}
			}
		}
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal("finding refused Apply prerequisite", kind, err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION finding78_executor`); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		var raw json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, start).Scan(&raw)
		tx.Rollback(ctx)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || (pg.Code != "42501" && pg.Code != "40001") {
			t.Fatal("finding Apply accepted unavailable approval or assignee", kind, err)
		}
	}
	var untouched bool
	if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$1)`, approval.RunID).Scan(&untouched); err != nil || !untouched {
		t.Fatal("refused finding Apply persisted effect", untouched, err)
	}
}
