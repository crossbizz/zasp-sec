package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type findingResponseNoteCase struct{ status, note string }

func findingNoteEdges() []rune {
	return []rune{'\u0009', '\u000a', '\u000b', '\u000c', '\u000d', ' ', '\u0085', '\u00a0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff'}
}

func findingNoteSamples() []struct {
	note  string
	valid bool
} {
	samples := []struct {
		note  string
		valid bool
	}{{"Investigate\u00a0exposure\u3000now\ufeff.", true}, {strings.Repeat("é", 256), true}, {strings.Repeat("é", 256) + "x", false}, {"", false}}
	for _, r := range findingNoteEdges() {
		samples = append(samples, struct {
			note  string
			valid bool
		}{string(r) + "Investigate", false}, struct {
			note  string
			valid bool
		}{"Investigate" + string(r), false})
	}
	for _, r := range []rune{1, 31, 127, 128, 133, 159} {
		samples = append(samples, struct {
			note  string
			valid bool
		}{"a" + string(r) + "b", false})
	}
	return samples
}

func TestFindingResponseNoteContract(t *testing.T) {
	for _, status := range []string{"open", "investigating"} {
		for i, s := range findingNoteSamples() {
			t.Run(fmt.Sprintf("%s/%d", status, i), func(t *testing.T) {
				target := "open"
				if status == "investigating" {
					target = "under_review"
				}
				raw, _ := json.Marshal(SecurityAgentActionArguments{TargetID: "pid_78000005-0000-4000-8000-000000000005", ExpectedVersion: 1, TargetStatus: target, AssigneeID: "pid_78000006-0000-4000-8000-000000000006", ResponseStatus: status, Note: s.note})
				got, err := decodeSecurityAgentActionArguments("update_finding_response", raw)
				if (err == nil) != s.valid {
					t.Fatalf("note case%d acceptance=%t want%t", i, err == nil, s.valid)
				}
				if s.valid && got.Note != s.note {
					t.Fatal("approved note normalized")
				}
			})
		}
	}
}

func findingNoteProvider(finding, assignee, status, note string) string {
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": assignee, "status": status, "note": note}}})
	provider, _ := json.Marshal(map[string]any{"id": "finding78-note", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
	return string(provider)
}

func assertFindingNoteParser(t *testing.T, ctx context.Context, owner *pgx.Conn, cv json.RawMessage, finding, assignee string) {
	t.Helper()
	for _, status := range []string{"open", "investigating"} {
		for i, s := range findingNoteSamples() {
			var parsed json.RawMessage
			err := owner.QueryRow(ctx, `SELECT zasp_temporal78.planning_result($1,'openai/gpt-5-mini',$2::jsonb)->'candidate'`, findingNoteProvider(finding, assignee, status, s.note), cv).Scan(&parsed)
			if err != nil {
				t.Fatal("installed note parser", err)
			}
			accepted := string(parsed) != "null" && len(parsed) > 0
			if accepted != s.valid {
				t.Errorf("installed note status=%s case=%d accepted=%t want=%t", status, i, accepted, s.valid)
			}
			if accepted && s.valid {
				var c struct {
					Steps []struct {
						Note string `json:"note"`
					} `json:"steps"`
				}
				if json.Unmarshal(parsed, &c) != nil || len(c.Steps) != 1 || c.Steps[0].Note != s.note {
					t.Fatal("parser normalized note")
				}
			}
		}
	}
}

func assertFindingNoteAdmissionRefusal(t *testing.T, ctx context.Context, owner *pgx.Conn, run, finding, assignee, status string) {
	t.Helper()
	var base json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&base); err != nil {
		t.Fatal(err)
	}
	call := func(op string, payload any) (map[string]any, error) {
		var request map[string]any
		if err := json.Unmarshal(base, &request); err != nil {
			return nil, err
		}
		request["operation"], request["payload"] = op, payload
		q, _ := json.Marshal(request)
		var raw json.RawMessage
		err := owner.QueryRow(ctx, `SELECT zasp_temporal78.plan($1::jsonb)`, q).Scan(&raw)
		var value map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &value)
		}
		return value, err
	}
	const noEffect = `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_approvals WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$1)`
	for _, edge := range []string{"\u00a0", "\u3000", "\ufeff"} {
		if _, err := owner.Exec(ctx, `BEGIN;SET LOCAL SESSION AUTHORIZATION finding78_executor`); err != nil {
			t.Fatal(err)
		}
		var principal string
		if err := owner.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "finding78_executor" {
			owner.Exec(ctx, `ROLLBACK`)
			t.Fatal("note admission principal", principal, err)
		}
		_, resultErr := call("result", map[string]any{"raw": findingNoteProvider(finding, assignee, status, edge+"Investigate")})
		settled, settleErr := call("settle", map[string]any{})
		if resultErr != nil || settleErr != nil || settled["state"] != "needs_human" {
			owner.Exec(ctx, `ROLLBACK`)
			t.Fatal("invalid note did not settle to terminal refusal", resultErr, settleErr, settled["state"])
		}
		if _, err := owner.Exec(ctx, `SAVEPOINT denied_admit`); err != nil {
			owner.Exec(ctx, `ROLLBACK`)
			t.Fatal(err)
		}
		_, admitErr := call("admit", map[string]any{})
		_, restoreErr := owner.Exec(ctx, `ROLLBACK TO SAVEPOINT denied_admit;RESET SESSION AUTHORIZATION`)
		var clean bool
		inspectErr := restoreErr
		if inspectErr == nil {
			inspectErr = owner.QueryRow(ctx, noEffect, run).Scan(&clean)
		}
		var terminal bool
		if inspectErr == nil {
			inspectErr = owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.last_error_code='planner_rejected' AND j.state='needs_human' AND j.result_value->'candidate'='null'::jsonb AND p.settled_at IS NOT NULL AND p.released_at IS NULL FROM zasp_security_agent_runs r JOIN zasp_temporal78.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal78.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&terminal)
		}
		_, rollbackErr := owner.Exec(ctx, `ROLLBACK`)
		if rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		var pgError *pgconn.PgError
		if !errors.As(admitErr, &pgError) || pgError.Code != "40001" {
			t.Fatal("terminal invalid note admitted", admitErr)
		}
		if inspectErr != nil || !clean || !terminal {
			t.Fatal("invalid note lacks terminal proof or contains plan/proposal/effect before commit", clean, terminal, inspectErr)
		}
	}
	var clean bool
	if err := owner.QueryRow(ctx, noEffect, run).Scan(&clean); err != nil || !clean {
		t.Fatal("invalid note persisted plan/proposal/effect", clean, err)
	}
}

func TestTemporalFindingResponseNotePostgres(t *testing.T) {
	for _, mode := range []string{"autonomous", "supervised"} {
		for _, status := range []string{"open", "investigating"} {
			t.Run(mode+"_"+status, func(t *testing.T) {
				runFindingResponseFixtureOptions(t, nil, nil, mode == "supervised", findingResponseNoteCase{status: status, note: "Investigate\u00a0exposure\u3000now\ufeff."})
			})
		}
	}
}

func assertFindingNoteReadback(t *testing.T, ctx context.Context, f findingResponseFixture, run, finding string, c findingResponseNoteCase, supervised bool) {
	t.Helper()
	if supervised {
		var approval string
		if err := f.owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		req := workflowRequest(t, f.identity, testCorrelationID, "getSecurityAgentApproval", map[string]string{"id": approval}, http.MethodGet, "/api/v1/security-agent-approvals/"+approval, "")
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		var value SecurityAgentApproval
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &value) != nil || !requiredFindingApprovalContext(value) || value.Context.FindingResponse.Note != c.note || value.Context.FindingResponse.ResponseStatus != c.status {
			t.Fatal("Unicode proposal readback", res.Code)
		}
		req = workflowRequest(t, f.identity, testCorrelationID, "decideSecurityAgentApproval", map[string]string{"id": approval}, http.MethodPost, "/api/v1/security-agent-approvals/"+approval+"/decision", `{"decision":"approved"}`)
		req.Header.Set("If-Match", `"1"`)
		req.Header.Set("Idempotency-Key", "finding-note-approved")
		req.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
		res = httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		if res.Code != 200 {
			t.Fatal("Unicode proposal decision", res.Code)
		}
	}
	var start json.RawMessage
	if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&start); err != nil {
		t.Fatal(err)
	}
	var applied json.RawMessage
	if err := f.executor.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, start).Scan(&applied); err != nil {
		t.Fatal("Unicode note effect", err)
	}
	req := workflowRequest(t, f.identity, testCorrelationID, "getSecurityAgentRun", map[string]string{"id": run}, http.MethodGet, "/api/v1/security-agent-runs/"+run, "")
	req.Header.Set("X-Zasp-Action-Details", "v1")
	res := httptest.NewRecorder()
	f.handler.ServeHTTP(res, req)
	var detail SecurityAgentRunDetail
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &detail) != nil || len(detail.ActionDetails) != 1 {
		t.Fatal("Unicode effect readback", res.Code)
	}
	a := detail.ActionDetails[0]
	if a.Arguments == nil || a.Arguments.Note != c.note || a.Arguments.ResponseStatus != c.status || a.Result == nil || a.Result.State != "verified" || a.Verification.State != "verified" {
		t.Fatal("approved Unicode text changed or unverified")
	}
	var exact bool
	if err := f.owner.QueryRow(ctx, `SELECT note=$2 AND response_status=$3 AND expected_version=1 AND result_version=2 FROM zasp_temporal78.response_metadata WHERE run_id=$1`, run, c.note, c.status).Scan(&exact); err != nil || !exact {
		t.Fatal("persisted Unicode note changed", exact, err)
	}
}
