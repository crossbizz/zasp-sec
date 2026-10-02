package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Runs inside the existing owned audit fixture so authority checks and relation
// reads share a registered release without another database setup per case.
func exerciseSecurityAgentActivityRelations(t *testing.T, ctx context.Context, owner, api *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, org, workspace, environment, principal string, digest []byte, csrf string) {
	t.Helper()
	const target = "pid_7c000099-0000-4000-8000-000000000099"
	const first = "pid_7c000001-0000-4000-8000-000000000001"
	const second = "pid_7c000002-0000-4000-8000-000000000002"
	for i, seed := range []struct{ id, kind string }{{first, "finding"}, {second, "finding"}, {"pid_7c000003-0000-4000-8000-000000000003", "attack_path"}, {"pid_7c000004-0000-4000-8000-000000000004", "runtime_decision"}, {"pid_7c000005-0000-4000-8000-000000000005", "manual"}} {
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at) SELECT organization_id,workspace_id,environment_id,$1,definition_id,definition_version,$2,'relation-fixture','queued','2026-09-16T00:00:00Z' FROM zasp_security_agent_definitions`, seed.id, target); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) SELECT organization_id,workspace_id,environment_id,definition_id,trigger_id,$2,$3,decode(repeat('c',64),'hex'),run_id FROM zasp_security_agent_runs WHERE run_id=$1`, seed.id, seed.kind, i+1); err != nil {
			t.Fatal(err)
		}
	}
	type page struct {
		Items         []json.RawMessage `json:"items"`
		NextCreatedAt *string           `json:"next_created_at"`
		NextID        *string           `json:"next_id"`
		Coverage      string            `json:"coverage"`
	}
	read := func(kind, id string, beforeTime, beforeID any, limit int) page {
		t.Helper()
		var raw json.RawMessage
		if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_related_runs($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, org, workspace, environment, principal, digest, csrf, kind, id, beforeTime, beforeID, limit).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var result page
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		request := SecurityAgentActivityRunRequest{Kind: kind, EntityID: id, Limit: limit}
		if beforeID != nil {
			request.BeforeID = beforeID.(string)
			var err error
			request.BeforeCreatedAt, err = time.Parse(time.RFC3339Nano, beforeTime.(string))
			if err != nil {
				t.Fatal(err)
			}
		}
		public, err := repository.ListSecurityAgentActivityRuns(ctx, identity, request, digest)
		if err != nil || len(public.Items) != len(result.Items) || public.Coverage != result.Coverage {
			t.Fatalf("real repository relation page=%#v error=%v", public, err)
		}
		for i, item := range result.Items {
			if _, err := decodeSecurityAgentRunContextEnvelope(item, public.Items[i].ID); err != nil {
				t.Fatalf("repository relation identity: %v", err)
			}
		}
		return result
	}
	check := func(value page, want ...string) {
		t.Helper()
		if len(value.Items) != len(want) {
			t.Fatalf("relation items=%d want=%d", len(value.Items), len(want))
		}
		for i, raw := range value.Items {
			detail, err := decodeSecurityAgentRunContextEnvelope(raw, want[i])
			if err != nil || detail.Run.ID != want[i] {
				t.Fatalf("relation envelope=%s err=%v", raw, err)
			}
		}
	}
	one := read("finding", target, nil, nil, 1)
	check(one, second)
	if one.NextID == nil || *one.NextID != second || one.NextCreatedAt == nil {
		t.Fatal("relation continuation missing")
	}
	two := read("finding", target, *one.NextCreatedAt, *one.NextID, 1)
	check(two, first)
	if two.NextID != nil || two.NextCreatedAt != nil {
		t.Fatal("relation continuation beyond final page")
	}
	check(read("attack_path", target, nil, nil, 10), "pid_7c000003-0000-4000-8000-000000000003")
	check(read("session", target, nil, nil, 10), "pid_7c000004-0000-4000-8000-000000000004")
	check(read("audit", "pid_7b000003-0000-4000-8000-000000000003", nil, nil, 10), "pid_7b000002-0000-4000-8000-000000000002")
	handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	publicRead := func(kind, id, cursor string) string {
		t.Helper()
		request := workflowRequest(t, identity, "pid_7b000004-0000-4000-8000-000000000004", "listSecurityAgentActivityRuns", map[string]string{"kind": kind, "id": id}, "GET", "/api/v1/security-agent-activity/"+kind+"/"+id+"/runs", "")
		request.URL.RawQuery = "limit=1"
		if cursor != "" {
			request.URL.RawQuery += "&cursor=" + url.QueryEscape(cursor)
		}
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "activity-audit-session-" + org[4:6]})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var value struct {
			Items    []SecurityAgentRun `json:"items"`
			Next     string             `json:"next_cursor"`
			Coverage string             `json:"coverage"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &value) != nil || len(value.Items) != 1 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("registered reverse handler=%d %s", response.Code, response.Body.String())
		}
		if kind == "finding" && ((cursor == "" && value.Items[0].ID != second) || (cursor != "" && value.Items[0].ID != first)) {
			t.Fatal("HTTP cursor returned wrong run")
		}
		return value.Next
	}
	next := publicRead("finding", target, "")
	if next == "" {
		t.Fatal("real reverse HTTP continuation missing")
	}
	if publicRead("finding", target, next) != "" {
		t.Fatal("real reverse HTTP terminal page has cursor")
	}
	publicRead("attack_path", target, "")
	publicRead("session", target, "")
	publicRead("audit", "pid_7b000003-0000-4000-8000-000000000003", "")
	exerciseSecurityAgentActivityTargets(t, ctx, owner, api, repository, identity, digest)
	check(read("finding", "pid_7c000098-0000-4000-8000-000000000098", nil, nil, 10))
	if one.Coverage != "partial" {
		t.Fatalf("missing trigger authority was hidden: %s", one.Coverage)
	}
	var privateAllowed bool
	if err := api.QueryRow(ctx, `SELECT has_function_privilege(current_user,'public.zasp_production_security_agent_run_context_activity_browser(text,text,text,text,bytea,text,text)','EXECUTE')`).Scan(&privateAllowed); err != nil || privateAllowed {
		t.Fatalf("private browser helper executable: %v %v", privateAllowed, err)
	}
	for _, tc := range []struct {
		index int
		value any
		code  string
	}{
		{1, "pid_9a000002-0000-4000-8000-000000000002", "28000"},
		{2, "pid_9a000003-0000-4000-8000-000000000003", "28000"},
		{4, []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "28000"},
		{5, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "42501"},
		{6, "manual", "22023"}, {7, "not-a-product-id", "22023"}, {9, first, "22023"}, {10, 101, "22023"},
	} {
		args := []any{org, workspace, environment, principal, digest, csrf, "finding", target, nil, nil, 10}
		args[tc.index] = tc.value
		var raw json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_related_runs($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != tc.code {
			t.Fatalf("relation invalid argument%d code=%s: %v", tc.index, tc.code, err)
		}
	}
	for _, tc := range []struct{ name, mutate, restore, code string }{
		{"revoked", `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE principal_id=$1 AND organization_id=$2`, `UPDATE zasp_product_sessions SET revoked_at=NULL WHERE principal_id=$1 AND organization_id=$2`, "28000"},
		{"expired", `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE principal_id=$1 AND organization_id=$2`, `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE principal_id=$1 AND organization_id=$2`, "28000"},
		{"inactive membership", `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1 AND organization_id=$2`, "42501"},
	} {
		if _, err := owner.Exec(ctx, tc.mutate, principal, org); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_related_runs($1,$2,$3,$4,$5,$6,'finding',$7,NULL,NULL,10)`, org, workspace, environment, principal, digest, csrf, target).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != tc.code {
			t.Fatalf("relation %s authority bypass: %v", tc.name, err)
		}
		if _, err := owner.Exec(ctx, tc.restore, principal, org); err != nil {
			t.Fatal(err)
		}
		check(read("finding", target, nil, nil, 10), second, first)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE principal_id=$1 AND organization_id=$2`, principal, org); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"session", "audit"} {
		var raw json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_related_runs($1,$2,$3,$4,$5,$6,$7,$8,NULL,NULL,10)`, org, workspace, environment, principal, digest, csrf, kind, target).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("relation %s permission bypass: %v", kind, err)
		}
	}
	check(read("finding", target, nil, nil, 10), second, first)
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$1 AND organization_id=$2`, principal, org); err != nil {
		t.Fatal(err)
	}
	check(read("session", target, nil, nil, 10), "pid_7c000004-0000-4000-8000-000000000004")
	// Fill the only legacy receipt gap, then introduce an argument-bearing plan
	// whose relevant action target is missing. An array alone cannot prove coverage.
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) SELECT organization_id,workspace_id,environment_id,definition_id,trigger_id,'manual',99,decode(repeat('d',64),'hex'),run_id FROM zasp_security_agent_runs WHERE organization_id=$1 AND run_id='pid_7b000002-0000-4000-8000-000000000002'`, org); err != nil {
		t.Fatal(err)
	}
	if got := read("finding", target, nil, nil, 10); got.Coverage != "complete" {
		t.Fatalf("known relation coverage=%s", got.Coverage)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,decode(repeat('c',64),'hex'),'security-agent-actions-v1',body,digest(convert_to(body::text,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs CROSS JOIN LATERAL(SELECT '{"steps":[{"index":0,"step_id":"pid_7c000009-0000-4000-8000-000000000009","action":"update_finding_response","expected_version":1,"target_status":"under_review"}]}'::jsonb body) fixture WHERE organization_id=$1 AND run_id='pid_7c000005-0000-4000-8000-000000000005'`, org); err != nil {
		t.Fatal(err)
	}
	if got := read("finding", "pid_7c000098-0000-4000-8000-000000000098", nil, nil, 10); got.Coverage != "partial" {
		t.Fatalf("missing action target incorrectly reported coverage=%s", got.Coverage)
	}
	for _, tc := range []struct {
		name, kind, steps, coverage string
	}{
		{"null target", "finding", `[{"action":"update_finding_response","target_id":null}]`, "partial"},
		{"malformed target", "finding", `[{"action":"update_finding_response","target_id":"not-a-product-id"}]`, "partial"},
		{"unbound finding target", "finding", `[{"action":"update_finding_response","target_id":"` + target + `"}]`, "partial"},
		{"missing session binding", "session", `[{"action":"isolate_session","target_id":"` + target + `"}]`, "partial"},
		{"mismatched session binding", "session", `[{"action":"isolate_session","target_id":"` + target + `","session_id":"` + first + `"}]`, "partial"},
		{"unbound session target", "session", `[{"action":"isolate_session","target_id":"` + target + `","session_id":"` + target + `"}]`, "partial"},
		{"unknown action", "finding", `[{"action":"future_action"}]`, "partial"},
		{"non-object step", "finding", `[null]`, "partial"},
		{"non-array steps", "finding", `{}`, "partial"},
	} {
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_build_object('steps',$2::jsonb) WHERE organization_id=$1 AND run_id='pid_7c000005-0000-4000-8000-000000000005'`, org, tc.steps); err != nil {
			t.Fatal(err)
		}
		if got := read(tc.kind, "pid_7c000098-0000-4000-8000-000000000098", nil, nil, 10); got.Coverage != tc.coverage {
			t.Fatalf("%s coverage=%s, want %s", tc.name, got.Coverage, tc.coverage)
		}
	}
	const manualRun = "pid_7c000005-0000-4000-8000-000000000005"
	const stepID = "pid_7c000009-0000-4000-8000-000000000009"
	const knownPlan = `{"steps":[{"index":0,"step_id":"` + stepID + `","action":"update_finding_response","target_id":"` + target + `","expected_version":1,"target_status":"under_review"}]}`
	bindPlan := func(body string) {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=$3::jsonb,plan_hash=digest(convert_to(($3::jsonb)::text,'UTF8'),'sha256') WHERE organization_id=$1 AND run_id=$2`, org, manualRun, body); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs run SET plan_hash=plan.plan_hash FROM zasp_security_agent_plans plan WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id) AND run.organization_id=$1 AND run.run_id=$2`, org, manualRun); err != nil {
			t.Fatal(err)
		}
	}
	bindPlan(knownPlan)
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) SELECT organization_id,workspace_id,environment_id,run_id,$3,0,'update_finding_response',digest(convert_to((plan->'steps'->0)::text,'UTF8'),'sha256'),'allow','queued' FROM zasp_security_agent_plans WHERE organization_id=$1 AND run_id=$2`, org, manualRun, stepID); err != nil {
		t.Fatal(err)
	}
	if got := read("finding", "pid_7c000098-0000-4000-8000-000000000098", nil, nil, 10); got.Coverage != "complete" {
		t.Fatalf("bound plan coverage=%s", got.Coverage)
	}
	check(read("finding", target, nil, nil, 10), manualRun, second, first)
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_trigger_receipts SET trigger_kind='finding' WHERE organization_id=$1 AND run_id=$2`, org, manualRun); err != nil {
		t.Fatal(err)
	}
	check(read("finding", target, nil, nil, 10), manualRun, second, first)
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_trigger_receipts SET trigger_kind='manual' WHERE organization_id=$1 AND run_id=$2`, org, manualRun); err != nil {
		t.Fatal(err)
	}
	bindPlan(`{"steps":[]}`)
	if got := read("finding", target, nil, nil, 10); got.Coverage != "partial" {
		t.Fatalf("omitted execution step reported coverage=%s", got.Coverage)
	}
	bindPlan(knownPlan)
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,target_id}',to_jsonb($3::text)) WHERE organization_id=$1 AND run_id=$2`, org, manualRun, first); err != nil {
		t.Fatal(err)
	}
	if got := read("finding", target, nil, nil, 10); got.Coverage != "partial" {
		t.Fatalf("altered target reported coverage=%s", got.Coverage)
	}
}
