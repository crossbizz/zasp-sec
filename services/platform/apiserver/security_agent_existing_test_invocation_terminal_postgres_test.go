package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Response/protected digests are controlled fixture observations, not a live
// adapter or curated-assertion proof. The persistence operations remain private.
func exerciseExistingTestInvocationTerminal(t *testing.T, ctx context.Context, owner, adapter *pgx.Conn, org, ws, env, run, startQuery string) {
	t.Helper()
	const signature = "public.zasp_production_security_agent_existing_tests_invocation_complete_core(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea)"
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT to_regprocedure($1) IS NOT NULL`, signature).Scan(&exists); err != nil || !exists {
		t.Fatalf("durable terminal receipt authority missing: %v", err)
	}
	const query = `SELECT zasp_production_security_agent_existing_tests_invocation_complete_core($1,$2,$3,$4,1,convert_to(repeat('a',32),'UTF8'),'prompt_injection',decode(repeat('ab',32),'hex'),200,decode(repeat('cd',32),'hex'),true,decode(repeat('dd',32),'hex'))`
	var raw json.RawMessage
	var pg *pgconn.PgError
	if err := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "42501" {
		t.Fatalf("unfinished terminal core exposed: %s %v", raw, err)
	}
	if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+signature+` TO existing_test_red_adapter`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(context.Background(), `REVOKE ALL ON FUNCTION `+signature+` FROM existing_test_red_adapter`)
	for _, wrong := range []string{strings.Replace(query, ",200,", ",500,", 1), strings.Replace(query, ",true,", ",NULL,", 1), strings.Replace(query, "decode(repeat('dd',32),'hex')", "NULL", 1), strings.Replace(query, "repeat('dd',32)", "repeat('00',32)", 1), strings.Replace(query, "repeat('dd',32)", "repeat('dd',31)", 1)} {
		if err := adapter.QueryRow(ctx, wrong, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "22023" {
			t.Fatalf("invalid response/protected combination accepted: %s %v", raw, err)
		}
	}
	for _, wrong := range []string{strings.Replace(query, "repeat('a',32)", "repeat('b',32)", 1), strings.Replace(query, "repeat('ab',32)", "repeat('ef',32)", 1), strings.Replace(query, "$4,1,", "$4,2,", 1)} {
		if err := adapter.QueryRow(ctx, wrong, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("wrong terminal association accepted: %s %v", raw, err)
		}
	}
	if err := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); err != nil {
		t.Fatalf("persist known terminal response: %v", err)
	}
	var result struct {
		State          string `json:"state"`
		Attempt        int    `json:"attempt"`
		HTTPStatus     int    `json:"http_status"`
		Protected      bool   `json:"protected"`
		ResponseDigest string `json:"response_digest"`
	}
	if json.Unmarshal(raw, &result) != nil || result.State != "completed" || result.Attempt != 1 || result.HTTPStatus != 200 || !result.Protected || result.ResponseDigest != strings.Repeat("cd", 32) {
		t.Fatalf("terminal receipt: %s", raw)
	}
	original := append(json.RawMessage(nil), raw...)
	snapshot := func() string {
		var s string
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(i)::text FROM zasp_security_agent_test_invocations i WHERE (organization_id,workspace_id,environment_id,test_run_id,category)=($1,$2,$3,$4,'prompt_injection')`, org, ws, env, run).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot()
	var originalAttributes json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT winning_attributes FROM zasp_inventory_entities WHERE id=(SELECT target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run).Scan(&originalAttributes); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=jsonb_set(winning_attributes,'{red_team,endpoint}','"https://changed.customer.example/v1/evaluate"') WHERE id=(SELECT target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run); err != nil {
		t.Fatal(err)
	}
	changeErr := adapter.QueryRow(ctx, startQuery, org, ws, env, run).Scan(&raw)
	if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=$2 WHERE id=(SELECT target_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`, run, originalAttributes); err != nil {
		t.Fatal(err)
	}
	if !errors.As(changeErr, &pg) || pg.Code != "40001" || snapshot() != before {
		t.Fatalf("changed endpoint reused invocation receipt: %s %v", raw, changeErr)
	}
	for _, q := range []string{query, startQuery} {
		if err := adapter.QueryRow(ctx, q, org, ws, env, run).Scan(&raw); err != nil || !equalIntegrationJSON(raw, original) || snapshot() != before {
			t.Fatalf("immutable terminal replay: %s %v", raw, err)
		}
	}
	for _, wrong := range []string{strings.Replace(query, "repeat('cd',32)", "repeat('ef',32)", 1), strings.Replace(query, ",true,", ",false,", 1), strings.Replace(query, "repeat('dd',32)", "repeat('ee',32)", 1)} {
		if err := adapter.QueryRow(ctx, wrong, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "40001" || snapshot() != before {
			t.Fatalf("conflicting terminal receipt accepted: %s %v", raw, err)
		}
	}
	next := strings.Replace(startQuery, "'prompt_injection'", "'tool_abuse'", 1)
	if err := adapter.QueryRow(ctx, next, org, ws, env, run).Scan(&raw); err != nil {
		t.Fatalf("known first response prevented next category: %v", err)
	}
	var started struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &started) != nil || started.State != "started" {
		t.Fatalf("next category: %s", raw)
	}
	third := strings.Replace(startQuery, "'prompt_injection'", "'data_leakage'", 1)
	if err := adapter.QueryRow(ctx, third, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "55000" {
		t.Fatalf("cross-category unknown outcome allowed another start: %s %v", raw, err)
	}
	if err := adapter.QueryRow(ctx, startQuery, org, ws, env, run).Scan(&raw); err != nil || !equalIntegrationJSON(raw, original) || snapshot() != before {
		t.Fatalf("known receipt replay lost during other uncertainty: %s %v", raw, err)
	}
	// An observed response may arrive after cancellation/lease expiry. Persist
	// the observation, but never re-enable, complete or otherwise mutate the run.
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true,lease_expires_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run); err != nil {
		t.Fatal(err)
	}
	runSnapshot := func() string {
		var s string
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM zasp_red_team_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	beforeRun := runSnapshot()
	errorResponse := strings.NewReplacer("'prompt_injection'", "'tool_abuse'", ",200,", ",500,", ",true,", ",NULL,").Replace(query)
	if err := adapter.QueryRow(ctx, errorResponse, org, ws, env, run).Scan(&raw); err != nil || runSnapshot() != beforeRun {
		t.Fatalf("late known response rejected or changed run: %s %v", raw, err)
	}
	var failed struct {
		State      string `json:"state"`
		HTTPStatus int    `json:"http_status"`
		Protected  *bool  `json:"protected"`
	}
	if json.Unmarshal(raw, &failed) != nil || failed.State != "completed" || failed.HTTPStatus != 500 || failed.Protected != nil {
		t.Fatalf("failed HTTP response claimed protected result: %s", raw)
	}
	if err := adapter.QueryRow(ctx, startQuery, org, ws, env, run).Scan(&raw); !errors.As(err, &pg) || pg.Code != "40001" || runSnapshot() != beforeRun {
		t.Fatalf("expired/cancelled start replay renewed authority: %s %v", raw, err)
	}
	if err := adapter.QueryRow(ctx, query, org, ws, env, run).Scan(&raw); err != nil || !equalIntegrationJSON(raw, original) || snapshot() != before || runSnapshot() != beforeRun {
		t.Fatalf("late receipt replay changed durable observation: %s %v", raw, err)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(state='completed' AND completed_at>=started_at) FROM zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&exact); err != nil || !exact {
		t.Fatalf("terminal journal count/state: %t %v", exact, err)
	}
}
