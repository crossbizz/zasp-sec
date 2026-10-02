package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Each invocation follows real78 source and planner admission. A transaction
// rollback must remove the domain mutation and every proof row together.
func assertFindingResponseAtomicEffect(t *testing.T, ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, finding, assignee string) {
	t.Helper()
	var digest string
	var version int64
	if err := owner.QueryRow(ctx, `SELECT input_digest,definition_version FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&digest, &version); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": version, "input_digest": digest})
	var raw json.RawMessage
	var phase string
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.inspect($1::jsonb)->>'phase'`, request).Scan(&phase); err != nil || phase != "apply" {
		t.Fatal("finding apply observation", phase, err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&raw); err == nil {
		t.Fatal("API principal executed worker finding effect")
	}
	tx, err := executor.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&raw); err != nil {
		tx.Rollback(ctx)
		t.Fatal("finding atomic apply before rollback", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var clean bool
	if err := owner.QueryRow(ctx, `SELECT f.status='open' AND f.version=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) FROM zasp_risk_findings f WHERE f.id=$2`, run, finding).Scan(&clean); err != nil || !clean {
		t.Fatal("finding atomic rollback", clean, err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&raw); err != nil {
		t.Fatal("finding atomic apply", err)
	}
	var replay json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&replay); err != nil {
		t.Fatal("finding atomic replay", err)
	}
	assertAutomaticRuleJSON(t, "same finding effect receipt", raw, replay)
	var verified bool
	if err := owner.QueryRow(ctx, `SELECT f.status='under_review' AND f.version=2 AND r.state='remediated' AND r.requested_by=g.principal_id
 AND m.assignee_id=$3 AND m.response_status='investigating' AND m.note='Investigate the credential exposure' AND m.expected_version=1 AND m.result_version=2
 AND m.result_digest=digest(convert_to(m.result_value::text,'UTF8'),'sha256') AND ef.result_digest=m.result_digest AND ef.outcome_id=m.outcome_id AND ef.state='verified' AND ef.lease_token IS NULL
 AND st.state='succeeded' AND st.action_key='update_finding_response' AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_temporal78.response_metadata WHERE run_id=$1)
 FROM zasp_temporal78.response_metadata m JOIN zasp_risk_findings f ON(f.organization_id,f.workspace_id,f.environment_id,f.id)=(m.organization_id,m.workspace_id,m.environment_id,m.finding_id)
 JOIN zasp_security_agent_runs r ON(r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(m.organization_id,m.workspace_id,m.environment_id,m.run_id)
 JOIN zasp_temporal78.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.definition_version)
 JOIN zasp_security_agent_effects ef ON(ef.organization_id,ef.workspace_id,ef.environment_id,ef.run_id,ef.step_id)=(m.organization_id,m.workspace_id,m.environment_id,m.run_id,m.step_id)
 JOIN zasp_security_agent_steps st ON(st.organization_id,st.workspace_id,st.environment_id,st.run_id,st.step_id)=(m.organization_id,m.workspace_id,m.environment_id,m.run_id,m.step_id)
 WHERE m.run_id=$1 AND m.finding_id=$2`, run, finding, assignee).Scan(&verified); err != nil || !verified {
		t.Fatal("finding metadata/effect verification", verified, err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.inspect($1::jsonb)->>'phase'`, request).Scan(&phase); err != nil || phase != "terminal" {
		t.Fatal("finding verified observation", phase, err)
	}
	config := owner.Config().Copy()
	config.User = "finding78_compensation"
	compensation, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer compensation.Close(context.Background())
	var fields map[string]any
	if json.Unmarshal(request, &fields) != nil {
		t.Fatal("finding cleanup request")
	}
	fields["reason"] = "terminal"
	cleanup, _ := json.Marshal(fields)
	if err := compensation.QueryRow(ctx, `SELECT zasp_temporal78.cleanup($1::jsonb)`, cleanup).Scan(&raw); err != nil {
		t.Fatal("finding verified cleanup", err)
	}
	var receipt struct {
		WorkflowID string `json:"workflow_id"`
		Pending    bool   `json:"pending"`
		Digest     string `json:"evidence_digest"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Pending || receipt.WorkflowID != "security-agent-finding/v1/"+o+"/"+w+"/"+e+"/"+run || !securityAgentPlanHashPattern.MatchString(receipt.Digest) {
		t.Fatal("finding cleanup proof invalid")
	}
}
