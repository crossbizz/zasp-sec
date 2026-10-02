package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The source/planner rows are real78 admissions. Revocation is a rolled-back
// prerequisite change; cleanup executes as the registered compensation login.
func assertFindingPlannerCleanup(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run, actor string, uncertain bool) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var digest string
	var version int64
	if err := tx.QueryRow(ctx, `SELECT input_digest,definition_version FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&digest, &version); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION finding78_compensation`); err != nil {
		t.Fatal(err)
	}
	var principal string
	if err := tx.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "finding78_compensation" {
		t.Fatal("cleanup test principal", principal, err)
	}
	request, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": version, "input_digest": digest, "reason": "workflow_cancelled"})
	var raw json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT zasp_temporal78.cleanup($1::jsonb)`, request).Scan(&raw); err != nil {
		t.Fatal("revoked initiator planner cleanup", uncertain, err)
	}
	var receipt struct {
		Pending bool   `json:"pending"`
		Digest  string `json:"evidence_digest"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Pending != uncertain || !securityAgentPlanHashPattern.MatchString(receipt.Digest) {
		t.Fatal("planner cleanup uncertainty proof", uncertain)
	}
	var replay json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT zasp_temporal78.cleanup($1::jsonb)`, request).Scan(&replay); err != nil {
		t.Fatal("planner cleanup replay", err)
	}
	assertAutomaticRuleJSON(t, "planner cleanup replay", raw, replay)
	if _, err := tx.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
		t.Fatal(err)
	}
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT r.state='needs_human' AND zasp_temporal73.unresolved($1,$2,$3,$4)=$5 AND (p.released_at IS NULL)=$5 AND p.settled_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$4) FROM zasp_security_agent_runs r JOIN zasp_temporal78.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$4`, o, w, e, run, uncertain).Scan(&valid); err != nil || !valid {
		t.Fatal("terminal finding planner accounting", uncertain, valid, err)
	}
}
