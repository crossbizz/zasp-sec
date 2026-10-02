package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertFindingApplyCurrentAuthority(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run, finding, actor string) {
	t.Helper()
	for _, test := range []struct {
		name, sql, code string
		args            []any
	}{
		{"stale_source", `UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, "40001", []any{finding}},
		{"revoked_actor", `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, "42501", []any{actor}},
		{"killed_action", `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE(organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'update_finding_response')`, "55000", []any{o, w, e}},
		{"cancelled_run", `UPDATE zasp_security_agent_runs SET state='cancelled',version=version+1,completed_at=clock_timestamp() WHERE run_id=$1`, "40001", []any{run}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var request json.RawMessage
			if err := tx.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&request); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, test.sql, test.args...); err != nil {
				t.Fatal("authority fixture", err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION finding78_executor`); err != nil {
				t.Fatal(err)
			}
			var principal string
			if err := tx.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "finding78_executor" {
				t.Fatal("authority principal", principal, err)
			}
			var raw json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&raw)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || pgError.Code != test.code {
				t.Fatal("finding current authority refusal", test.code, err)
			}
		})
	}
	var clean bool
	if err := owner.QueryRow(ctx, `SELECT f.status='open' AND f.version=1 AND r.state='queued' AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) FROM zasp_risk_findings f CROSS JOIN zasp_security_agent_runs r WHERE r.run_id=$1 AND f.id=$2`, run, finding).Scan(&clean); err != nil || !clean {
		t.Fatal("authority refusals persisted effects", clean, err)
	}
}

func assertFindingStartJournal(t *testing.T, ctx context.Context, owner, executor *pgx.Conn, run string) {
	t.Helper()
	var raw json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.pending()`).Scan(&raw); err != nil {
		t.Fatal("finding durable starts", err)
	}
	var starts []struct {
		Ref struct {
			OrganizationID string `json:"organization_id"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
			RunID          string `json:"run_id"`
		} `json:"ref"`
		DefinitionVersion int64  `json:"definition_version"`
		InputDigest       string `json:"input_digest"`
	}
	if json.Unmarshal(raw, &starts) != nil || len(starts) != 1 || starts[0].Ref.RunID != run {
		t.Fatal("finding start identity")
	}
	s := starts[0]
	q, _ := json.Marshal(map[string]any{"organization_id": s.Ref.OrganizationID, "workspace_id": s.Ref.WorkspaceID, "environment_id": s.Ref.EnvironmentID, "run_id": run, "definition_version": s.DefinitionVersion, "input_digest": s.InputDigest})
	var wrong map[string]any
	_ = json.Unmarshal(q, &wrong)
	wrong["definition_version"] = s.DefinitionVersion + 1
	bad, _ := json.Marshal(wrong)
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_start($1::jsonb)`, bad).Scan(&raw); err == nil {
		t.Fatal("altered start acknowledged")
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.pending()`).Scan(&raw); err != nil {
		t.Fatal("start retry", err)
	}
	if json.Unmarshal(raw, &starts) != nil || len(starts) != 1 || starts[0] != s {
		t.Fatal("ambiguous start lost on retry")
	}
	// SQL receipt contract only. Real durable Temporal acceptance belongs to
	// the connected worker fixture and the independently checked starter.
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_start($1::jsonb)`, q).Scan(&raw); err != nil {
		t.Fatal("finding start receipt", err)
	}
	var replay json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.accept_start($1::jsonb)`, q).Scan(&replay); err != nil {
		t.Fatal(err)
	}
	assertAutomaticRuleJSON(t, "finding start receipt replay", raw, replay)
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal78.pending()`).Scan(&raw); err != nil || string(raw) != "[]" {
		t.Fatal("accepted start remains pending", err)
	}
}
