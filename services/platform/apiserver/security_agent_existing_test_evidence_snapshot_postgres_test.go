package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Called after the real registered worker completion. The loader remains
// private until link claim/lease settlement and production composition exist.
func assertExistingTestEvidenceSnapshot(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, scope domain.Scope, testRun string, unknown bool) {
	t.Helper()
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	var run, step string
	if err := owner.QueryRow(ctx, `SELECT run_id,step_id FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4)`, o, w, e, testRun).Scan(&run, &step); err != nil {
		t.Fatal(err)
	}
	const query = `SELECT zasp_production_security_agent_existing_tests_evidence_snapshot($1,$2,$3,$4,$5)`
	var body json.RawMessage
	if err := owner.QueryRow(ctx, query, o, w, e, run, step).Scan(&body); err != nil {
		t.Fatalf("persisted evidence snapshot unavailable: %v", err)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT $1::jsonb->>'schema_version'='security-agent-test-evidence-snapshot-v1'
 AND $1::jsonb->>'run_id'=l.run_id AND $1::jsonb->>'step_id'=l.step_id
 AND $1::jsonb->'categories'='["prompt_injection","tool_abuse","data_leakage"]'::jsonb
 AND $1::jsonb->'after'->>'run_id'=r.run_id AND ($1::jsonb->'after'->>'attempt')::int=3
 AND $1::jsonb->'after'->>'input_digest'=encode(a.input_digest,'hex')
 AND $1::jsonb->'after'->'input_artifact'=a.input_artifact
 AND $1::jsonb->'after'->'output_artifact'=jsonb_build_object('reference',a.evidence_reference,'key',a.evidence_key,'version_id',a.evidence_version_id,'sha256',encode(a.evidence_checksum,'hex'),'size_bytes',a.evidence_size)
 AND ($1::jsonb->'after'->>'outcome_unknown')::boolean=$6
 AND $1::jsonb->'after'->'observations'=(SELECT COALESCE(jsonb_agg(jsonb_build_object('schema_version','red-team-linked-observation-v1','run_id',j.test_run_id,'category',j.category,'credential_version_digest',encode(j.credential_version_digest,'hex'),'target_comparison',j.target_resolution->'comparison','observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected)) ORDER BY j.category),'[]'::jsonb) FROM zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.attempt,j.input_digest)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.attempt,r.input_digest) AND j.state='completed' AND j.http_status=200)
 FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs r ON (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 JOIN zasp_red_team_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.attempt)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=($2,$3,$4,$5)`, body, o, w, e, run, unknown).Scan(&exact); err != nil || !exact {
		t.Fatalf("snapshot lost exact persisted attempt/journal: %s %v", body, err)
	}
	deny := func(conn *pgx.Conn, organization string, code string) {
		t.Helper()
		var pg *pgconn.PgError
		err := conn.QueryRow(ctx, query, organization, w, e, run, step).Scan(&body)
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("snapshot refusal want%s got%v", code, err)
		}
	}
	deny(worker, o, "42501")
	deny(owner, "pid_ffffffff-0000-4000-8000-000000000001", "40001")
	for _, column := range []string{"input_digest", "evidence_checksum"} {
		var previous []byte
		if err := owner.QueryRow(ctx, `SELECT `+column+` FROM zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,3)`, o, w, e, testRun).Scan(&previous); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_attempts SET `+column+`=digest('substituted-attempt','sha256') WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,3)`, o, w, e, testRun); err != nil {
			t.Fatal(err)
		}
		deny(owner, o, "40001")
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_attempts SET `+column+`=$5 WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,3)`, o, w, e, testRun, previous); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_attempts SET attempt=4 WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,3)`, o, w, e, testRun); err != nil {
		t.Fatal(err)
	}
	deny(owner, o, "40001")
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_attempts SET attempt=3 WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=($1,$2,$3,$4,4)`, o, w, e, testRun); err != nil {
		t.Fatal(err)
	}
	runExistingTestClientChild(t, ctx, owner, o, w, e, run, step, "complete", unknown)
	if os.Getenv("ZASP_TEST_EXISTING_SETTLEMENT") == "true" {
		assertExistingTestSettlement(t, ctx, owner, o, w, e, run, step)
	}
}
