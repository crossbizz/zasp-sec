package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A newer pass, incomplete receipt, mismatched attempt, different version or
// future completion must not displace the latest eligible failed attempt.
// These are database fixtures, not artifact retrieval or remediation proof.
func seedExistingTestBaseline(t *testing.T, ctx context.Context, db *pgx.Conn, o, w, e, definition, actor string, mode int) string {
	t.Helper()
	if mode == 0 {
		return ""
	}
	want := ""
	for n, variant := range []string{"older", "latest", "pass", "version", "missing_input", "mismatch", "future", "zero_checksum"} {
		id := fmt.Sprintf("pid_89ba%02d%02d-0000-4000-8000-000000000001", mode, n)
		key := "organizations/" + o + "/workspaces/" + w + "/environments/" + e + "/artifacts/" + id
		_, err := db.Exec(ctx, `INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at)
 VALUES($1,$2,$3,$4,$5,CASE WHEN $8='version' THEN 2 ELSE 1 END,$6,'complete',1,digest('baseline-input','sha256'),CASE WHEN $8='pass' THEN 'pass' ELSE 'fail' END,'s3://fixture-bucket/'||$7,$7,'output-version',CASE WHEN $8='zero_checksum' THEN decode(repeat('00',32),'hex') ELSE digest('baseline-output','sha256') END,100,clock_timestamp()+CASE WHEN $8='future' THEN interval '1 hour' WHEN $8='older' THEN interval '-2 hours' WHEN $8='latest' THEN interval '-1 hour' ELSE interval '0 seconds' END);
 INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at,input_artifact)
 SELECT organization_id,workspace_id,environment_id,run_id,attempt,CASE WHEN $8='mismatch' THEN digest('wrong-input','sha256') ELSE input_digest END,verdict,'controlled baseline','controlled unsafe result','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at,
 CASE WHEN $8='missing_input' THEN NULL ELSE jsonb_build_object('reference','s3://fixture-bucket/organizations/'||$1||'/workspaces/'||$2||'/environments/'||$3||'/artifacts/pid_89ba0000-0000-4000-8000-000000000002','version_id','input-version','sha256',encode(digest('baseline-input-body','sha256'),'hex'),'size_bytes',90) END
 FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, pgx.QueryExecModeSimpleProtocol, o, w, e, id, definition, actor, key, variant)
		if err != nil {
			t.Fatalf("seed baseline %s: %v", variant, err)
		}
		if variant == "latest" {
			want = id
			if _, err := db.Exec(ctx, `WITH changed AS (UPDATE zasp_red_team_runs SET completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) RETURNING completed_at)
 UPDATE zasp_red_team_attempts SET completed_at=(SELECT completed_at FROM changed) WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	return want
}

func assertExistingTestBaseline(t *testing.T, ctx context.Context, db *pgx.Conn, o, w, e, run, step, want string) {
	t.Helper()
	var selected string
	if err := db.QueryRow(ctx, `SELECT COALESCE(baseline->>'run_id','') FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step).Scan(&selected); err != nil || selected != want {
		t.Fatalf("enqueue baseline=%q want=%q: %v", selected, want, err)
	}
	var snapshot json.RawMessage
	const read = `SELECT zasp_production_security_agent_existing_tests_evidence_snapshot($1,$2,$3,$4,$5)`
	if err := db.QueryRow(ctx, read, o, w, e, run, step).Scan(&snapshot); err != nil {
		t.Fatalf("pending/baseline snapshot: %v", err)
	}
	var body struct {
		Before *struct {
			RunID string `json:"run_id"`
		} `json:"before"`
		After struct {
			State string `json:"state"`
		} `json:"after"`
	}
	if err := json.Unmarshal(snapshot, &body); err != nil || body.After.State != "queued" || want == "" && body.Before != nil || want != "" && (body.Before == nil || body.Before.RunID != want) {
		t.Fatalf("wrong pending/baseline association: %s %v", snapshot, err)
	}
	// Definition edits after enqueue cannot replace the original category set.
	var categories json.RawMessage
	if err := db.QueryRow(ctx, `SELECT d.categories FROM zasp_red_team_definitions d JOIN zasp_security_agent_test_links l ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_definition_id) WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&categories); err != nil {
		t.Fatal(err)
	}
	update := `UPDATE zasp_red_team_definitions d SET categories=$5::jsonb FROM zasp_security_agent_test_links l WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_definition_id) AND (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=($1,$2,$3,$4)`
	if _, err := db.Exec(ctx, update, o, w, e, run, `["authorization_bypass"]`); err != nil {
		t.Fatal(err)
	}
	var unchanged json.RawMessage
	if err := db.QueryRow(ctx, read, o, w, e, run, step).Scan(&unchanged); err != nil || string(unchanged) != string(snapshot) {
		t.Fatalf("definition edit replaced evidence binding: %v", err)
	}
	if _, err := db.Exec(ctx, update, o, w, e, run, categories); err != nil {
		t.Fatal(err)
	}
	if want == "" {
		return
	}
	if _, err := db.Exec(ctx, `SET TIME ZONE 'America/Los_Angeles'`); err != nil {
		t.Fatal(err)
	}
	timezoneErr := db.QueryRow(ctx, read, o, w, e, run, step).Scan(&unchanged)
	if _, err := db.Exec(ctx, `SET TIME ZONE 'UTC'`); err != nil {
		t.Fatal(err)
	}
	if timezoneErr != nil || string(unchanged) != string(snapshot) {
		t.Fatalf("session timezone changed immutable evidence: %v", timezoneErr)
	}
	var exact bool
	if err := db.QueryRow(ctx, `SELECT l.baseline=jsonb_build_object('schema_version','security-agent-test-baseline-v1','run_id',a.run_id,'attempt',a.attempt,'input_digest',encode(a.input_digest,'hex'),'completed_at',to_char(a.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'input_artifact',a.input_artifact,'output_artifact',jsonb_build_object('reference',a.evidence_reference,'key',a.evidence_key,'version_id',a.evidence_version_id,'sha256',encode(a.evidence_checksum,'hex'),'size_bytes',a.evidence_size))
 FROM zasp_security_agent_test_links l JOIN zasp_red_team_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=($1,$2,$3,$6,1)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=($1,$2,$3,$4,$5)`, o, w, e, run, step, want).Scan(&exact); err != nil || !exact {
		t.Fatalf("baseline didn't retain exact attempt and both receipts: %t %v", exact, err)
	}
	// Remove eligibility, then exercise the real idempotent link path. It must
	// keep the enqueue-time snapshot, even if selection would now yield nothing.
	var before, after string
	if err := db.QueryRow(ctx, `SELECT baseline::text FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE zasp_red_team_runs SET definition_version=2 WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND run_id LIKE 'pid_89ba%'`, o, w, e); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, read, o, w, e, run, step).Scan(&unchanged); err == nil {
		t.Fatal("snapshot silently replaced altered baseline")
	}
	if _, err := db.Exec(ctx, `SELECT zasp_security_agent_test_link_enqueue($1,$2,$3,$4,$5,'pid_89ba0000-0000-4000-8000-000000000003')`, o, w, e, run, step); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT baseline::text FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&after); err != nil || after != before {
		t.Fatalf("replay changed baseline: %v", err)
	}
}
