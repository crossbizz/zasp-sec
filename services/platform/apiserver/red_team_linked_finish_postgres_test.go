package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Controlled artifact bytes, not proof of an uploaded object or engine run.
func refreshLinkedFinishArtifact(t *testing.T, args []any, runnerInput map[string]any, comparison json.RawMessage) {
	t.Helper()
	var input, evidence any
	if json.Unmarshal([]byte(args[17].(string)), &input) != nil || json.Unmarshal([]byte(args[11].(string)), &evidence) != nil {
		t.Fatal("invalid artifact fixture")
	}
	var nativeOutput any
	if comparison == nil {
		comparison, _ = json.Marshal(map[string]any{"schema_version": "red-team-target-comparison-v1", "organization_id": runnerInput["organization_id"], "workspace_id": runnerInput["workspace_id"], "environment_id": runnerInput["environment_id"], "test_definition_id": runnerInput["definition_id"], "test_definition_version": runnerInput["definition_version"], "target_id": runnerInput["target_id"], "target_kind": runnerInput["target_kind"], "categories": runnerInput["categories"], "safety_digest": strings.Repeat("a", 64), "endpoint_digest": strings.Repeat("b", 64), "configuration_digest": strings.Repeat("c", 64), "credential_binding_id": runnerInput["target_id"], "credential_binding_version": 1, "credential_binding_digest": strings.Repeat("d", 64)})
	}
	if args[7] != "engine_error" {
		var records []any
		for index, category := range []string{"prompt_injection", "tool_abuse", "data_leakage"} {
			protected := args[7] != "fail" || index != 1
			records = append(records, map[string]any{"success": protected, "vars": map[string]any{"category": category}, "response": map[string]any{"linked_observation": map[string]any{"target_comparison": comparison, "schema_version": "red-team-linked-observation-v1", "run_id": args[3], "category": category, "credential_version_digest": strings.Repeat("d", 64), "observation": map[string]any{"http_status": 200, "response_digest": strings.Repeat("cd", 32), "protected": protected}}}})
		}
		nativeOutput = map[string]any{"results": map[string]any{"results": records}}
	}
	inputDigest := hex.EncodeToString(args[6].([]byte))
	body, err := json.Marshal(map[string]any{"schema_version": "red-team-evidence-bundle-v2", "input_artifact": input, "summary": map[string]any{"schema_version": "red-team-evidence-v2", "engine": "promptfoo", "engine_version": "0.121.19", "run_id": args[3], "input_digest": inputDigest, "objective": args[8], "behavior": args[9], "verdict": args[7], "error_code": args[10], "evidence": evidence}, "native_artifact": map[string]any{"schema_version": "red-team-native-artifact-v2", "redaction_policy": "red-team-artifact-redaction-v2", "run_id": args[3], "input_digest": inputDigest, "native_output": nativeOutput}})
	if err != nil {
		t.Fatal(err)
	}
	if node := os.Getenv("ZASP_LINKED_FINISH_NODE"); node != "" {
		// Only the engine responses/storage receipt are controlled. The actual
		// product producer constructs both the summary and full native document.
		payload, err := json.Marshal(map[string]any{"input": runnerInput, "inputArtifact": input, "verdict": args[7], "comparison": comparison})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, node, "--input-type=module", "-e", `
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const {buildPromptfooConfiguration,normalizePromptfooResult,buildRedTeamNativeArtifact}=await import(pathToFileURL(process.env.ZASP_LINKED_FINISH_RUNNER));
const {input,inputArtifact,verdict,comparison}=JSON.parse(readFileSync(0,'utf8'));
const config=buildPromptfooConfiguration(input,'https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/linked/evaluate');
const document={metadata:{promptfooVersion:'0.121.19'},results:{version:3,results:config.tests.map((test,index)=>{
 const success=verdict!=='engine_error'&&(verdict!=='fail'||index!==1);
 const observation={target_comparison:comparison,schema_version:'red-team-linked-observation-v1',run_id:input.run_id,category:test.vars.category,credential_version_digest:'d'.repeat(64),observation:{http_status:200,response_digest:'cd'.repeat(32),protected:success}};
 return {success,provider:{label:'zasp-red-team-adapter'},vars:test.vars,testCase:test,response:{metadata:{http:{status:verdict==='engine_error'?503:200}},output:verdict==='engine_error'?'unavailable':JSON.stringify(observation)},gradingResult:{pass:success}};
})}};
process.stdout.write(JSON.stringify({schema_version:'red-team-evidence-bundle-v2',input_artifact:inputArtifact,summary:normalizePromptfooResult(input,document),native_artifact:buildRedTeamNativeArtifact(input,document)}));`)
		command.Stdin = bytes.NewReader(payload)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		body, err = command.Output()
		if err != nil {
			t.Fatalf("actual Node evidence producer: %v %s", err, stderr.String())
		}
	}
	digest := sha256.Sum256(body)
	args[15] = digest[:]
	args[16] = int64(len(body))
	args[20] = body
}

func TestSecurityAgentExistingTestWorkerFinishPostgres(t *testing.T) {
	if os.Getenv("ZASP_RECONCILE_INCLUDE_BASELINE") == "true" {
		t.Setenv("ZASP_RECONCILE_BASELINE_ROOT", t.TempDir())
	}
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true, false, false, false, true, true)
}

func exerciseLinkedRedTeamFinish(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, scope domain.Scope, run string, mode int) {
	t.Helper()
	const query = `SELECT zasp_production_security_agent_existing_tests_worker_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21)`
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea)') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("linked finish missing: %v", err)
	}
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	key := "organizations/" + o + "/workspaces/" + w + "/environments/" + e + "/artifacts/" + run
	var digest []byte
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_red_team_runs WHERE run_id=$1`, run).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	var definitionID, targetID, targetKind string
	var definitionVersion int
	if err := owner.QueryRow(ctx, `SELECT test_definition_id,test_definition_version,target_id,target_kind FROM zasp_security_agent_test_links WHERE test_run_id=$1`, run).Scan(&definitionID, &definitionVersion, &targetID, &targetKind); err != nil {
		t.Fatal(err)
	}
	runnerInput := map[string]any{"schema_version": "red-team-runner-input-v2", "organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_id": definitionID, "definition_version": definitionVersion, "target_id": targetID, "target_kind": targetKind, "input_digest": hex.EncodeToString(digest), "runner_image_digest": "sha256:" + strings.Repeat("e", 64), "categories": []string{"prompt_injection", "tool_abuse", "data_leakage"}}
	input := `{"reference":"s3://zasp-evidence/organizations/` + o + `/workspaces/` + w + `/environments/` + e + `/artifacts/pid_99400004-0000-4000-8000-000000000004","version_id":"controlled-input-version","sha256":"` + strings.Repeat("cd", 32) + `","size_bytes":512}`
	inputBytes, err := json.Marshal(runnerInput)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS") == "true" {
		d := sha256.Sum256(inputBytes)
		inputID := fmt.Sprintf("pid_994001%02d-0000-4000-8000-000000000004", mode)
		b, err := json.Marshal(RedTeamArtifactReference{Reference: "s3://zasp-evidence/organizations/" + o + "/workspaces/" + w + "/environments/" + e + "/artifacts/" + inputID, VersionID: "controlled-input-version", SHA256: hex.EncodeToString(d[:]), SizeBytes: int64(len(inputBytes))})
		if err != nil {
			t.Fatal(err)
		}
		input = string(b)
	}
	args := []any{o, w, e, run, "existing-test-linked-worker", []byte(strings.Repeat("b", 32)), digest, "pass", "Evaluate curated categories: prompt_injection", "1 of 1 curated security checks passed; 0 exposed unsafe behavior.", nil, `["prompt_injection: protected"]`, "s3://zasp-evidence/" + key, key, "controlled-output-version", []byte(strings.Repeat("d", 32)), int64(1024), input, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	args[8] = "Evaluate curated categories: prompt_injection, tool_abuse, data_leakage"
	args[9] = "3 of 3 curated security checks passed; 0 exposed unsafe behavior."
	args[11] = `["prompt_injection: protected","tool_abuse: protected","data_leakage: protected"]`
	args = append(args, nil)
	refreshLinkedFinishArtifact(t, args, runnerInput, nil)
	snapshot := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',to_jsonb(r),'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.attempt),'[]'::jsonb) FROM zasp_red_team_attempts a WHERE a.run_id=r.run_id),'journal',(SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY j.attempt,j.category),'[]'::jsonb) FROM zasp_security_agent_test_invocations j WHERE j.test_run_id=r.run_id))::text FROM zasp_red_team_runs r WHERE run_id=$1`, run).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	var raw json.RawMessage
	deny := func(conn *pgx.Conn, values []any, code string) {
		t.Helper()
		before := snapshot()
		err := conn.QueryRow(ctx, query, values...).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != code || snapshot() != before {
			t.Fatalf("finish refusal %s: %s %v", code, raw, err)
		}
	}
	deny(owner, args, "42501")
	config := owner.Config().Copy()
	config.User = "existing_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close(ctx)
	deny(adapter, args, "42501")
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20} {
		bad := append([]any(nil), args...)
		bad[index] = nil
		code := "22023"
		if index == 18 || index == 19 {
			code = "55000"
		}
		deny(worker, bad, code)
	}
	for index, value := range map[int]any{2: "pid_89ffffff-0000-4000-8000-000000000001", 4: "other-worker", 5: []byte(strings.Repeat("c", 32)), 6: []byte(strings.Repeat("f", 32))} {
		bad := append([]any(nil), args...)
		bad[index] = value
		code := "40001"
		if index == 2 {
			code = "22023"
		}
		deny(worker, bad, code)
	}
	deny(worker, args, "40001") // No actual invocation may be called a pass.
	if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,'prompt_injection',decode(repeat('ab',32),'hex'),$6,$7)`, o, w, e, run, args[5], args[18], args[19]).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	deny(worker, args, "40001") // Started is uncertainty, not a protected response.
	if mode != 2 {
		if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,3,$5,'prompt_injection',decode(repeat('ab',32),'hex'),200,decode(repeat('cd',32),'hex'),true,decode(repeat('dd',32),'hex'),$6,$7)`, o, w, e, run, args[5], args[18], args[19]).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		for _, category := range []string{"tool_abuse", "data_leakage"} {
			if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_start($1,$2,$3,$4,$5,$6,decode(repeat('ab',32),'hex'),$7,$8)`, o, w, e, run, args[5], category, args[18], args[19]).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			protected := !(mode == 1 && category == "tool_abuse")
			if err := adapter.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_invocation_complete($1,$2,$3,$4,3,$5,$6,decode(repeat('ab',32),'hex'),200,decode(repeat('cd',32),'hex'),$7,decode(repeat('dd',32),'hex'),$8,$9)`, o, w, e, run, args[5], category, protected, args[18], args[19]).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	if mode == 1 {
		args[7] = "fail"
		args[9] = "2 of 3 curated security checks passed; 1 exposed unsafe behavior."
		args[11] = `["prompt_injection: protected","tool_abuse: unsafe behavior observed","data_leakage: protected"]`
	}
	if mode == 2 {
		args[7] = "engine_error"
		args[9] = "The bounded target adapter did not return a complete evaluation."
		args[10] = "outcome_unknown"
		args[11] = `["Target adapter evaluation did not complete"]`
	}
	var comparison json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT target_resolution->'comparison' FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 ORDER BY category LIMIT 1`, run).Scan(&comparison); err != nil {
		t.Fatal(err)
	}
	refreshLinkedFinishArtifact(t, args, runnerInput, comparison)
	if mode != 2 {
		var tuple map[string]json.RawMessage
		if json.Unmarshal(comparison, &tuple) != nil {
			t.Fatal("invalid comparison fixture")
		}
		for _, field := range []string{"endpoint_digest", "configuration_digest", "safety_digest", "credential_binding_digest"} {
			// Preserve valid format and recompute the bundle checksum: only the
			// journal-owned comparison association should reject this artifact.
			old := `"` + field + `":` + string(tuple[field])
			body := []byte(strings.Replace(string(args[20].([]byte)), old, `"`+field+`":"`+strings.Repeat("e", 64)+`"`, 1))
			if string(body) == string(args[20].([]byte)) {
				t.Fatal("comparison mutation did not change artifact")
			}
			digest := sha256.Sum256(body)
			bad := append([]any(nil), args...)
			bad[15], bad[16], bad[20] = digest[:], int64(len(body)), body
			deny(worker, bad, "40001")
		}
		for _, replacement := range []struct{ old, new string }{
			{strings.Repeat("d", 64), strings.Repeat("e", 64)},
			{`"response_digest":"` + strings.Repeat("cd", 32) + `"`, `"response_digest":"` + strings.Repeat("ef", 32) + `"`},
			{`"category":"prompt_injection"`, `"category":"tool_abuse"`},
			{`"protected":true`, `"protected":false`},
		} {
			bad := append([]any(nil), args...)
			body := []byte(strings.Replace(string(args[20].([]byte)), replacement.old, replacement.new, 1))
			digest := sha256.Sum256(body)
			bad[15] = digest[:]
			bad[16] = int64(len(body))
			bad[20] = body
			deny(worker, bad, "40001")
		}
	}
	badBytes := append([]any(nil), args...)
	badBytes[20] = append(append([]byte(nil), args[20].([]byte)...), ' ')
	deny(worker, badBytes, "22023") // Exact size and checksum, not semantic JSON equality.
	duplicate := append([]any(nil), args...)
	duplicateBody := []byte(strings.Replace(string(args[20].([]byte)), `"schema_version":"red-team-evidence-bundle-v2"`, `"schema_version":"wrong","schema_version":"red-team-evidence-bundle-v2"`, 1))
	duplicateDigest := sha256.Sum256(duplicateBody)
	duplicate[15] = duplicateDigest[:]
	duplicate[16] = int64(len(duplicateBody))
	duplicate[20] = duplicateBody
	deny(worker, duplicate, "22023")
	bad := append([]any(nil), args...)
	if mode == 1 {
		bad[7] = "pass"
	} else if mode == 2 {
		bad[7] = "pass"
		bad[10] = nil
	} else {
		bad[7] = "fail"
	}
	deny(worker, bad, "40001")
	bad = append([]any(nil), args...)
	bad[11] = `["data_leakage: protected","tool_abuse: protected","prompt_injection: protected"]`
	if mode == 2 {
		deny(worker, bad, "22023")
	} else {
		deny(worker, bad, "40001")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	deny(worker, args, "40001")
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=false WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if mode == 3 {
		for _, boundary := range []string{"lease", "budget"} {
			read := `SELECT lease_expires_at FROM zasp_red_team_runs WHERE run_id=$1`
			shorten := `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
			restore := `UPDATE zasp_red_team_runs SET lease_expires_at=$2 WHERE run_id=$1`
			if boundary == "budget" {
				read = `SELECT deadline_at FROM zasp_security_agent_run_budgets WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`
				shorten = `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1) RETURNING deadline_at`
				restore = `UPDATE zasp_security_agent_run_budgets SET deadline_at=$2 WHERE run_id=(SELECT run_id FROM zasp_security_agent_test_links WHERE test_run_id=$1)`
			}
			var original, deadline time.Time
			if err := owner.QueryRow(ctx, read, run).Scan(&original); err != nil {
				t.Fatal(err)
			}
			if err := owner.QueryRow(ctx, shorten, run).Scan(&deadline); err != nil {
				t.Fatal(err)
			}
			before := snapshot()
			err := existingTestAcceptanceWait(t, ctx, owner, worker, run, "finish_"+boundary, func() error { return worker.QueryRow(ctx, query, args...).Scan(&raw) }, deadline)
			after := snapshot()
			if _, restoreErr := owner.Exec(ctx, restore, run, original); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" || before != after {
				t.Fatalf("finish crossed %s after observed wait: %v", boundary, err)
			}
		}
	}
	if os.Getenv("ZASP_TEST_EXISTING_SETTLEMENT_RECOVERY") == "true" && mode == 2 {
		var parent, step string
		if err := owner.QueryRow(ctx, `SELECT run_id,step_id FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&parent, &step); err != nil {
			t.Fatal(err)
		}
		assertExistingTestSettlement(t, ctx, owner, o, w, e, parent, step)
		assertExistingTestLateCompletionAfterSettlement(t, ctx, owner, o, w, e, run, parent, step, args[5].([]byte))
		return
	}
	client, err := NewLinkedRedTeamExecutionRepository(existingTestJournalDatabase{worker})
	if err != nil {
		t.Fatal(err)
	}
	completion := RedTeamRunCompletion{RunID: run, Worker: args[4].(string), LeaseToken: string(args[5].([]byte)), Verdict: args[7].(string), Objective: args[8].(string), Behavior: args[9].(string), EvidenceReference: args[12].(string), EvidenceKey: key, EvidenceVersionID: args[14].(string), EvidenceChecksum: args[15].([]byte), EvidenceSizeBytes: args[16].(int64)}
	copy(completion.InputDigest[:], digest)
	completion.EvidenceArtifact = append([]byte(nil), args[20].([]byte)...)
	if args[10] != nil {
		completion.ErrorCode = args[10].(string)
	}
	if json.Unmarshal([]byte(input), &completion.InputArtifact) != nil || json.Unmarshal([]byte(args[11].(string)), &completion.Evidence) != nil {
		t.Fatal("invalid fixture")
	}
	result, err := client.FinishRedTeamRun(ctx, scope, completion)
	if err != nil || result.ID != run || result.Status != "complete" || result.Verdict != args[7] || result.Attempt != 3 {
		t.Fatalf("finish response: %#v %v", result, err)
	}
	var persisted bool
	if err := owner.QueryRow(ctx, `SELECT r.state='complete' AND r.lease_token IS NULL AND a.input_artifact=$2::jsonb AND a.evidence_version_id=$3 AND a.evidence_checksum=$4 AND a.input_digest=$5 AND a.verdict=$6 FROM zasp_red_team_runs r JOIN zasp_red_team_attempts a USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND a.attempt=3`, run, input, args[14], args[15], digest, args[7]).Scan(&persisted); err != nil || !persisted {
		t.Fatalf("completion not durably associated: %t %v", persisted, err)
	}
	if mode == 2 {
		var retained bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(state='started') FROM zasp_security_agent_test_invocations WHERE test_run_id=$1`, run).Scan(&retained); err != nil || !retained {
			t.Fatalf("uncertainty discarded: %t %v", retained, err)
		}
	}
	deny(worker, args, "40001") // Duplicate finish cannot rewrite immutable receipts.
	if os.Getenv("ZASP_RECONCILE_COMPOSE_ARTIFACTS") == "true" {
		value := map[string]any{"input": inputBytes, "output": args[20], "mode": mode}
		if os.Getenv("ZASP_RECONCILE_INCLUDE_BASELINE") == "true" && mode == 3 {
			previous, err := os.ReadFile(filepath.Join(os.Getenv("ZASP_RECONCILE_BASELINE_ROOT"), "failed-attempt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var saved struct{ Input, Output []byte }
			if err := json.Unmarshal(previous, &saved); err != nil {
				t.Fatal(err)
			}
			value["baseline_input"], value["baseline_output"] = saved.Input, saved.Output
		}
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "reconcile-artifacts.json")
		if err := os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if os.Getenv("ZASP_RECONCILE_INCLUDE_BASELINE") == "true" && mode == 1 {
			if err := os.WriteFile(filepath.Join(os.Getenv("ZASP_RECONCILE_BASELINE_ROOT"), "failed-attempt.json"), payload, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("ZASP_RECONCILE_ARTIFACT_FILE", path)
	}
	assertExistingTestEvidenceSnapshot(t, ctx, owner, worker, scope, run, mode == 2)
}
