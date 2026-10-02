package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

func TestCompletedComparisonBindingFixedVector(t *testing.T) {
	// Independently counted UTF-8 length prefixes: category payload is
	// "1:216:prompt_injection10:tool_abuse" (35 bytes); versions are 1:7 and 2:11.
	v := &redteamadapter.TargetComparison{Schema: "red-team-target-comparison-v1", Organization: "pid_99400001-0000-4000-8000-000000000001", Workspace: "pid_99400002-0000-4000-8000-000000000002", Environment: "pid_99400003-0000-4000-8000-000000000003", Definition: "pid_99400004-0000-4000-8000-000000000004", DefinitionVersion: 7, Target: "pid_99400005-0000-4000-8000-000000000005", Kind: "agent_endpoint", Categories: []string{"prompt_injection", "tool_abuse"}, Safety: strings.Repeat("a", 64), Endpoint: strings.Repeat("b", 64), Configuration: strings.Repeat("c", 64), Credential: "pid_99400006-0000-4000-8000-000000000006", CredentialVersion: 11, CredentialDigest: strings.Repeat("d", 64)}
	if got := testComparisonBinding(v); got != "35b24189b40cce9e16339d0380cfe8a5fb8d38ef216990df5b79fd1914d47309" {
		t.Fatal("comparison encoding changed", got)
	}
	v.Categories = []string{"tool_abuse", "prompt_injection"}
	if testComparisonBinding(v) == "35b24189b40cce9e16339d0380cfe8a5fb8d38ef216990df5b79fd1914d47309" {
		t.Fatal("ordered categories collapsed")
	}
}

func TestCompletedComparisonBindingCategoryCountIsInjective(t *testing.T) {
	a := &redteamadapter.TargetComparison{Categories: []string{"abcdefghij" + strings.Repeat("8:abcdefgh", 10)}}
	b := &redteamadapter.TargetComparison{Categories: []string{"abcdefghij"}}
	for n := 0; n < 10; n++ {
		b.Categories = append(b.Categories, "abcdefgh")
	}
	if testComparisonBinding(a) == testComparisonBinding(b) {
		t.Fatal("category count merged with first byte length")
	}
}

func capturedEvidenceFixture(t *testing.T, d *existingTestEvidenceDriver, q *existingTestEvidenceRequest, recovered bool) {
	t.Helper()
	var input redTeamRunnerInput
	for l, o := range d.objects {
		if "s3://zasp-evidence/"+l.Key == q.InputArtifact.Reference {
			if json.Unmarshal(o.Body, &input) != nil {
				t.Fatal("input fixture")
			}
		}
	}
	parent, step := snapshotRun, snapshotStep
	effect := sha256.Sum256([]byte(strings.Join([]string{"zasp-temporal-effect-v1", input.OrganizationID, input.WorkspaceID, input.EnvironmentID, parent, step, "1"}, "\x1f")))
	captured := &capturedTestEvidence{}
	for _, o := range q.Observations {
		captured.Observations = append(captured.Observations, capturedTestObservation{Schema: o.SchemaVersion, RunID: o.RunID, Category: o.Category, ComparisonDigest: testComparisonBinding(o.TargetComparison), CredentialDigest: o.CredentialVersionDigest, Observation: o.Observation})
		wire := fmt.Sprintf(`{"schema_version":"red-team-target-v1","run_id":%q,"target_id":%q,"target_kind":%q,"category":%q,"input":%q}`, input.RunID, input.TargetID, input.TargetKind, o.Category, redTeamCuratedPrompt(o.Category))
		digest := sha256.Sum256([]byte(wire))
		captured.Receipts = append(captured.Receipts, completedTestReceipt{Organization: input.OrganizationID, Workspace: input.WorkspaceID, Environment: input.EnvironmentID, Parent: parent, Run: input.RunID, Step: step, Effect: hex.EncodeToString(effect[:]), Generation: 1, Category: o.Category, InputDigest: input.InputDigest, RequestDigest: hex.EncodeToString(digest[:]), State: "completed", Attempt: 1, HTTPStatus: 200, Protected: o.Observation.Protected, ResponseDigest: o.Observation.ResponseDigest, CredentialDigest: o.CredentialVersionDigest, CompletedAt: "2026-09-25T12:00:00.123456Z", ResolutionDigest: strings.Repeat("f", 64)})
	}
	q.Captured = captured
	q.Observations = nil
	if !recovered {
		return
	}
	module, err := filepath.Abs("../../../workers/redteam-node/runner.mjs")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"input": input, "authority": map[string]any{"parent_run_id": parent, "step_id": step, "effect_key": hex.EncodeToString(effect[:]), "generation": 1}, "receipts": captured.Receipts})
	command := exec.Command("node", "--input-type=module", "-e", `import{pathToFileURL}from'node:url';let s='';for await(const b of process.stdin)s+=b;const q=JSON.parse(s),r=await import(pathToFileURL(process.argv[2]));process.stdout.write(JSON.stringify(r.buildCompletedReceiptArtifact(q.input,q.authority,q.receipts)));`, "owned-fixture", module)
	command.Stdin = bytes.NewReader(request)
	body, err := command.Output()
	if err != nil {
		t.Fatal("actual Node artifact", err)
	}
	var artifact map[string]json.RawMessage
	if json.Unmarshal(body, &artifact) != nil {
		t.Fatal("Node artifact JSON")
	}
	artifact["input_artifact"], _ = json.Marshal(q.InputArtifact)
	body, _ = json.Marshal(artifact)
	for l, o := range d.objects {
		if "s3://zasp-evidence/"+l.Key == q.OutputArtifact.Reference {
			o.Body = body
			o.Size = int64(len(body))
			o.SHA256 = sha256.Sum256(body)
			d.objects[l] = o
			q.OutputArtifact.SizeBytes = o.Size
			q.OutputArtifact.SHA256 = hex.EncodeToString(o.SHA256[:])
			return
		}
	}
	t.Fatal("output fixture absent")
}

func TestCompletedEvidenceAllComparisonFormats(t *testing.T) {
	for _, beforeRecovered := range []bool{false, true} {
		for _, afterRecovered := range []bool{false, true} {
			t.Run(fmt.Sprintf("before_%t_after_%t", beforeRecovered, afterRecovered), func(t *testing.T) {
				store, driver, before := fixtureExistingTestEvidence(t, false, true)
				_, next, after := fixtureExistingTestEvidence(t, true, true)
				capturedEvidenceFixture(t, driver, &before, beforeRecovered)
				capturedEvidenceFixture(t, next, &after, afterRecovered)
				for l, o := range next.objects {
					driver.objects[l] = o
				}
				result := verifyExistingTestComparison(context.Background(), store, &before, after)
				if result.Outcome != "remediated" || result.Reason != "test_condition_changed" || len(result.Checks) != 2 || result.Checks[0].BeforeProtected || !result.Checks[0].AfterProtected || !result.Checks[1].BeforeProtected || result.Checks[0].CheckID != "zasp.curated.prompt_injection.v1" {
					t.Fatalf("comparison criteria lost: %#v", result)
				}
			})
		}
	}
}

func TestCompletedEvidenceRejectsUnboundArtifacts(t *testing.T) {
	for _, mutation := range []string{"missing_metadata", "receipt_result", "receipt_identity", "comparison_missing", "duplicate_category", "artifact_image", "artifact_recipe", "artifact_input", "artifact_result", "artifact_extra", "artifact_alias", "artifact_null"} {
		t.Run(mutation, func(t *testing.T) {
			store, driver, q := fixtureExistingTestEvidence(t, true)
			capturedEvidenceFixture(t, driver, &q, true)
			switch mutation {
			case "missing_metadata":
				q.Captured = nil
			case "receipt_result":
				q.Captured.Receipts[0].ResponseDigest = strings.Repeat("c", 64)
			case "receipt_identity":
				q.Captured.Receipts[0].Parent = q.TargetID
			case "comparison_missing":
				q.Captured.Observations[0].ComparisonDigest = ""
			case "duplicate_category":
				q.Captured.Observations = append(q.Captured.Observations, q.Captured.Observations[0])
			case "artifact_image":
				driver.rewrite(t, &q.OutputArtifact, `"runner_image_digest":"sha256:`+strings.Repeat("d", 64)+`"`, `"runner_image_digest":"sha256:`+strings.Repeat("c", 64)+`"`)
			case "artifact_recipe":
				driver.rewrite(t, &q.OutputArtifact, `zasp.curated.prompt_injection.v1`, `zasp.curated.prompt_injection.v2`)
			case "artifact_input":
				driver.rewrite(t, &q.OutputArtifact, `"input_digest":"`+q.InputDigest+`"`, `"input_digest":"`+strings.Repeat("c", 64)+`"`)
			case "artifact_result":
				driver.rewrite(t, &q.OutputArtifact, `"protected":true`, `"protected":false`)
			case "artifact_extra":
				driver.rewrite(t, &q.OutputArtifact, `"schema_version":"red-team-completed-receipts-v1"`, `"schema_version":"red-team-completed-receipts-v1","native_output":{}`)
			case "artifact_alias":
				driver.rewrite(t, &q.OutputArtifact, `"captured_evaluation_identity":`, `"Captured_evaluation_identity":`)
			case "artifact_null":
				driver.rewrite(t, &q.OutputArtifact, `"protected":true`, `"protected":null`)
			}
			if _, err := readExistingTestEvidence(context.Background(), store, q); err == nil {
				t.Fatal("unbound recovered evidence accepted")
			}
		})
	}
}
