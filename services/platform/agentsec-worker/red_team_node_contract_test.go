package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Exercise Run's version selection and persisted input through the actual Node
// producer and Go verifier. Engine responses and object storage are controlled.
func TestProductionRedTeamRunnerLinkedNodeContract(t *testing.T) {
	node := os.Getenv("ZASP_TEST_NODE")
	if node == "" {
		t.Skip("set ZASP_TEST_NODE to run the Node/Go product contract")
	}
	for _, version := range []string{"red-team-v2", "v2", "red-team-v3", "RED-TEAM-V2", " red-team-v2"} {
		t.Run(version, func(t *testing.T) {
			root := t.TempDir()
			tokenFile := filepath.Join(root, "token")
			if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 64)), 0o400); err != nil {
				t.Fatal(err)
			}
			store := newRedTeamReadbackStore(t)
			calls := 0
			command := redTeamCommandFunc(func(ctx context.Context, _ string, args, environment []string, directory string) error {
				calls++
				inputBytes, err := os.ReadFile(args[2])
				if err != nil {
					return err
				}
				var input redTeamRunnerInput
				if err := json.Unmarshal(inputBytes, &input); err != nil {
					return err
				}
				if input.SchemaVersion != "red-team-runner-input-v2" || input.RunnerImageDigest != "sha256:"+strings.Repeat("e", 64) {
					t.Fatalf("linked run lost version or configured image: %#v", input)
				}
				if len(store.puts) != 1 || !bytes.Equal(store.puts[0].Body, inputBytes) {
					t.Fatal("execution preceded exact input persistence")
				}
				endpoint := "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/linked/evaluate"
				if !containsWorkerString(environment, "ZASP_RED_TEAM_TARGET_ENDPOINT="+endpoint) {
					t.Fatal("linked run used legacy endpoint")
				}
				producer := exec.CommandContext(ctx, node, "--input-type=module", "-e", `
import {comparisonFixture} from '../../../workers/redteam-node/comparison-fixture.mjs';
import {readFileSync,writeFileSync} from 'node:fs';
import {buildPromptfooConfiguration,normalizePromptfooResult,buildRedTeamNativeArtifact} from '../../../workers/redteam-node/runner.mjs';
const input=JSON.parse(readFileSync(process.argv[1],'utf8'));
const config=buildPromptfooConfiguration(input,process.argv[3]);
const document={metadata:{promptfooVersion:'0.121.19'},results:{version:3,results:config.tests.map((test,index)=>({success:index%2===0,provider:{label:'zasp-red-team-adapter'},vars:test.vars,testCase:test,response:{metadata:{http:{status:200}},output:JSON.stringify({target_comparison:comparisonFixture(input),schema_version:'red-team-linked-observation-v1',credential_version_digest:'e'.repeat(64),run_id:input.run_id,category:test.vars.category,observation:{http_status:200,response_digest:'b'.repeat(64),protected:index%2===0}})},gradingResult:{pass:index%2===0}}))}};
writeFileSync(process.argv[2],JSON.stringify(normalizePromptfooResult(input,document)),{mode:0o600,flag:'wx'});
writeFileSync(process.argv[4],JSON.stringify(buildRedTeamNativeArtifact(input,document)),{mode:0o600,flag:'wx'});`, args[2], args[3], endpoint, filepath.Join(directory, "artifact.json"))
				if output, err := producer.CombinedOutput(); err != nil {
					t.Fatalf("Node contract: %s %v", output, err)
				}
				return nil
			})
			runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/zasp/red-team-worker@sha256:" + strings.Repeat("e", 64), Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", TargetTokenFile: tokenFile, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: time.Minute, Clock: func() time.Time { return time.Now().UTC() }})
			if err != nil {
				t.Fatal(err)
			}
			definitionID := "pid_99400002-0000-4000-8000-000000000002"
			result, err := runner.Run(context.Background(), redTeamExecutionRequest{EvidenceVersion: version, LeaseToken: strings.Repeat("a", 32), Scope: fixtureRedTeamScope(t), Run: apiserver.RedTeamRun{ID: "pid_99400001-0000-4000-8000-000000000001", DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1}, Definition: apiserver.RedTeamDefinition{ID: definitionID, Version: 1, TargetID: "pid_99400003-0000-4000-8000-000000000003", TargetKind: "agent_endpoint", Categories: []string{"prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information"}, Safety: apiserver.RedTeamSafety{Environment: "test", CredentialClass: "read_only"}}, InputDigest: sha256.Sum256([]byte("linked-input"))})
			if version != "red-team-v2" {
				if err == nil || calls != 0 || len(store.puts) != 0 {
					t.Fatal("unsupported version executed or persisted input")
				}
				return
			}
			if err != nil || result.Verdict != "fail" || calls != 1 || len(store.puts) != 2 || store.api.gets != 2 || result.InputArtifact == nil {
				t.Fatalf("result=%#v err=%v calls=%d puts=%d", result, err, calls, len(store.puts))
			}
			var bundle map[string]json.RawMessage
			if !bytes.Equal(result.EvidenceArtifact, store.puts[1].Body) {
				t.Fatal("completion lost exact uploaded artifact bytes")
			}
			if json.Unmarshal(store.puts[1].Body, &bundle) != nil || string(bundle["schema_version"]) != `"red-team-evidence-bundle-v2"` || !bytes.Contains(store.puts[1].Body, []byte(`"runner_image_digest":"sha256:`+strings.Repeat("e", 64)+`"`)) {
				t.Fatal("linked bundle lost version/image")
			}
			for _, put := range store.puts {
				if bytes.Contains(put.Body, []byte(strings.Repeat("a", 32))) || bytes.Contains(put.Body, []byte(strings.Repeat("t", 64))) {
					t.Fatal("authority leaked into evidence")
				}
			}
		})
	}
}

// The two actual product implementations must agree for all curated checks.
// This tests their wire contract, not a live engine or provider execution.
func TestRedTeamLinkedArtifactNodeContract(t *testing.T) {
	node := os.Getenv("ZASP_TEST_NODE")
	if node == "" {
		t.Skip("set ZASP_TEST_NODE to run the Node/Go product contract")
	}
	input := redTeamRunnerInput{
		RunnerImageDigest: "sha256:" + strings.Repeat("d", 64), SchemaVersion: "red-team-runner-input-v2", OrganizationID: "pid_99400001-0000-4000-8000-000000000001", WorkspaceID: "pid_99400002-0000-4000-8000-000000000002", EnvironmentID: "pid_99400003-0000-4000-8000-000000000003", RunID: "pid_99400004-0000-4000-8000-000000000004", DefinitionID: "pid_99400005-0000-4000-8000-000000000005", DefinitionVersion: 1, TargetID: "pid_99400006-0000-4000-8000-000000000006", TargetKind: "agent_endpoint", InputDigest: strings.Repeat("a", 64),
		Categories: []string{"prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information"},
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "--input-type=module", "-e", `
import {comparisonFixture} from '../../../workers/redteam-node/comparison-fixture.mjs';
import {readFileSync} from 'node:fs';
import {buildPromptfooConfiguration, normalizePromptfooResult, buildRedTeamNativeArtifact} from '../../../workers/redteam-node/runner.mjs';
const input=JSON.parse(readFileSync(0,'utf8'));
const config=buildPromptfooConfiguration(input,'https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/linked/evaluate');
const document={metadata:{promptfooVersion:'0.121.19'},results:{version:3,results:config.tests.map((test,index)=>({success:index%2===0,provider:{label:'zasp-red-team-adapter'},vars:test.vars,testCase:test,response:{metadata:{http:{status:200}},output:JSON.stringify({target_comparison:comparisonFixture(input),schema_version:'red-team-linked-observation-v1',credential_version_digest:'e'.repeat(64),run_id:input.run_id,category:test.vars.category,observation:{http_status:200,response_digest:'b'.repeat(64),protected:index%2===0}})},gradingResult:{pass:index%2===0}}))}};
process.stdout.write(JSON.stringify({summary:normalizePromptfooResult(input,document),artifact:buildRedTeamNativeArtifact(input,document)}));`)
	command.Stdin = bytes.NewReader(body)
	produced, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Node product contract: %s %v", produced, err)
	}
	var wire struct {
		Summary  json.RawMessage `json:"summary"`
		Artifact json.RawMessage `json:"artifact"`
	}
	if err := json.Unmarshal(produced, &wire); err != nil {
		t.Fatal(err)
	}
	var summary redTeamRunnerOutput
	if err := decodeRedTeamEvidenceJSON(input, wire.Summary, &summary); err != nil {
		t.Fatal(err)
	}
	receipt := &apiserver.RedTeamArtifactReference{Reference: "s3://zasp-evidence/input", VersionID: "immutable-1", SHA256: strings.Repeat("c", 64), SizeBytes: 512}
	if _, err := buildRedTeamEvidenceBundle(input, summary, receipt, wire.Artifact); err != nil {
		t.Fatalf("Node/Go six-check contract differs: %v", err)
	}
	var artifact redTeamNativeArtifact
	if err := decodeRedTeamEvidenceJSON(input, wire.Artifact, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.EvaluationIdentity.Checks[0], artifact.EvaluationIdentity.Checks[1] = artifact.EvaluationIdentity.Checks[1], artifact.EvaluationIdentity.Checks[0]
	reordered, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildRedTeamEvidenceBundle(input, summary, receipt, reordered); err == nil {
		t.Fatal("reordered check identity accepted")
	}
}
