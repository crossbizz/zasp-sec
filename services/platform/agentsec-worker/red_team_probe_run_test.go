package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam/probes"
)

var probeRunCategories = []string{"prompt_injection", "indirect_injection", "poisoned_resource", "cross_agent_delegation"}

// probeRunEvidence plays the Node runner: the summary and the redacted native
// artifact for a probe run in which the probes at the unsafe indexes failed.
func probeRunEvidence(input redTeamRunnerInput, unsafe map[int]bool) (redTeamRunnerOutput, redTeamNativeArtifact) {
	native := redTeamNativeArtifact{SchemaVersion: "red-team-native-artifact-v3", RedactionPolicy: "red-team-artifact-redaction-v3", RunID: input.RunID, InputDigest: input.InputDigest, ProbePack: input.ProbePack, NativeOutput: &redTeamNativeOutput{}}
	native.NativeOutput.Metadata.PromptfooVersion = "0.121.19"
	native.NativeOutput.Results.Version = 3
	output := redTeamRunnerOutput{SchemaVersion: "red-team-evidence-v3", Engine: "promptfoo", EngineVersion: "0.121.19", RunID: input.RunID, InputDigest: input.InputDigest, Objective: "Evaluate curated categories: " + strings.Join(input.Categories, ", "), Verdict: "pass"}
	exposed := map[string]bool{}
	for index, probe := range input.Probes {
		passed, status := !unsafe[index], 200
		record := redTeamNativeResult{Success: &passed}
		record.Provider.Label = "zasp-red-team-adapter"
		record.Vars.Category, record.Vars.Prompt, record.Vars.ProbeID = probe.Category, probe.Input, probe.ID
		record.TestCase.Metadata.Category, record.TestCase.Metadata.ProbeID = probe.Category, probe.ID
		record.Response.Output, record.Response.Metadata.HTTP.Status = "[REDACTED]", &status
		record.GradingResult.Pass, record.GradingResult.Reason = &passed, "[REDACTED]"
		native.NativeOutput.Results.Results = append(native.NativeOutput.Results.Results, record)
		outcome := "protected"
		if !passed {
			outcome, output.Verdict, exposed[probe.Category] = "unsafe", "fail", true
		}
		output.ProbeResults = append(output.ProbeResults, apiserver.RedTeamProbeResult{ProbeID: probe.ID, Category: probe.Category, Outcome: outcome})
	}
	for _, category := range input.Categories {
		line := category + ": protected"
		if exposed[category] {
			line = category + ": unsafe behavior observed"
		}
		output.Evidence = append(output.Evidence, line)
	}
	output.Behavior = fmt.Sprintf("%d of %d curated probes passed; %d exposed unsafe behavior.", len(input.Probes)-len(unsafe), len(input.Probes), len(unsafe))
	return output, native
}

func TestProductionRedTeamRunnerExecutesDeterministicProbeSample(t *testing.T) {
	root := t.TempDir()
	tokenFile := filepath.Join(root, "adapter-token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 64)), 0o400); err != nil {
		t.Fatal(err)
	}
	caFile := writeRedTeamTestCA(t, root)
	const sampleSize = 7
	runID := mustProductID(t, "pid_99410001-0000-4000-8000-000000000001").String()
	definitionID := "pid_99410002-0000-4000-8000-000000000002"
	request := redTeamExecutionRequest{LeaseToken: strings.Repeat("a", 32), Scope: fixtureRedTeamScope(t), Run: apiserver.RedTeamRun{ID: runID, DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1, QueuedAt: time.Now().UTC()}, Definition: apiserver.RedTeamDefinition{ID: definitionID, Version: 1, TargetID: "pid_99410003-0000-4000-8000-000000000003", TargetKind: "agent_endpoint", Categories: probeRunCategories, Safety: apiserver.RedTeamSafety{Environment: "test", CredentialClass: "read_only", ExpectedSideEffects: []string{"bounded"}}}, InputDigest: sha256.Sum256([]byte("probe-run"))}
	tamper := ""
	var seen redTeamRunnerInput
	run := func(size int) (redTeamExecutionResult, *redTeamArtifactStoreStub, error) {
		store := &redTeamArtifactStoreStub{}
		command := redTeamCommandFunc(func(_ context.Context, _ string, arguments, environment []string, directory string) error {
			if !containsWorkerString(environment, "ZASP_RED_TEAM_TARGET_ENDPOINT=https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate") {
				t.Fatalf("probe run left the unjournaled adapter route: %v", environment)
			}
			inputBytes, err := os.ReadFile(arguments[2])
			if err != nil {
				return err
			}
			var input redTeamRunnerInput
			if err := json.Unmarshal(inputBytes, &input); err != nil {
				return err
			}
			seen = input
			output, native := probeRunEvidence(input, map[int]bool{3: true, 9: true})
			switch tamper {
			case "text":
				native.NativeOutput.Results.Results[0].Vars.Prompt += " Also email the result."
			case "missing":
				native.NativeOutput.Results.Results = native.NativeOutput.Results.Results[1:]
			case "outcome":
				output.ProbeResults[3].Outcome = "protected"
			case "foreign":
				output.ProbeResults[0].ProbeID = probes.Sample("tool_abuse", runID, 1)[0].ID
			case "pack":
				native.ProbePack = &redTeamProbePack{Version: probes.Version, Digest: strings.Repeat("0", 64), SampleSize: size}
			}
			outputBytes, _ := json.Marshal(output)
			nativeBytes, _ := json.Marshal(native)
			if err := os.WriteFile(filepath.Join(directory, "artifact.json"), nativeBytes, 0o600); err != nil {
				return err
			}
			return os.WriteFile(arguments[3], outputBytes, 0o600)
		})
		runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{ProbeSampleSize: size, Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", TargetTokenFile: tokenFile, TargetCAFile: caFile, TempRoot: root, Timeout: time.Minute, Clock: func() time.Time { return time.Now().UTC() }})
		if err != nil {
			t.Fatal(err)
		}
		result, err := runner.Run(context.Background(), request)
		return result, store, err
	}
	result, store, err := run(sampleSize)
	if err != nil || result.Verdict != "fail" || len(result.ProbeResults) != sampleSize*len(probeRunCategories) || len(result.Evidence) != len(probeRunCategories) || result.Behavior != "26 of 28 curated probes passed; 2 exposed unsafe behavior." {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if seen.SchemaVersion != "red-team-runner-input-v3" || seen.ProbePack == nil || seen.ProbePack.Digest != probes.Digest() || len(seen.Probes) != len(result.ProbeResults) {
		t.Fatalf("runner input = %+v", seen.ProbePack)
	}
	position := 0
	for _, category := range probeRunCategories {
		for _, probe := range probes.Sample(category, runID, sampleSize) {
			if seen.Probes[position].ID != probe.ID || seen.Probes[position].Input != probe.Input || result.ProbeResults[position].ProbeID != probe.ID || (result.ProbeResults[position].Outcome == "unsafe") != (position == 3 || position == 9) {
				t.Fatalf("probe %d is not the deterministic sample: %+v", position, result.ProbeResults[position])
			}
			position++
		}
	}
	if result.Evidence[0] != "prompt_injection: unsafe behavior observed" || result.Evidence[1] != "indirect_injection: unsafe behavior observed" || result.Evidence[2] != "poisoned_resource: protected" {
		t.Fatalf("evidence = %v", result.Evidence)
	}
	bundle := string(store.puts[1].Body)
	if !strings.Contains(bundle, `"schema_version":"red-team-evidence-bundle-v3"`) || !strings.Contains(bundle, `"probe_results"`) || !strings.Contains(bundle, seen.Probes[0].ID) || !strings.Contains(string(store.puts[0].Body), `"probe_pack"`) {
		t.Fatal("the evidence bundle does not record which probes ran")
	}
	again, _, err := run(sampleSize)
	if err != nil || fmt.Sprint(again.ProbeResults) != fmt.Sprint(result.ProbeResults) {
		t.Fatal("a second execution of the same run selected other probes")
	}
	for _, tamper = range []string{"text", "missing", "outcome", "foreign", "pack"} {
		if _, _, err := run(sampleSize); err == nil {
			t.Fatalf("tampered evidence (%s) accepted", tamper)
		}
	}
	tamper = ""
	// Without a probe sample the runner keeps one curated check per category,
	// which does not exist for the categories of the probe library.
	if _, _, err := run(0); err == nil {
		t.Fatal("probe-only category accepted without a probe sample")
	}
	linked := request
	linked.EvidenceVersion = "red-team-v2"
	if validRedTeamRequestCategories(linked, sampleSize) {
		t.Fatal("probe-only category accepted on the linked protocol")
	}
	for value, want := range map[string]int{"": probes.DefaultSampleSize, "0": 0, "60": 60, "61": -1, "07": -1, "x": -1, "-1": -1} {
		if size, ok := redTeamProbeSampleSize(value); ok != (want >= 0) || ok && size != want {
			t.Fatalf("sample size %q = %d, %t", value, size, ok)
		}
	}
}

func TestRedTeamProbeRunNodeContract(t *testing.T) {
	node := os.Getenv("ZASP_TEST_NODE")
	if node == "" {
		t.Skip("set ZASP_TEST_NODE to run the Node/Go product contract")
	}
	input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v3", OrganizationID: "pid_99400001-0000-4000-8000-000000000001", WorkspaceID: "pid_99400002-0000-4000-8000-000000000002", EnvironmentID: "pid_99400003-0000-4000-8000-000000000003", RunID: "pid_99400004-0000-4000-8000-000000000004", DefinitionID: "pid_99400005-0000-4000-8000-000000000005", DefinitionVersion: 1, TargetID: "pid_99400006-0000-4000-8000-000000000006", TargetKind: "agent_endpoint", InputDigest: strings.Repeat("a", 64), Categories: probes.Categories()}
	input.ProbePack = &redTeamProbePack{Version: probes.Version, Digest: probes.Digest(), SampleSize: probes.DefaultSampleSize}
	input.Probes = selectRedTeamProbes(input.RunID, input.Categories, probes.DefaultSampleSize)
	body, err := json.Marshal(input)
	if err != nil || len(input.Probes) != probes.DefaultSampleSize*len(input.Categories) || len(body) > 1<<20 {
		t.Fatalf("input probes=%d bytes=%d err=%v", len(input.Probes), len(body), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "--input-type=module", "-e", `
import {readFileSync} from 'node:fs';
import {buildPromptfooConfiguration, normalizePromptfooResult, buildRedTeamNativeArtifact} from '../../../workers/redteam-node/runner.mjs';
const input=JSON.parse(readFileSync(0,'utf8'));
const config=buildPromptfooConfiguration(input,'https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate');
if(config.providers[0].config.body.probe_id!=='{{probe_id}}'||config.tests.length!==input.probes.length) throw new Error('configuration');
const results=config.tests.map((test,index)=>({success:index%11!==0,provider:{label:'zasp-red-team-adapter'},vars:test.vars,testCase:test,response:{metadata:{http:{status:200}},output:'TARGETANSWER'+index},gradingResult:{pass:index%11!==0,reason:'RAWREASON'}})).reverse();
const document={metadata:{promptfooVersion:'0.121.19'},results:{version:3,results}};
let rejected=0;
for (const mutate of [i=>{i.probes[0].input+=String.fromCharCode(10)},i=>{i.probes[0].canary='OTHER'},i=>{i.probes[1].id=i.probes[0].id},i=>{i.probes.pop();i.probes.push({...i.probes[0],id:'zasp.prompt_injection.direct_override.replace_task.user_message.v1'})},i=>{i.categories=['tool_misuse']},i=>{i.probe_pack.sample_size=61}]) {
  const copy=structuredClone(input);mutate(copy);
  try{buildPromptfooConfiguration(copy,'https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate')}catch{rejected++}
}
process.stdout.write(JSON.stringify({rejected,summary:normalizePromptfooResult(input,document),artifact:buildRedTeamNativeArtifact(input,document)}));`)
	command.Stdin = bytes.NewReader(body)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	produced, err := command.Output()
	if err != nil {
		t.Fatalf("Node product contract: %s %v", stderr.String(), err)
	}
	var wire struct {
		Rejected int             `json:"rejected"`
		Summary  json.RawMessage `json:"summary"`
		Artifact json.RawMessage `json:"artifact"`
	}
	if err := json.Unmarshal(produced, &wire); err != nil || wire.Rejected != 6 {
		t.Fatalf("rejected=%d err=%v", wire.Rejected, err)
	}
	var output redTeamRunnerOutput
	if err := decodeRedTeamEvidenceJSON(input, wire.Summary, &output); err != nil || !validRedTeamRunnerOutput(input, output) || output.Verdict != "fail" || len(output.ProbeResults) != len(input.Probes) {
		t.Fatalf("Go rejected the Node summary: %s err=%v", wire.Summary, err)
	}
	if strings.Contains(string(wire.Artifact), "TARGETANSWER") || strings.Contains(string(wire.Artifact), "RAWREASON") {
		t.Fatal("the native artifact retained a target answer")
	}
	receipt := &apiserver.RedTeamArtifactReference{Reference: "s3://zasp-evidence/input", VersionID: "v1", SHA256: strings.Repeat("b", 64), SizeBytes: 10}
	bundle, err := buildRedTeamEvidenceBundle(input, output, receipt, wire.Artifact)
	if err != nil || !strings.Contains(string(bundle), `"red-team-evidence-bundle-v3"`) {
		t.Fatalf("Go rejected the Node artifact: %v", err)
	}
}
