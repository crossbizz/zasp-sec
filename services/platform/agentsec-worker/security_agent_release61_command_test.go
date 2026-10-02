package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

type release61ArtifactDriver struct {
	orderedFileArtifactDriver
	fired bool
}

func (d *release61ArtifactDriver) Put(ctx context.Context, v artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	result, err := d.orderedFileArtifactDriver.Put(ctx, v)
	if err == nil && d.failArtifact("put", result.Body) {
		return artifactstore.DriverObject{}, errWorkerExecution
	}
	return result, err
}

func (d *release61ArtifactDriver) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	result, err := d.orderedFileArtifactDriver.Get(ctx, v)
	if err == nil && d.failArtifact("get", result.Body) {
		return artifactstore.DriverObject{}, errWorkerExecution
	}
	return result, err
}

func (d *release61ArtifactDriver) failArtifact(operation string, body []byte) bool {
	var schema struct {
		Schema string `json:"schema_version"`
	}
	fault := os.Getenv("ZASP_RELEASE61_ARTIFACT_FAULT")
	if !d.fired && json.Unmarshal(body, &schema) == nil && (fault == "output_"+operation && schema.Schema == "red-team-evidence-bundle-v2" || fault == "input_"+operation && schema.Schema == "red-team-runner-input-v2") {
		d.fired = true
		return true
	}
	return false
}

func (d *release61ArtifactDriver) ObjectReference(v artifactstore.DriverLocator) (string, error) {
	return "s3://zasp-release61-component/" + v.Key, nil
}
func (d *release61ArtifactDriver) PlannedObjectReference(v artifactstore.DriverLocator) (string, error) {
	return d.ObjectReference(v)
}

// Component-only command fixture: real private journal and TLS invocation,
// controlled Promptfoo-shaped output. This is not proof of live Promptfoo.
func release61ComponentRunner(t *testing.T, r *securityAgentRelease61Runtime, store artifactstore.ObjectReferencingArtifactStore, _ *httptest.Server) *productionRedTeamRunner {
	root := t.TempDir()
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0400); err != nil {
		t.Fatal(err)
	}
	ca := writeRedTeamTestCA(t, root)
	command := redTeamCommandFunc(func(ctx context.Context, executable string, args, env []string, dir string) error {
		if executable != "/usr/local/bin/node" || len(args) != 4 || args[0] != "/app/redteam-runner.mjs" || args[1] != "run" || !containsWorkerString(env, "ZASP_RED_TEAM_RUN_LEASE="+r.planning.LeaseToken) {
			return errWorkerExecution
		}
		body, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var input redTeamRunnerInput
		if decodeStrictWorkerJSON(body, &input) != nil {
			return errWorkerExecution
		}
		categories, _ := json.Marshal(input.Categories)
		child := exec.CommandContext(ctx, os.Getenv("ZASP_RELEASE61_ADAPTER_BINARY"), "-test.run=^TestRelease61OwnedHTTPS$", "-test.v", "-test.timeout=50s")
		child.WaitDelay = 5 * time.Second
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "ZASP_ORDERED_JOURNAL_OWNER_DSN="+os.Getenv("ZASP_ORDERED_PLANNING_DSN"), "ZASP_ORDERED_ORG="+input.OrganizationID, "ZASP_ORDERED_WORKSPACE="+input.WorkspaceID, "ZASP_ORDERED_ENVIRONMENT="+input.EnvironmentID, "ZASP_ORDERED_TEST_RUN="+input.RunID, "ZASP_ORDERED_LEASE="+r.planning.LeaseToken, "ZASP_RELEASE61_CATEGORIES="+string(categories), "ZASP_RELEASE61_TARGET="+input.TargetID, "ZASP_RELEASE61_KIND="+input.TargetKind)
		fault := os.Getenv("ZASP_RELEASE61_JOURNAL_FAULT")
		child.Env = append(child.Env, "ZASP_RELEASE61_JOURNAL_FAULT="+fault)
		child.Env = append(child.Env, "ZASP_RELEASE61_JOURNAL_CATEGORY="+os.Getenv("ZASP_RELEASE61_JOURNAL_CATEGORY"))
		output, err := child.CombinedOutput()
		t.Log(string(output))
		if err != nil || !strings.Contains(string(output), "--- PASS: TestRelease61OwnedHTTPS") || strings.Contains(string(output), "--- SKIP:") {
			return errWorkerExecution
		}
		if fault != "" {
			if !strings.Contains(string(output), "release61 journal fault joined: "+fault) {
				t.Fatal("journal fault not proven")
			}
			return errWorkerExecution
		}
		state, err := r.read(ctx)
		if err != nil || state.Test.TestRunID != input.RunID || state.Test.InputBody != string(body) {
			return errWorkerExecution
		}
		observations := map[string]redteamadapter.LinkedObservationResponse{}
		for _, item := range state.Test.Observations {
			var observed redteamadapter.LinkedObservationResponse
			if item.State != "completed" || json.Unmarshal(item.Observation, &observed) != nil {
				return errWorkerExecution
			}
			observations[item.Category] = observed
		}
		native := redTeamNativeArtifact{SchemaVersion: "red-team-native-artifact-v2", RedactionPolicy: "red-team-artifact-redaction-v2", RunID: input.RunID, InputDigest: input.InputDigest, EvaluationIdentity: expectedRedTeamEvaluationIdentity(input), NativeOutput: &redTeamNativeOutput{}}
		native.NativeOutput.Metadata.PromptfooVersion = "0.121.19"
		native.NativeOutput.Results.Version = 3
		summary := redTeamRunnerOutput{SchemaVersion: "red-team-evidence-v2", Engine: "promptfoo", EngineVersion: "0.121.19", RunID: input.RunID, InputDigest: input.InputDigest, Objective: "Evaluate curated categories: " + strings.Join(input.Categories, ", "), Verdict: "pass"}
		passed := 0
		for _, category := range input.Categories {
			observation, ok := observations[category]
			if !ok || observation.Observation.Protected == nil {
				return errWorkerExecution
			}
			protected := *observation.Observation.Protected
			record := redTeamNativeResult{Success: &protected}
			record.Provider.Label = "zasp-red-team-adapter"
			record.Vars.Category = category
			record.Vars.Prompt = redTeamCuratedPrompt(category)
			record.TestCase.Metadata.Category = category
			record.TestCase.Assert = []redTeamNativeAssertion{{Type: "javascript", Value: redTeamLinkedAssertion}}
			record.Response.Output = "[REDACTED]"
			status := observation.Observation.HTTPStatus
			record.Response.Metadata.HTTP.Status = &status
			record.Response.LinkedObservation = &observation
			record.GradingResult.Pass = &protected
			record.GradingResult.Reason = "[REDACTED]"
			native.NativeOutput.Results.Results = append(native.NativeOutput.Results.Results, record)
			suffix := "unsafe behavior observed"
			if protected {
				passed++
				suffix = "protected"
			} else {
				summary.Verdict = "fail"
			}
			summary.Evidence = append(summary.Evidence, category+": "+suffix)
		}
		summary.Behavior = fmt.Sprintf("%d of %d curated security checks passed; %d exposed unsafe behavior.", passed, len(input.Categories), len(input.Categories)-passed)
		nativeBody, _ := json.Marshal(native)
		summaryBody, _ := json.Marshal(summary)
		if writeRedTeamFile(filepath.Join(dir, "artifact.json"), nativeBody) != nil || writeRedTeamFile(args[3], summaryBody) != nil {
			return errWorkerExecution
		}
		return nil
	})
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/zasp-red-team@sha256:" + strings.Repeat("a", 64), Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", TargetTokenFile: token, TargetCAFile: ca, TempRoot: root, Timeout: 60 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}
