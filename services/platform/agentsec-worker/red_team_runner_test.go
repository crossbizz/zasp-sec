package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

func TestProductionRedTeamRunnerInvokesFixedAdapterAndPersistsBoundInputAndNativeEvidence(t *testing.T) {
	root := t.TempDir()
	tokenFile := filepath.Join(root, "adapter-token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("t", 64)), 0o400); err != nil {
		t.Fatal(err)
	}
	caFile := writeRedTeamTestCA(t, root)
	store := &redTeamArtifactStoreStub{}
	command := redTeamCommandFunc(func(_ context.Context, executable string, arguments, environment []string, directory string) error {
		if len(store.puts) != 1 || !strings.Contains(string(store.puts[0].Body), `"schema_version":"red-team-runner-input-v1"`) {
			t.Fatal("exact input artifact must be durable before target execution")
		}
		if executable != "/usr/local/bin/node" || len(arguments) != 4 || arguments[0] != "/app/redteam-runner.mjs" || arguments[1] != "run" || filepath.Dir(arguments[2]) != directory || filepath.Dir(arguments[3]) != directory || !containsWorkerString(environment, "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE="+tokenFile) || !containsWorkerString(environment, "ZASP_RED_TEAM_TARGET_CA_FILE="+caFile) || !containsWorkerString(environment, "ZASP_RED_TEAM_RUN_LEASE="+strings.Repeat("a", 32)) {
			t.Fatalf("command executable=%q args=%#v env=%#v dir=%q", executable, arguments, environment, directory)
		}
		inputBytes, err := os.ReadFile(arguments[2])
		if err != nil {
			return err
		}
		var input redTeamRunnerInput
		if strings.Contains(string(inputBytes), strings.Repeat("a", 32)) || strings.Contains(string(inputBytes), "lease") {
			t.Fatal("lease leaked into persisted runner input")
		}
		if err := json.Unmarshal(inputBytes, &input); err != nil {
			return err
		}
		output := redTeamRunnerOutput{SchemaVersion: "red-team-evidence-v1", Engine: "promptfoo", EngineVersion: "0.121.19", RunID: input.RunID, InputDigest: input.InputDigest, Objective: "Evaluate curated categories: prompt_injection", Behavior: "1 of 1 curated security checks passed; 0 exposed unsafe behavior.", Verdict: "pass", Evidence: []string{"prompt_injection: protected"}}
		bytes, err := json.Marshal(output)
		if err != nil {
			return err
		}
		native := redTeamNativeArtifact{SchemaVersion: "red-team-native-artifact-v1", RedactionPolicy: "red-team-artifact-redaction-v1", RunID: input.RunID, InputDigest: input.InputDigest, NativeOutput: &redTeamNativeOutput{}}
		native.NativeOutput.Metadata.PromptfooVersion = "0.121.19"
		native.NativeOutput.Results.Version = 3
		passed := true
		record := redTeamNativeResult{Success: &passed}
		record.Provider.Label = "zasp-red-team-adapter"
		record.Vars.Category, record.Vars.Prompt = "prompt_injection", redTeamCuratedPrompt("prompt_injection")
		record.TestCase.Metadata.Category = "prompt_injection"
		status := 200
		record.Response.Output, record.Response.Metadata.HTTP.Status = "[REDACTED]", &status
		record.GradingResult.Pass, record.GradingResult.Reason = &passed, "[REDACTED]"
		native.NativeOutput.Results.Results = []redTeamNativeResult{record}
		nativeBytes, err := json.Marshal(native)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, "artifact.json"), nativeBytes, 0o600); err != nil {
			return err
		}
		return os.WriteFile(arguments[3], bytes, 0o600)
	})
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate", TargetTokenFile: tokenFile, TargetCAFile: caFile, TempRoot: root, Timeout: time.Minute, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_99400001-0000-4000-8000-000000000001")
	definitionID := "pid_99400002-0000-4000-8000-000000000002"
	digest := sha256.Sum256([]byte("runner-input"))
	result, err := runner.Run(context.Background(), redTeamExecutionRequest{LeaseToken: strings.Repeat("a", 32), Scope: scope, Run: apiserver.RedTeamRun{ID: runID.String(), DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1, QueuedAt: time.Now().UTC()}, Definition: apiserver.RedTeamDefinition{ID: definitionID, Version: 1, TargetID: "pid_99400003-0000-4000-8000-000000000003", TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, Safety: apiserver.RedTeamSafety{Environment: "test", CredentialClass: "read_only", ExpectedSideEffects: []string{"bounded"}}}, InputDigest: digest})
	if err != nil || result.Verdict != "pass" || result.EvidenceReference == "" || result.EvidenceKey == "" || result.EvidenceVersionID != "version-red-team-1" || len(store.puts) != 2 {
		t.Fatalf("result=%#v err=%v puts=%#v", result, err, store.puts)
	}
	for _, put := range store.puts {
		if strings.Contains(string(put.Body), strings.Repeat("a", 32)) || strings.Contains(string(put.Body), strings.Repeat("t", 32)) {
			t.Fatal("runtime authority entered persistent evidence")
		}
	}
	if result.InputArtifact == nil || result.InputArtifact.Reference == result.EvidenceReference || result.InputArtifact.SizeBytes != int64(len(store.puts[0].Body)) || !strings.Contains(string(store.puts[1].Body), `"schema_version":"red-team-evidence-bundle-v1"`) || !strings.Contains(string(store.puts[1].Body), `"native_artifact"`) || !strings.Contains(string(store.puts[1].Body), result.InputArtifact.Reference) {
		t.Fatal("input reference or native artifact was not retained in the evidence bundle")
	}
}

func writeRedTeamTestCA(t *testing.T, root string) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adapter-ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

type redTeamCommandFunc func(context.Context, string, []string, []string, string) error

func (function redTeamCommandFunc) Run(ctx context.Context, executable string, arguments, environment []string, directory string) error {
	return function(ctx, executable, arguments, environment, directory)
}

type redTeamArtifactStoreStub struct{ puts []artifactstore.PutRequest }

func (store *redTeamArtifactStoreStub) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	store.puts = append(store.puts, request)
	checksum := sha256.Sum256(request.Body)
	return artifactstore.Artifact{Locator: artifactstore.Locator{Scope: request.Scope, Reference: request.Reference, VersionID: "version-red-team-1"}, MediaType: request.MediaType, Body: append([]byte(nil), request.Body...), Size: int64(len(request.Body)), SHA256: checksum}, nil
}
func (*redTeamArtifactStoreStub) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, nil
}
func (*redTeamArtifactStoreStub) Delete(context.Context, artifactstore.Locator) error { return nil }
func (*redTeamArtifactStoreStub) ObjectReference(locator artifactstore.Locator) (string, error) {
	return "s3://zasp-evidence/organizations/" + locator.Scope.OrganizationID().String() + "/workspaces/" + locator.Scope.WorkspaceID().String() + "/environments/" + locator.Scope.EnvironmentID().String() + "/artifacts/" + locator.Reference.String(), nil
}

func containsWorkerString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
