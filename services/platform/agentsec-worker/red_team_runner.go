package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var redTeamTargetEndpointPattern = regexp.MustCompile(`^https://agentsec-red-team-adapter(?:\.[a-z0-9-]{1,63}){1,4}\.svc\.cluster\.local/v1/evaluate$`)
var redTeamAdapterTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type redTeamCommand interface {
	Run(context.Context, string, []string, []string, string) error
}

type productionRedTeamRunnerConfig struct {
	Artifacts       artifactstore.ObjectReferencingArtifactStore
	Command         redTeamCommand
	NodePath        string
	ScriptPath      string
	PromptfooPath   string
	TargetEndpoint  string
	TargetTokenFile string
	TempRoot        string
	Timeout         time.Duration
	Clock           func() time.Time
}

type productionRedTeamRunner struct{ config productionRedTeamRunnerConfig }

type redTeamRunnerInput struct {
	SchemaVersion     string   `json:"schema_version"`
	OrganizationID    string   `json:"organization_id"`
	WorkspaceID       string   `json:"workspace_id"`
	EnvironmentID     string   `json:"environment_id"`
	RunID             string   `json:"run_id"`
	DefinitionID      string   `json:"definition_id"`
	DefinitionVersion int64    `json:"definition_version"`
	TargetID          string   `json:"target_id"`
	TargetKind        string   `json:"target_kind"`
	Categories        []string `json:"categories"`
	InputDigest       string   `json:"input_digest"`
}

type redTeamRunnerOutput struct {
	SchemaVersion string   `json:"schema_version"`
	Engine        string   `json:"engine"`
	EngineVersion string   `json:"engine_version"`
	RunID         string   `json:"run_id"`
	InputDigest   string   `json:"input_digest"`
	Objective     string   `json:"objective"`
	Behavior      string   `json:"behavior"`
	Verdict       string   `json:"verdict"`
	ErrorCode     *string  `json:"error_code"`
	Evidence      []string `json:"evidence"`
}

type productionRedTeamCommand struct{}

func (productionRedTeamCommand) Run(ctx context.Context, executable string, arguments, environment []string, directory string) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = append([]string(nil), environment...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func newProductionRedTeamRunner(config productionRedTeamRunnerConfig) (*productionRedTeamRunner, error) {
	if nilWorkerDependency(config.Artifacts) || nilWorkerDependency(config.Command) || config.NodePath != "/usr/local/bin/node" || config.ScriptPath != "/app/redteam-runner.mjs" || config.PromptfooPath != "/app/node_modules/.bin/promptfoo" || !redTeamTargetEndpointPattern.MatchString(config.TargetEndpoint) || !filepath.IsAbs(config.TargetTokenFile) || !filepath.IsAbs(config.TempRoot) || config.Timeout < 30*time.Second || config.Timeout > 15*time.Minute || config.Clock == nil {
		return nil, errRuntimeUnavailable
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC || !validRedTeamTokenFile(config.TargetTokenFile) {
		return nil, errRuntimeUnavailable
	}
	return &productionRedTeamRunner{config: config}, nil
}

func (runner *productionRedTeamRunner) Run(ctx context.Context, request redTeamExecutionRequest) (redTeamExecutionResult, error) {
	if runner == nil || ctx == nil || ctx.Err() != nil || !validProductionRedTeamRequest(request) || !validRedTeamTokenFile(runner.config.TargetTokenFile) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	workspace, err := os.MkdirTemp(runner.config.TempRoot, "zasp-red-team-")
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	defer func() { _ = os.RemoveAll(workspace) }()
	if os.Chmod(workspace, 0o700) != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v1", OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String(), RunID: request.Run.ID, DefinitionID: request.Definition.ID, DefinitionVersion: request.Definition.Version, TargetID: request.Definition.TargetID, TargetKind: request.Definition.TargetKind, Categories: append([]string(nil), request.Definition.Categories...), InputDigest: hex.EncodeToString(request.InputDigest[:])}
	inputBytes, err := json.Marshal(input)
	if err != nil || len(inputBytes) > 65_536 {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	inputPath, outputPath := filepath.Join(workspace, "input.json"), filepath.Join(workspace, "output.json")
	if writeRedTeamFile(inputPath, inputBytes) != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	bounded, cancel := context.WithTimeout(ctx, runner.config.Timeout)
	environment := []string{"HOME=" + workspace, "ZASP_PROMPTFOO_BIN=" + runner.config.PromptfooPath, "ZASP_RED_TEAM_TARGET_ENDPOINT=" + runner.config.TargetEndpoint, "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE=" + runner.config.TargetTokenFile}
	commandErr := runner.config.Command.Run(bounded, runner.config.NodePath, []string{runner.config.ScriptPath, "run", inputPath, outputPath}, environment, workspace)
	boundedErr := bounded.Err()
	cancel()
	if commandErr != nil || boundedErr != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	outputBytes, err := readRedTeamOutput(outputPath)
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	var output redTeamRunnerOutput
	if decodeStrictWorkerJSON(outputBytes, &output) != nil || !validRedTeamRunnerOutput(input, output) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	runID, parseErr := domain.ParseProductID(request.Run.ID)
	reference, referenceErr := domain.NewEvidenceRef(runID)
	if parseErr != nil || referenceErr != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	artifact, err := runner.config.Artifacts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: request.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(outputBytes)})
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	objectReference, err := runner.config.Artifacts.ObjectReference(artifact.Locator)
	if err != nil || artifact.Size != int64(len(outputBytes)) || artifact.SHA256 != sha256.Sum256(outputBytes) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	errorCode := ""
	if output.ErrorCode != nil {
		errorCode = *output.ErrorCode
	}
	return redTeamExecutionResult{Verdict: output.Verdict, Objective: output.Objective, Behavior: output.Behavior, ErrorCode: errorCode, Evidence: append([]string(nil), output.Evidence...), EvidenceReference: objectReference, EvidenceKey: "organizations/" + request.Scope.OrganizationID().String() + "/workspaces/" + request.Scope.WorkspaceID().String() + "/environments/" + request.Scope.EnvironmentID().String() + "/artifacts/" + request.Run.ID, EvidenceVersionID: artifact.VersionID, EvidenceChecksum: append([]byte(nil), artifact.SHA256[:]...), EvidenceSizeBytes: artifact.Size}, nil
}

func validProductionRedTeamRequest(request redTeamExecutionRequest) bool {
	if request.Scope.Validate() != nil || request.InputDigest == [sha256.Size]byte{} || request.Run.ID == "" || request.Run.Status != "leased" || request.Run.Attempt < 1 || request.Run.Attempt > 5 || request.Run.DefinitionID != request.Definition.ID || request.Run.DefinitionVersion != request.Definition.Version || request.Definition.Version < 1 || !stringInWorker(request.Definition.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || len(request.Definition.Categories) < 1 || len(request.Definition.Categories) > 16 || !stringInWorker(request.Definition.Safety.Environment, "development", "test", "staging") || !stringInWorker(request.Definition.Safety.CredentialClass, "read_only", "test_write") {
		return false
	}
	for _, category := range request.Definition.Categories {
		if !stringInWorker(category, "prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information") {
			return false
		}
	}
	return true
}

func validRedTeamRunnerOutput(input redTeamRunnerInput, output redTeamRunnerOutput) bool {
	if output.SchemaVersion != "red-team-evidence-v1" || output.Engine != "promptfoo" || output.EngineVersion != "0.121.19" || output.RunID != input.RunID || output.InputDigest != input.InputDigest || output.Objective != "Evaluate curated categories: "+strings.Join(input.Categories, ", ") || !stringInWorker(output.Verdict, "pass", "fail", "engine_error") || !validRedTeamBoundedWorkerText(output.Behavior, 2048) {
		return false
	}
	if output.Verdict == "engine_error" {
		return output.ErrorCode != nil && *output.ErrorCode == "outcome_unknown" && len(output.Evidence) == 1 && (output.Behavior == "The bounded target adapter did not return a complete evaluation." && output.Evidence[0] == "Target adapter evaluation did not complete" || output.Behavior == "The bounded Promptfoo engine did not complete the evaluation." && output.Evidence[0] == "Promptfoo execution did not complete")
	}
	if output.ErrorCode != nil || len(output.Evidence) != len(input.Categories) {
		return false
	}
	unsafe := 0
	for index, evidence := range output.Evidence {
		if evidence != input.Categories[index]+": protected" && evidence != input.Categories[index]+": unsafe behavior observed" {
			return false
		}
		if strings.HasSuffix(evidence, "unsafe behavior observed") {
			unsafe++
		}
	}
	wantVerdict := "pass"
	if unsafe > 0 {
		wantVerdict = "fail"
	}
	wantBehavior := fmt.Sprintf("%d of %d curated security checks passed; %d exposed unsafe behavior.", len(input.Categories)-unsafe, len(input.Categories), unsafe)
	return output.Verdict == wantVerdict && output.Behavior == wantBehavior
}

func validRedTeamBoundedWorkerText(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validRedTeamTokenFile(path string) bool {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() < 64 || before.Size() > 16_384 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 16_385))
	after, statErr := file.Stat()
	closeErr := file.Close()
	return readErr == nil && statErr == nil && closeErr == nil && os.SameFile(before, after) && after.Mode().Perm() == 0o600 && after.Size() == before.Size() && int64(len(payload)) == before.Size() && redTeamAdapterTokenPattern.Match(payload)
}

func writeRedTeamFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(payload) {
		return errRuntimeUnavailable
	}
	return nil
}

func readRedTeamOutput(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() < 1 || before.Size() > 1<<20 {
		return nil, errRuntimeUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 1<<20+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() || len(payload) < 1 || len(payload) > 1<<20 || !json.Valid(payload) {
		return nil, errRuntimeUnavailable
	}
	return payload, nil
}

var _ redTeamCommand = productionRedTeamCommand{}
var _ redTeamRunner = (*productionRedTeamRunner)(nil)
