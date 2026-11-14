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
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam/probes"
)

var redTeamTargetEndpointPattern = regexp.MustCompile(`^https://agentsec-red-team-adapter(?:\.[a-z0-9-]{1,63}){1,4}\.svc\.cluster\.local/v1/evaluate$`)
var redTeamAdapterTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
var redTeamRunLeasePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var redTeamArtifactBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var redTeamRunnerImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*(?::[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})$`)

func redTeamRunnerImageDigest(value string) string {
	match := redTeamRunnerImagePattern.FindStringSubmatch(value)
	if len(match) != 2 || match[1] == "sha256:"+strings.Repeat("0", 64) {
		return ""
	}
	return match[1]
}

type redTeamCommand interface {
	Run(context.Context, string, []string, []string, string) error
}

type productionRedTeamRunnerConfig struct {
	RunnerImage     string
	Artifacts       artifactstore.ObjectReferencingArtifactStore
	Command         redTeamCommand
	NodePath        string
	ScriptPath      string
	PromptfooPath   string
	TargetEndpoint  string
	TargetTokenFile string
	TargetCAFile    string
	TempRoot        string
	Timeout         time.Duration
	Clock           func() time.Time
	// ProbeSampleSize is the number of probe library entries a standalone run
	// executes per category. Zero keeps the single curated check per category.
	ProbeSampleSize int
}

type productionRedTeamRunner struct{ config productionRedTeamRunnerConfig }

type redTeamRunnerInput struct {
	RunnerImageDigest string   `json:"runner_image_digest,omitempty"`
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
	// ProbePack and Probes are set only by runner input v3: the probes this
	// run executes, selected from the embedded library by the run identifier.
	ProbePack *redTeamProbePack    `json:"probe_pack,omitempty"`
	Probes    []redTeamRunnerProbe `json:"probes,omitempty"`
}

type redTeamProbePack struct {
	Version    string `json:"version"`
	Digest     string `json:"digest"`
	SampleSize int    `json:"sample_size"`
}

type redTeamRunnerProbe struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Input    string `json:"input"`
	Canary   string `json:"canary"`
}

// selectRedTeamProbes returns the probes of a run: for each category, in the
// definition's order, the sample the run identifier selects.
func selectRedTeamProbes(runID string, categories []string, sampleSize int) []redTeamRunnerProbe {
	selected := []redTeamRunnerProbe{}
	for _, category := range categories {
		sample := probes.Sample(category, runID, sampleSize)
		if len(sample) == 0 {
			return nil
		}
		for _, probe := range sample {
			selected = append(selected, redTeamRunnerProbe{ID: probe.ID, Category: probe.Category, Input: probe.Input, Canary: probe.Canary})
		}
	}
	if len(selected) > probes.MaximumRunProbes {
		return nil
	}
	return selected
}

func validRedTeamProbeInput(input redTeamRunnerInput) bool {
	if input.ProbePack == nil || input.ProbePack.Version != probes.Version || input.ProbePack.Digest != probes.Digest() || input.ProbePack.SampleSize < 1 || input.ProbePack.SampleSize > probes.MaximumSampleSize {
		return false
	}
	return reflect.DeepEqual(input.Probes, selectRedTeamProbes(input.RunID, input.Categories, input.ProbePack.SampleSize))
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
	// ProbeResults holds one outcome per executed probe (runner input v3).
	ProbeResults []apiserver.RedTeamProbeResult `json:"probe_results,omitempty"`
}

type productionRedTeamCommand struct{}

func newProductionRedTeamRunner(config productionRedTeamRunnerConfig) (*productionRedTeamRunner, error) {
	if config.RunnerImage != "" && redTeamRunnerImageDigest(config.RunnerImage) == "" || config.ProbeSampleSize < 0 || config.ProbeSampleSize > probes.MaximumSampleSize {
		return nil, errRuntimeUnavailable
	}
	if nilWorkerDependency(config.Artifacts) || nilWorkerDependency(config.Command) || config.NodePath != "/usr/local/bin/node" || config.ScriptPath != "/app/redteam-runner.mjs" || config.PromptfooPath != "/app/dist/src/entrypoint.js" || !redTeamTargetEndpointPattern.MatchString(config.TargetEndpoint) || !filepath.IsAbs(config.TargetTokenFile) || !filepath.IsAbs(config.TargetCAFile) || !filepath.IsAbs(config.TempRoot) || config.Timeout < 30*time.Second || config.Timeout > 15*time.Minute || config.Clock == nil {
		return nil, errRuntimeUnavailable
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errRuntimeUnavailable
	}
	return &productionRedTeamRunner{config: config}, nil
}

func (runner *productionRedTeamRunner) Run(ctx context.Context, request redTeamExecutionRequest) (redTeamExecutionResult, error) {
	if runner == nil || ctx == nil || ctx.Err() != nil || !validProductionRedTeamRequest(request) || !validRedTeamRequestCategories(request, runner.config.ProbeSampleSize) || request.EvidenceVersion == "red-team-v2" && redTeamRunnerImageDigest(runner.config.RunnerImage) == "" || !validRedTeamTokenFile(runner.config.TargetTokenFile) || !validRedTeamCAFile(runner.config.TargetCAFile) {
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
	targetEndpoint := runner.config.TargetEndpoint
	if request.EvidenceVersion == "red-team-v2" {
		input.SchemaVersion = "red-team-runner-input-v2"
		input.RunnerImageDigest = redTeamRunnerImageDigest(runner.config.RunnerImage)
		targetEndpoint = strings.TrimSuffix(targetEndpoint, "/v1/evaluate") + "/v1/linked/evaluate"
	}
	maximumInput := 65_536
	if request.EvidenceVersion == "" && runner.config.ProbeSampleSize > 0 {
		// A standalone run executes a sample of the probe library instead of
		// one curated prompt per category. The linked protocol keeps its
		// journaled single check.
		input.SchemaVersion = "red-team-runner-input-v3"
		input.ProbePack = &redTeamProbePack{Version: probes.Version, Digest: probes.Digest(), SampleSize: runner.config.ProbeSampleSize}
		input.Probes = selectRedTeamProbes(input.RunID, input.Categories, runner.config.ProbeSampleSize)
		if len(input.Probes) == 0 {
			return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
		}
		maximumInput = 1 << 20
	}
	inputBytes, err := json.Marshal(input)
	if err != nil || len(inputBytes) > maximumInput {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	inputPath, outputPath := filepath.Join(workspace, "input.json"), filepath.Join(workspace, "output.json")
	if writeRedTeamFile(inputPath, inputBytes) != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	inputID, err := domain.NewProductID()
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	inputReference, err := domain.NewEvidenceRef(inputID)
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	inputArtifact, err := runner.config.Artifacts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: request.Scope, Reference: inputReference}, MediaType: "application/json", Body: bytes.Clone(inputBytes)})
	if err != nil || !validRedTeamPersistedArtifact(inputArtifact, request.Scope, inputReference, inputBytes) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	inputObjectReference, err := runner.config.Artifacts.ObjectReference(inputArtifact.Locator)
	inputKey := "organizations/" + request.Scope.OrganizationID().String() + "/workspaces/" + request.Scope.WorkspaceID().String() + "/environments/" + request.Scope.EnvironmentID().String() + "/artifacts/" + inputID.String()
	if err != nil || !validRedTeamArtifactObjectReference(inputObjectReference, inputKey) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	inputReceipt := &apiserver.RedTeamArtifactReference{Reference: inputObjectReference, VersionID: inputArtifact.VersionID, SHA256: hex.EncodeToString(inputArtifact.SHA256[:]), SizeBytes: inputArtifact.Size}
	bounded, cancel := context.WithTimeout(ctx, runner.config.Timeout)
	environment := []string{"HOME=" + workspace, "ZASP_PROMPTFOO_BIN=" + runner.config.PromptfooPath, "ZASP_RED_TEAM_TARGET_ENDPOINT=" + targetEndpoint, "ZASP_RED_TEAM_ADAPTER_TOKEN_FILE=" + runner.config.TargetTokenFile, "ZASP_RED_TEAM_TARGET_CA_FILE=" + runner.config.TargetCAFile}
	environment = append(environment, "ZASP_RED_TEAM_RUN_LEASE="+request.LeaseToken)
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
	if decodeRedTeamEvidenceJSON(input, outputBytes, &output) != nil || !validRedTeamRunnerOutput(input, output) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	nativeBytes, err := readRedTeamOutput(filepath.Join(workspace, "artifact.json"))
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	artifactBytes, err := buildRedTeamEvidenceBundle(input, output, inputReceipt, nativeBytes)
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	runID, parseErr := domain.ParseProductID(request.Run.ID)
	reference, referenceErr := domain.NewEvidenceRef(runID)
	if parseErr != nil || referenceErr != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	artifact, err := runner.config.Artifacts.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: request.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(artifactBytes)})
	if err != nil {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	objectReference, err := runner.config.Artifacts.ObjectReference(artifact.Locator)
	outputKey := "organizations/" + request.Scope.OrganizationID().String() + "/workspaces/" + request.Scope.WorkspaceID().String() + "/environments/" + request.Scope.EnvironmentID().String() + "/artifacts/" + request.Run.ID
	if err != nil || !validRedTeamPersistedArtifact(artifact, request.Scope, reference, artifactBytes) || !validRedTeamArtifactObjectReference(objectReference, outputKey) {
		return redTeamExecutionResult{}, &redTeamExecutionFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	errorCode := ""
	if output.ErrorCode != nil {
		errorCode = *output.ErrorCode
	}
	return redTeamExecutionResult{EvidenceArtifact: bytes.Clone(artifactBytes), InputArtifact: inputReceipt, Verdict: output.Verdict, Objective: output.Objective, Behavior: output.Behavior, ErrorCode: errorCode, Evidence: append([]string(nil), output.Evidence...), ProbeResults: append([]apiserver.RedTeamProbeResult(nil), output.ProbeResults...), EvidenceReference: objectReference, EvidenceKey: "organizations/" + request.Scope.OrganizationID().String() + "/workspaces/" + request.Scope.WorkspaceID().String() + "/environments/" + request.Scope.EnvironmentID().String() + "/artifacts/" + request.Run.ID, EvidenceVersionID: artifact.VersionID, EvidenceChecksum: append([]byte(nil), artifact.SHA256[:]...), EvidenceSizeBytes: artifact.Size}, nil
}

func validRedTeamPersistedArtifact(artifact artifactstore.Artifact, scope domain.Scope, reference domain.EvidenceRef, body []byte) bool {
	if artifact.Scope != scope || artifact.Reference != reference || artifact.MediaType != "application/json" || !bytes.Equal(artifact.Body, body) || artifact.Size != int64(len(body)) || artifact.SHA256 != sha256.Sum256(body) || len(artifact.VersionID) < 1 || len(artifact.VersionID) > 512 {
		return false
	}
	for _, character := range artifact.VersionID {
		if character <= 32 || character >= 127 {
			return false
		}
	}
	return true
}

func validRedTeamArtifactObjectReference(value, key string) bool {
	if len(value) > 1024 || !strings.HasPrefix(value, "s3://") {
		return false
	}
	bucket, actualKey, ok := strings.Cut(strings.TrimPrefix(value, "s3://"), "/")
	return ok && actualKey == key && redTeamArtifactBucketPattern.MatchString(bucket) && !strings.Contains(bucket, "..") && !strings.Contains(bucket, ".-") && !strings.Contains(bucket, "-.")
}

func validProductionRedTeamRequest(request redTeamExecutionRequest) bool {
	if request.EvidenceVersion != "" && request.EvidenceVersion != "red-team-v2" {
		return false
	}
	if !redTeamRunLeasePattern.MatchString(request.LeaseToken) {
		return false
	}
	if request.Scope.Validate() != nil || request.InputDigest == [sha256.Size]byte{} || request.Run.ID == "" || request.Run.Status != "leased" || request.Run.Attempt < 1 || request.Run.Attempt > 5 || request.Run.DefinitionID != request.Definition.ID || request.Run.DefinitionVersion != request.Definition.Version || request.Definition.Version < 1 || !stringInWorker(request.Definition.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || len(request.Definition.Categories) < 1 || len(request.Definition.Categories) > 16 || !stringInWorker(request.Definition.Safety.Environment, "development", "test", "staging") || !stringInWorker(request.Definition.Safety.CredentialClass, "read_only", "test_write") {
		return false
	}
	for _, category := range request.Definition.Categories {
		if !probes.ValidCategory(category) {
			return false
		}
	}
	return true
}

// validRedTeamRequestCategories keeps the categories that exist only in the
// probe library out of every execution that runs one curated check.
func validRedTeamRequestCategories(request redTeamExecutionRequest, sampleSize int) bool {
	if request.EvidenceVersion == "" && sampleSize > 0 {
		return true
	}
	for _, category := range request.Definition.Categories {
		if redTeamCuratedPrompt(category) == "" {
			return false
		}
	}
	return true
}

func redTeamEvidenceVersion(input redTeamRunnerInput) string {
	switch input.SchemaVersion {
	case "", "red-team-runner-input-v1":
		return "v1"
	case "red-team-runner-input-v2":
		return "v2"
	case "red-team-runner-input-v3":
		return "v3"
	default:
		return ""
	}
}

func validRedTeamRunnerOutput(input redTeamRunnerInput, output redTeamRunnerOutput) bool {
	version := redTeamEvidenceVersion(input)
	if version == "" || output.SchemaVersion != "red-team-evidence-"+version || output.Engine != "promptfoo" || output.EngineVersion != "0.121.19" || output.RunID != input.RunID || output.InputDigest != input.InputDigest || output.Objective != "Evaluate curated categories: "+strings.Join(input.Categories, ", ") || !stringInWorker(output.Verdict, "pass", "fail", "engine_error") || !validRedTeamBoundedWorkerText(output.Behavior, 2048) {
		return false
	}
	if output.Verdict == "engine_error" {
		if len(output.ProbeResults) != 0 || version == "v3" && !validRedTeamProbeInput(input) {
			return false
		}
		return output.ErrorCode != nil && *output.ErrorCode == "outcome_unknown" && len(output.Evidence) == 1 && (output.Behavior == "The bounded target adapter did not return a complete evaluation." && output.Evidence[0] == "Target adapter evaluation did not complete" || output.Behavior == "The bounded Promptfoo engine did not complete the evaluation." && output.Evidence[0] == "Promptfoo execution did not complete")
	}
	if version == "v3" {
		return validRedTeamProbeOutput(input, output)
	}
	if output.ErrorCode != nil || len(output.Evidence) != len(input.Categories) || len(output.ProbeResults) != 0 {
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

// validRedTeamProbeOutput checks a v3 summary against the probes of the run:
// one result per probe, in order, and a category is protected only when every
// one of its probes was.
func validRedTeamProbeOutput(input redTeamRunnerInput, output redTeamRunnerOutput) bool {
	if !validRedTeamProbeInput(input) || output.ErrorCode != nil || len(output.Evidence) != len(input.Categories) || len(output.ProbeResults) != len(input.Probes) {
		return false
	}
	exposedByCategory, exposed := map[string]int{}, 0
	for index, result := range output.ProbeResults {
		probe := input.Probes[index]
		if result.ProbeID != probe.ID || result.Category != probe.Category || !stringInWorker(result.Outcome, "protected", "unsafe") {
			return false
		}
		if result.Outcome == "unsafe" {
			exposedByCategory[probe.Category]++
			exposed++
		}
	}
	for index, category := range input.Categories {
		want := category + ": protected"
		if exposedByCategory[category] > 0 {
			want = category + ": unsafe behavior observed"
		}
		if output.Evidence[index] != want {
			return false
		}
	}
	wantVerdict := "pass"
	if exposed > 0 {
		wantVerdict = "fail"
	}
	return output.Verdict == wantVerdict && output.Behavior == fmt.Sprintf("%d of %d curated probes passed; %d exposed unsafe behavior.", len(input.Probes)-exposed, len(input.Probes), exposed)
}

func validRedTeamBoundedWorkerText(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func validRedTeamTokenFile(path string) bool {
	payload, ok := readRedTeamPinnedFile(path, 64, 16_384)
	defer clear(payload)
	return ok && redTeamAdapterTokenPattern.Match(payload)
}

func validRedTeamCAFile(path string) bool {
	payload, ok := readRedTeamPinnedFile(path, 64, 32<<10)
	defer clear(payload)
	return ok && validDiscoveryCABundle(payload)
}

func readRedTeamPinnedFile(path string, minimum, maximum int64) ([]byte, bool) {
	return readPinnedFile(path, minimum, maximum, 0o400)
}

func readPinnedFile(path string, minimum, maximum int64, permission os.FileMode) ([]byte, bool) {
	before, err := os.Lstat(path)
	if err != nil || minimum < 1 || maximum < minimum || permission.Perm() != permission || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != permission || before.Size() < minimum || before.Size() > maximum {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	opened, statErr := file.Stat()
	payload, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	ok := statErr == nil && readErr == nil && closeErr == nil && afterErr == nil && opened.Mode().IsRegular() && opened.Mode().Perm() == permission && after.Mode().IsRegular() && after.Mode().Perm() == permission && os.SameFile(before, opened) && os.SameFile(opened, after) && opened.Size() == before.Size() && after.Size() == before.Size() && int64(len(payload)) == before.Size()
	if !ok {
		clear(payload)
		return nil, false
	}
	return payload, true
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
