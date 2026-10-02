package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// These fields must come from the scoped persisted run/attempt and invocation
// journal, never planner input or an artifact's self-declared authority.
// The reconciler must still CAS its exact link lease after this read-only work.
type existingTestEvidenceRequest struct {
	Scope             domain.Scope
	RunID             string
	Attempt           int
	DefinitionID      string
	DefinitionVersion int64
	TargetID          string
	TargetKind        string
	Categories        []string
	InputDigest       string
	Verdict           string
	InputArtifact     apiserver.RedTeamArtifactReference
	OutputArtifact    apiserver.RedTeamArtifactReference
	Observations      []redteamadapter.LinkedObservationResponse
	Captured          *capturedTestEvidence
}

type existingTestEvidenceBundle struct {
	SchemaVersion  string                              `json:"schema_version"`
	InputArtifact  *apiserver.RedTeamArtifactReference `json:"input_artifact"`
	Summary        redTeamRunnerOutput                 `json:"summary"`
	NativeArtifact redTeamNativeArtifact               `json:"native_artifact"`
}

type existingTestEvidence struct {
	Input      redTeamRunnerInput
	Bundle     existingTestEvidenceBundle
	Verdict    string
	Evaluation *redTeamEvaluationIdentity
	Checks     []verifiedTestCheck
}

type existingTestArtifactReader interface {
	Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error)
	ObjectReference(artifactstore.Locator) (string, error)
}

func readExistingTestEvidence(ctx context.Context, store existingTestArtifactReader, request existingTestEvidenceRequest) (existingTestEvidence, error) {
	var result existingTestEvidence
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(store) || request.Scope.Validate() != nil || request.Attempt < 1 || request.Attempt > 5 || request.DefinitionVersion < 1 || request.DefinitionVersion > 1000000 || !stringInWorker(request.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || !stringInWorker(request.Verdict, "pass", "fail", "engine_error") || !redTeamLinkedDigestPattern.MatchString(request.InputDigest) || request.InputDigest == strings.Repeat("0", 64) || len(request.Categories) < 1 || len(request.Categories) > 6 {
		return result, errRuntimeUnavailable
	}
	for _, id := range []string{request.RunID, request.DefinitionID, request.TargetID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return result, errRuntimeUnavailable
		}
	}
	seen := map[string]bool{}
	for _, category := range request.Categories {
		if seen[category] || redTeamCuratedPrompt(category) == "" {
			return result, errRuntimeUnavailable
		}
		seen[category] = true
	}
	inputLocator, err := existingTestArtifactLocator(request.Scope, request.InputArtifact, 65536)
	if err != nil {
		return result, err
	}
	outputLocator, err := existingTestArtifactLocator(request.Scope, request.OutputArtifact, 1<<20)
	if err != nil || outputLocator.Reference.String() != request.RunID || inputLocator.Reference == outputLocator.Reference {
		return result, errRuntimeUnavailable
	}
	inputBody, err := readExistingTestArtifact(ctx, store, inputLocator, request.InputArtifact)
	if err != nil {
		return result, err
	}
	// Always enforce v2 exact keys, including before schema_version is decoded.
	strict := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}
	if decodeRedTeamEvidenceJSON(strict, inputBody, &result.Input) != nil {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	input := result.Input
	version := redTeamEvidenceVersion(input)
	if !stringInWorker(input.SchemaVersion, "red-team-runner-input-v1", "red-team-runner-input-v2") || input.OrganizationID != request.Scope.OrganizationID().String() || input.WorkspaceID != request.Scope.WorkspaceID().String() || input.EnvironmentID != request.Scope.EnvironmentID().String() || input.RunID != request.RunID || input.DefinitionID != request.DefinitionID || input.DefinitionVersion != request.DefinitionVersion || input.TargetID != request.TargetID || input.TargetKind != request.TargetKind || input.InputDigest != request.InputDigest || !reflect.DeepEqual(input.Categories, request.Categories) || version == "v2" && expectedRedTeamEvaluationIdentity(input) == nil || version == "v1" && input.RunnerImageDigest != "" {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	outputBody, err := readExistingTestArtifact(ctx, store, outputLocator, request.OutputArtifact)
	if err != nil {
		return existingTestEvidence{}, err
	}
	var format struct {
		Schema string `json:"schema_version"`
	}
	if json.Unmarshal(outputBody, &format) != nil {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	if format.Schema == "red-team-completed-receipts-v1" {
		return readCompletedTestEvidence(input, outputBody, request)
	}
	if decodeRedTeamEvidenceJSON(strict, outputBody, &result.Bundle) != nil || result.Bundle.SchemaVersion != "red-team-evidence-bundle-"+version || result.Bundle.InputArtifact == nil || *result.Bundle.InputArtifact != request.InputArtifact || result.Bundle.Summary.Verdict != request.Verdict {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	nativeBytes, err := json.Marshal(result.Bundle.NativeArtifact)
	if err != nil {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	if _, err := buildRedTeamEvidenceBundle(input, result.Bundle.Summary, result.Bundle.InputArtifact, nativeBytes); err != nil {
		return existingTestEvidence{}, err
	}
	// Stored artifact claims must match the journal pinned at actual invocation.
	// Matching a self-declared target tuple alone is not evidence of provenance.
	observations := map[string]redteamadapter.LinkedObservationResponse{}
	for _, value := range request.Observations {
		if _, exists := observations[value.Category]; exists || value.RunID != request.RunID || !seen[value.Category] {
			return existingTestEvidence{}, errRuntimeUnavailable
		}
		observations[value.Category] = value
	}
	matched := 0
	if request.Captured != nil && len(request.Observations) != 0 {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	result.Verdict, result.Evaluation = result.Bundle.Summary.Verdict, result.Bundle.NativeArtifact.EvaluationIdentity
	if native := result.Bundle.NativeArtifact.NativeOutput; native != nil {
		for _, record := range native.Results.Results {
			if actual := record.Response.LinkedObservation; actual != nil {
				if request.Captured != nil {
					want, err := capturedObservationFor(request.Captured, record.Vars.Category)
					check, checkErr := capturedCheck(input, want, record.Vars.Category)
					if err != nil || checkErr != nil || testComparisonBinding(actual.TargetComparison) != want.ComparisonDigest || actual.CredentialVersionDigest != want.CredentialDigest || actual.Observation.ResponseDigest != want.Observation.ResponseDigest || actual.Observation.Protected == nil || *actual.Observation.Protected != check.Protected || actual.Observation.HTTPStatus != check.HTTPStatus {
						return existingTestEvidence{}, errRuntimeUnavailable
					}
					result.Checks = append(result.Checks, check)
					matched++
					continue
				}
				want, exists := observations[record.Vars.Category]
				if !exists {
					return existingTestEvidence{}, errRuntimeUnavailable
				}
				actualJSON, _ := json.Marshal(actual)
				wantJSON, err := json.Marshal(want)
				if err != nil || !bytes.Equal(actualJSON, wantJSON) {
					return existingTestEvidence{}, errRuntimeUnavailable
				}
				matched++
				result.Checks = append(result.Checks, verifiedTestCheck{record.Vars.Category, testComparisonBinding(actual.TargetComparison), actual.CredentialVersionDigest, actual.Observation.HTTPStatus, *actual.Observation.Protected})
			}
		}
	}
	expectedCount := len(observations)
	if request.Captured != nil {
		expectedCount = len(request.Captured.Observations)
	}
	if matched != expectedCount || ctx.Err() != nil {
		return existingTestEvidence{}, errRuntimeUnavailable
	}
	return result, nil
}

func existingTestArtifactLocator(scope domain.Scope, receipt apiserver.RedTeamArtifactReference, maximum int64) (artifactstore.Locator, error) {
	var locator artifactstore.Locator
	prefix := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/"
	_, key, ok := strings.Cut(strings.TrimPrefix(receipt.Reference, "s3://"), "/")
	if !ok || !strings.HasPrefix(key, prefix) || !validRedTeamArtifactObjectReference(receipt.Reference, key) || receipt.SizeBytes < 1 || receipt.SizeBytes > maximum || !redTeamLinkedDigestPattern.MatchString(receipt.SHA256) || receipt.SHA256 == strings.Repeat("0", 64) || len(receipt.VersionID) < 1 || len(receipt.VersionID) > 512 {
		return locator, errRuntimeUnavailable
	}
	for _, c := range receipt.VersionID {
		if c <= 32 || c >= 127 {
			return locator, errRuntimeUnavailable
		}
	}
	ref, err := domain.ParseEvidenceRef(strings.TrimPrefix(key, prefix))
	if err != nil {
		return locator, errRuntimeUnavailable
	}
	return artifactstore.Locator{Scope: scope, Reference: ref, VersionID: receipt.VersionID}, nil
}

func readExistingTestArtifact(ctx context.Context, store existingTestArtifactReader, locator artifactstore.Locator, receipt apiserver.RedTeamArtifactReference) ([]byte, error) {
	object, err := store.ObjectReference(locator)
	if err != nil || object != receipt.Reference || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	artifact, err := store.Get(ctx, locator)
	if err != nil || ctx.Err() != nil || artifact.VersionID != locator.VersionID || !validRedTeamPersistedArtifact(artifact, locator.Scope, locator.Reference, artifact.Body) || artifact.Size != receipt.SizeBytes || hex.EncodeToString(artifact.SHA256[:]) != receipt.SHA256 {
		return nil, errRuntimeUnavailable
	}
	return bytes.Clone(artifact.Body), nil
}
