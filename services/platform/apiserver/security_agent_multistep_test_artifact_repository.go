package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

var orderedTestCredentialPattern = regexp.MustCompile(`^ref:red-team/[a-z][a-z0-9_-]{7,127}$`)

func (repository *securityAgentMultistepAdmissionRepository) testDispatch(ctx context.Context, raw json.RawMessage, store artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error) {
	var request orderedTestAction
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 16384 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "lease_token", "run_version", "effect_version", "lease_seconds", "payload"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedTestScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	token, tokenErr := hex.DecodeString(request.LeaseToken)
	if !valid || request.Operation != "dispatch" || tokenErr != nil || len(token) != 16 || strings.ToLower(request.LeaseToken) != request.LeaseToken || !redTeamWorkerPattern.MatchString(request.WorkerID) || !validSecurityAgentWorkerLease(request.WorkerID, request.LeaseToken, request.LeaseSeconds) || request.RunVersion < 1 || request.RunVersion > 999999 || request.EffectVersion < 1 || request.EffectVersion > 999999 {
		return nil, ErrRepositoryOperation
	}
	var payload struct {
		InputArtifact RedTeamArtifactReference `json:"input_artifact"`
	}
	fields, ok := securityAgentOrderedClosedObject(request.Payload, "input_artifact")
	if !ok || decodeStrictDiscovery(request.Payload, &payload) != nil {
		return nil, ErrRepositoryOperation
	}
	if _, ok = securityAgentOrderedClosedObject(fields["input_artifact"], "reference", "version_id", "sha256", "size_bytes"); !ok {
		return nil, ErrRepositoryOperation
	}
	inputID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", request.RunID+"\x1f"+request.StepID)
	body, err := orderedTestReadArtifact(ctx, store, scope, inputID, payload.InputArtifact, 65536)
	if err != nil {
		return nil, err
	}
	input, valid := orderedTestDecodeInput(body)
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", request.RunID+"\x1f"+request.StepID+"\x1frun_test")
	if !valid || input.OrganizationID != request.OrganizationID || input.WorkspaceID != request.WorkspaceID || input.EnvironmentID != request.EnvironmentID || input.RunID != child {
		return nil, ErrRepositoryOperation
	}
	manifest, _ := json.Marshal(payload.InputArtifact)
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.test_dispatch($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID, request.WorkerID, request.LeaseToken, request.RunVersion, request.EffectVersion, manifest, body)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result struct {
		ContractVersion   int                      `json:"contract_version"`
		OrganizationID    string                   `json:"organization_id"`
		WorkspaceID       string                   `json:"workspace_id"`
		EnvironmentID     string                   `json:"environment_id"`
		RunID             string                   `json:"run_id"`
		StepID            string                   `json:"step_id"`
		TestRunID         string                   `json:"test_run_id"`
		Attempt           int                      `json:"attempt"`
		State             string                   `json:"state"`
		InputDigest       string                   `json:"input_digest"`
		DefinitionID      string                   `json:"test_definition_id"`
		DefinitionVersion int64                    `json:"test_definition_version"`
		TargetResolution  json.RawMessage          `json:"target_resolution"`
		InputArtifact     RedTeamArtifactReference `json:"input_artifact"`
		RunnerImageDigest string                   `json:"runner_image_digest"`
	}
	fields, ok = securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "test_run_id", "attempt", "state", "input_digest", "test_definition_id", "test_definition_version", "target_resolution", "input_artifact", "runner_image_digest")
	if !ok || len(response) > 16384 || decodeStrictDiscovery(response, &result) != nil || result.ContractVersion != 61 || result.OrganizationID != request.OrganizationID || result.WorkspaceID != request.WorkspaceID || result.EnvironmentID != request.EnvironmentID || result.RunID != request.RunID || result.StepID != request.StepID || result.TestRunID != child || result.Attempt < 1 || result.Attempt > 5 || result.State != "leased" || result.InputDigest != input.InputDigest || result.DefinitionID != input.DefinitionID || result.DefinitionVersion != input.DefinitionVersion || result.InputArtifact != payload.InputArtifact || result.RunnerImageDigest != input.RunnerImageDigest || !orderedTestResolutionValid(result.TargetResolution, input) {
		return nil, ErrRepositoryUnavailable
	}
	if _, ok = securityAgentOrderedClosedObject(fields["input_artifact"], "reference", "version_id", "sha256", "size_bytes"); !ok {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

type orderedTestInput struct {
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
	RunnerImageDigest string   `json:"runner_image_digest"`
}

func orderedTestDecodeInput(body []byte) (orderedTestInput, bool) {
	var input orderedTestInput
	if _, ok := securityAgentOrderedClosedObject(body, "schema_version", "organization_id", "workspace_id", "environment_id", "run_id", "definition_id", "definition_version", "target_id", "target_kind", "categories", "input_digest", "runner_image_digest"); !ok || decodeStrictDiscovery(body, &input) != nil || input.SchemaVersion != "red-team-runner-input-v2" || input.DefinitionVersion < 1 || input.DefinitionVersion > 1000000 || !stringIn(input.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || !validAttackLabDigest(input.InputDigest) || len(input.Categories) < 1 || len(input.Categories) > 6 {
		return input, false
	}
	if _, ok := decodeTemporaryPolicyDigest(input.RunnerImageDigest); !ok {
		return input, false
	}
	for _, id := range []string{input.OrganizationID, input.WorkspaceID, input.EnvironmentID, input.RunID, input.DefinitionID, input.TargetID} {
		if !validProductID(id) {
			return input, false
		}
	}
	seen := map[string]bool{}
	for _, category := range input.Categories {
		if !stringIn(category, "prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information") || seen[category] {
			return input, false
		}
		seen[category] = true
	}
	return input, true
}

func orderedTestReadArtifact(ctx context.Context, store artifactstore.ObjectReferencingArtifactStore, scope domain.Scope, id string, receipt RedTeamArtifactReference, maximum int64) ([]byte, error) {
	key := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + id
	if nilInterface(store) || !validS3ObjectReference(receipt.Reference) || !strings.HasSuffix(receipt.Reference, "/"+key) || !validAttackLabDigest(receipt.SHA256) || receipt.SizeBytes < 1 || receipt.SizeBytes > maximum || len(receipt.VersionID) < 1 || len(receipt.VersionID) > 512 {
		return nil, ErrRepositoryOperation
	}
	for _, c := range receipt.VersionID {
		if c <= 32 || c >= 127 {
			return nil, ErrRepositoryOperation
		}
	}
	ref, err := domain.ParseEvidenceRef(id)
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	locator := artifactstore.Locator{Scope: scope, Reference: ref, VersionID: receipt.VersionID}
	object, err := store.ObjectReference(locator)
	if err != nil || object != receipt.Reference {
		return nil, ErrRepositoryUnavailable
	}
	artifact, err := store.Get(ctx, locator)
	if err != nil || ctx.Err() != nil || artifact.Locator != locator || artifact.MediaType != "application/json" || artifact.Size != receipt.SizeBytes || int64(len(artifact.Body)) != receipt.SizeBytes || hex.EncodeToString(artifact.SHA256[:]) != receipt.SHA256 || sha256.Sum256(artifact.Body) != artifact.SHA256 {
		return nil, ErrRepositoryUnavailable
	}
	return bytes.Clone(artifact.Body), nil
}

func orderedTestResolutionValid(body json.RawMessage, input orderedTestInput) bool {
	var resolution struct {
		Binding    redteamadapter.TargetBinding    `json:"binding"`
		Comparison redteamadapter.TargetComparison `json:"comparison"`
		Provenance struct {
			IntegrationID string `json:"integration_id"`
			SnapshotID    string `json:"snapshot_id"`
			EvidenceID    string `json:"evidence_id"`
			Source        string `json:"source"`
			Generation    int64  `json:"generation"`
		} `json:"provenance"`
	}
	fields, ok := securityAgentOrderedClosedObject(body, "binding", "comparison", "provenance")
	if !ok || decodeStrictDiscovery(body, &resolution) != nil {
		return false
	}
	if _, ok = securityAgentOrderedClosedObject(fields["binding"], "target_id", "target_kind", "endpoint", "credential_reference", "version"); !ok {
		return false
	}
	if _, ok = securityAgentOrderedClosedObject(fields["provenance"], "integration_id", "snapshot_id", "evidence_id", "source", "generation"); !ok {
		return false
	}
	if _, ok = securityAgentOrderedClosedObject(fields["comparison"], "schema_version", "organization_id", "workspace_id", "environment_id", "test_definition_id", "test_definition_version", "target_id", "target_kind", "categories", "safety_digest", "endpoint_digest", "configuration_digest", "credential_binding_id", "credential_binding_version", "credential_binding_digest"); !ok {
		return false
	}
	b, c, p := resolution.Binding, resolution.Comparison, resolution.Provenance
	endpoint, err := url.Parse(b.Endpoint)
	digest := sha256.Sum256([]byte(b.Endpoint))
	if err != nil || len(b.Endpoint) > 2048 || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" || b.TargetID != input.TargetID || b.TargetKind != input.TargetKind || b.Version < 1 || !orderedTestCredentialPattern.MatchString(b.CredentialReference) || p.Generation < 1 || !validSecurityAgentText(p.Source, 128) || c.Schema != "red-team-target-comparison-v1" || c.Organization != input.OrganizationID || c.Workspace != input.WorkspaceID || c.Environment != input.EnvironmentID || c.Definition != input.DefinitionID || c.DefinitionVersion != input.DefinitionVersion || c.Target != input.TargetID || c.Kind != input.TargetKind || !reflect.DeepEqual(c.Categories, input.Categories) || c.CredentialVersion < 1 || c.Endpoint != hex.EncodeToString(digest[:]) {
		return false
	}
	for _, id := range []string{p.IntegrationID, p.SnapshotID, p.EvidenceID, c.Credential} {
		if !validProductID(id) {
			return false
		}
	}
	for _, digest := range []string{c.Safety, c.Endpoint, c.Configuration, c.CredentialDigest} {
		if !validAttackLabDigest(digest) {
			return false
		}
	}
	return true
}
