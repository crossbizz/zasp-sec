package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var attackLabWorkerSandboxReferencePattern = regexp.MustCompile(`^k8s://attack-lab/jobs/zasp-attack-lab-[a-z0-9-]{8,64}@[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type productionAttackLabEvidenceWriter struct {
	store artifactstore.ObjectReferencingArtifactStore
}

type attackLabEvidenceDocument struct {
	SchemaVersion     string   `json:"schema_version"`
	OrganizationID    string   `json:"organization_id"`
	WorkspaceID       string   `json:"workspace_id"`
	EnvironmentID     string   `json:"environment_id"`
	RunID             string   `json:"run_id"`
	Attempt           int      `json:"attempt"`
	SourceRunID       string   `json:"source_run_id"`
	DefinitionID      string   `json:"definition_id"`
	DefinitionVersion int64    `json:"definition_version"`
	TargetID          string   `json:"target_id"`
	TargetKind        string   `json:"target_kind"`
	InputDigest       string   `json:"input_digest"`
	SandboxReference  string   `json:"sandbox_reference"`
	Verdict           string   `json:"verdict"`
	CriterionObserved bool     `json:"criterion_observed"`
	CanaryTouched     bool     `json:"canary_touched"`
	ErrorCode         *string  `json:"error_code"`
	Evidence          []string `json:"evidence"`
}

func newProductionAttackLabEvidenceWriter(store artifactstore.ObjectReferencingArtifactStore) (*productionAttackLabEvidenceWriter, error) {
	if nilWorkerDependency(store) {
		return nil, errRuntimeUnavailable
	}
	return &productionAttackLabEvidenceWriter{store: store}, nil
}

func (writer *productionAttackLabEvidenceWriter) Write(ctx context.Context, request attackLabSandboxRequest, sandbox attackLabSandbox, result attackLabSandboxResult) (attackLabEvidenceArtifact, error) {
	if writer == nil || nilWorkerDependency(writer.store) || ctx == nil || ctx.Err() != nil || !validAttackLabEvidenceRequest(request, sandbox, result) {
		return attackLabEvidenceArtifact{}, errWorkerExecution
	}
	reference, key, err := attackLabEvidenceIdentity(request.Scope, request.Run.ID, request.Run.Attempt)
	if err != nil {
		return attackLabEvidenceArtifact{}, errWorkerExecution
	}
	var errorCode *string
	if result.ErrorCode != "" {
		code := result.ErrorCode
		errorCode = &code
	}
	document := attackLabEvidenceDocument{
		SchemaVersion: "attack-lab-evidence-v1", OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String(),
		RunID: request.Run.ID, Attempt: request.Run.Attempt, SourceRunID: request.Run.SourceRunID, DefinitionID: request.Run.DefinitionID, DefinitionVersion: request.Run.DefinitionVersion, TargetID: request.Run.TargetID, TargetKind: request.Run.TargetKind,
		InputDigest: hex.EncodeToString(request.InputDigest[:]), SandboxReference: sandbox.Reference, Verdict: result.Verdict, CriterionObserved: result.CriterionObserved, CanaryTouched: result.CanaryTouched, ErrorCode: errorCode, Evidence: append([]string(nil), result.Evidence...),
	}
	body, err := json.Marshal(document)
	if err != nil || len(body) < 1 || len(body) > 64<<20 {
		return attackLabEvidenceArtifact{}, errWorkerExecution
	}
	digest := sha256.Sum256(body)
	artifact, err := writer.store.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: request.Scope, Reference: reference}, MediaType: "application/json", Body: bytes.Clone(body)})
	if err != nil || artifact.Scope != request.Scope || artifact.Reference != reference || artifact.VersionID == "" || artifact.MediaType != "application/json" || artifact.Size != int64(len(body)) || artifact.SHA256 != digest || !bytes.Equal(artifact.Body, body) {
		return attackLabEvidenceArtifact{}, errWorkerExecution
	}
	objectReference, err := writer.store.ObjectReference(artifact.Locator)
	if err != nil || !strings.HasPrefix(objectReference, "s3://") || !strings.HasSuffix(objectReference, "/"+key) {
		return attackLabEvidenceArtifact{}, errWorkerExecution
	}
	return attackLabEvidenceArtifact{Reference: objectReference, Key: key, VersionID: artifact.VersionID, Checksum: append([]byte(nil), digest[:]...), SizeBytes: artifact.Size}, nil
}

func attackLabEvidenceIdentity(scope domain.Scope, runID string, attempt int) (domain.EvidenceRef, string, error) {
	if scope.Validate() != nil || attempt < 1 || attempt > 5 {
		return domain.EvidenceRef{}, "", errWorkerExecution
	}
	if _, err := domain.ParseProductID(runID); err != nil {
		return domain.EvidenceRef{}, "", errWorkerExecution
	}
	identity, err := apiserver.CanonicalDiscoveryID(scope, "attack_lab_evidence", runID+"\x1f"+strconv.Itoa(attempt))
	if err != nil {
		return domain.EvidenceRef{}, "", errWorkerExecution
	}
	artifactID, err := domain.ParseProductID(identity)
	if err != nil {
		return domain.EvidenceRef{}, "", errWorkerExecution
	}
	reference, err := domain.NewEvidenceRef(artifactID)
	if err != nil {
		return domain.EvidenceRef{}, "", errWorkerExecution
	}
	key := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + reference.String()
	return reference, key, nil
}

func validAttackLabEvidenceRequest(request attackLabSandboxRequest, sandbox attackLabSandbox, result attackLabSandboxResult) bool {
	if request.Scope.Validate() != nil || request.InputDigest == [sha256.Size]byte{} || request.Run.Status != "running" || request.Run.Attempt < 1 || request.Run.Attempt > 5 || request.Run.SourceRunID == request.Run.ID || request.Run.DefinitionVersion < 1 || request.Run.DefinitionVersion > 1_000_000 || !stringInWorker(request.Run.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") || !stringInWorker(request.Run.Environment, "development", "test", "staging") || !stringInWorker(request.Run.CredentialClass, "read_only", "test_write") || request.Run.Limits != (apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}) || !validAttackLabWorkerDestination(request.Run.Destination) || !attackLabWorkerSandboxReferencePattern.MatchString(sandbox.Reference) || !validAttackLabSandboxResult(result) {
		return false
	}
	for _, value := range []string{request.Run.ID, request.Run.SourceRunID, request.Run.DefinitionID, request.Run.TargetID} {
		if _, err := domain.ParseProductID(value); err != nil {
			return false
		}
	}
	return subtle.ConstantTimeCompare(request.InputDigest[:], make([]byte, sha256.Size)) != 1
}

func validAttackLabWorkerDestination(value string) bool {
	if len(value) < 1 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

var _ attackLabEvidenceWriter = (*productionAttackLabEvidenceWriter)(nil)
