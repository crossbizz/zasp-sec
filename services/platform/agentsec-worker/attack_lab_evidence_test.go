package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductionAttackLabEvidenceWriterPersistsCanonicalAttemptArtifact(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := "pid_7f200001-0000-4000-8000-000000000001"
	digest := sha256.Sum256([]byte("attack-lab-evidence-input"))
	request := attackLabSandboxRequest{Scope: scope, Run: apiserver.AttackLabRun{ID: runID, Version: 3, SourceRunID: "pid_7f200002-0000-4000-8000-000000000002", DefinitionID: "pid_7f200003-0000-4000-8000-000000000003", DefinitionVersion: 2, TargetID: "pid_7f200004-0000-4000-8000-000000000004", TargetKind: "agent_endpoint", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "running", Attempt: 2, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: time.Now().UTC()}, InputDigest: digest}
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7f200001@123e4567-e89b-12d3-a456-426614174000"}
	result := attackLabSandboxResult{Verdict: "verified", CriterionObserved: true, CanaryTouched: true, Evidence: []string{"semantic:criterion observed", "gateway:allowed", "egress:adapter.customer.example", "kubernetes:job complete", "cloud:canary touched"}}
	store := &attackLabEvidenceStoreStub{}
	writer, err := newProductionAttackLabEvidenceWriter(store)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := writer.Write(context.Background(), request, sandbox, result)
	if err != nil || len(store.puts) != 1 {
		t.Fatalf("artifact=%#v err=%v puts=%#v", artifact, err, store.puts)
	}
	wantID, err := apiserver.CanonicalDiscoveryID(scope, "attack_lab_evidence", runID+"\x1f2")
	if err != nil {
		t.Fatal(err)
	}
	wantKey := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + wantID
	if artifact.Key != wantKey || artifact.Reference != "s3://zasp-attack-lab-evidence/"+wantKey || artifact.VersionID != "version-attack-lab-1" || artifact.SizeBytes != int64(len(store.puts[0].Body)) || !bytes.Equal(artifact.Checksum, store.puts[0].BodySHA256[:]) {
		t.Fatalf("artifact=%#v put=%#v", artifact, store.puts[0])
	}
	var body struct {
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
	if err := json.Unmarshal(store.puts[0].Body, &body); err != nil || body.SchemaVersion != "attack-lab-evidence-v1" || body.OrganizationID != scope.OrganizationID().String() || body.WorkspaceID != scope.WorkspaceID().String() || body.EnvironmentID != scope.EnvironmentID().String() || body.RunID != runID || body.Attempt != 2 || body.InputDigest != hex.EncodeToString(digest[:]) || body.SandboxReference != sandbox.Reference || body.Verdict != "verified" || body.ErrorCode != nil || len(body.Evidence) != 5 {
		t.Fatalf("body=%#v err=%v raw=%s", body, err, store.puts[0].Body)
	}
	if strings.Contains(string(store.puts[0].Body), "credential_reference") || strings.Contains(string(store.puts[0].Body), "lease_token") {
		t.Fatalf("evidence leaked authority: %s", store.puts[0].Body)
	}
	if replay, err := writer.Write(context.Background(), request, sandbox, result); err != nil || replay.Reference != artifact.Reference || len(store.puts) != 2 || !bytes.Equal(store.puts[0].Body, store.puts[1].Body) || store.puts[0].Reference != store.puts[1].Reference {
		t.Fatalf("replay=%#v err=%v puts=%#v", replay, err, store.puts)
	}
}

func TestProductionAttackLabEvidenceWriterRejectsMismatchedArtifactStoreResult(t *testing.T) {
	request, sandbox, result := validAttackLabEvidenceWriteFixture(t)
	for _, mutate := range []func(*artifactstore.Artifact){
		func(value *artifactstore.Artifact) { value.Scope = fixtureRedTeamScopeWithSuffix(t, 9) },
		func(value *artifactstore.Artifact) { value.VersionID = "" },
		func(value *artifactstore.Artifact) { value.Size++ },
		func(value *artifactstore.Artifact) { value.SHA256 = sha256.Sum256([]byte("drift")) },
	} {
		store := &attackLabEvidenceStoreStub{mutate: mutate}
		writer, err := newProductionAttackLabEvidenceWriter(store)
		if err != nil {
			t.Fatal(err)
		}
		if artifact, err := writer.Write(context.Background(), request, sandbox, result); !errors.Is(err, errWorkerExecution) || artifact.Reference != "" || artifact.Key != "" || artifact.VersionID != "" || artifact.Checksum != nil || artifact.SizeBytes != 0 {
			t.Fatalf("artifact=%#v err=%v", artifact, err)
		}
	}
}

func validAttackLabEvidenceWriteFixture(t *testing.T) (attackLabSandboxRequest, attackLabSandbox, attackLabSandboxResult) {
	t.Helper()
	scope := fixtureRedTeamScope(t)
	digest := sha256.Sum256([]byte("attack-lab-evidence-fixture"))
	run := apiserver.AttackLabRun{ID: "pid_7f210001-0000-4000-8000-000000000001", Version: 2, SourceRunID: "pid_7f210002-0000-4000-8000-000000000002", DefinitionID: "pid_7f210003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f210004-0000-4000-8000-000000000004", TargetKind: "mcp_server", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "running", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: time.Now().UTC()}
	return attackLabSandboxRequest{Scope: scope, Run: run, InputDigest: digest}, attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7f210001@123e4567-e89b-12d3-a456-426614174000"}, attackLabSandboxResult{Verdict: "not_reproduced", Evidence: []string{"semantic:criterion not observed", "gateway:allowed", "egress:no undeclared egress", "kubernetes:job complete", "cloud:canary untouched"}}
}

type attackLabEvidenceStoreStub struct {
	puts   []attackLabEvidencePut
	mutate func(*artifactstore.Artifact)
}

type attackLabEvidencePut struct {
	artifactstore.PutRequest
	BodySHA256 [sha256.Size]byte
}

func (store *attackLabEvidenceStoreStub) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	digest := sha256.Sum256(request.Body)
	store.puts = append(store.puts, attackLabEvidencePut{PutRequest: artifactstore.PutRequest{Locator: request.Locator, MediaType: request.MediaType, Body: bytes.Clone(request.Body)}, BodySHA256: digest})
	artifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: request.Scope, Reference: request.Reference, VersionID: "version-attack-lab-1"}, MediaType: request.MediaType, Body: bytes.Clone(request.Body), Size: int64(len(request.Body)), SHA256: digest}
	if store.mutate != nil {
		store.mutate(&artifact)
	}
	return artifact, nil
}
func (*attackLabEvidenceStoreStub) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, nil
}
func (*attackLabEvidenceStoreStub) Delete(context.Context, artifactstore.Locator) error { return nil }
func (*attackLabEvidenceStoreStub) ObjectReference(locator artifactstore.Locator) (string, error) {
	return "s3://zasp-attack-lab-evidence/organizations/" + locator.Scope.OrganizationID().String() + "/workspaces/" + locator.Scope.WorkspaceID().String() + "/environments/" + locator.Scope.EnvironmentID().String() + "/artifacts/" + locator.Reference.String(), nil
}

var _ artifactstore.ObjectReferencingArtifactStore = (*attackLabEvidenceStoreStub)(nil)

func fixtureRedTeamScopeWithSuffix(t *testing.T, suffix byte) domain.Scope {
	t.Helper()
	organization := mustProductID(t, "pid_10000001-0000-4000-8000-00000000000"+string('0'+suffix))
	workspace := mustProductID(t, "pid_10000002-0000-4000-8000-000000000002")
	environment := mustProductID(t, "pid_10000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
