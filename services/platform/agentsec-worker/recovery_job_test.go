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

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type recoveryJobDatabaseFake struct {
	payload json.RawMessage
	err     error
	calls   int
}

func (fake *recoveryJobDatabaseFake) ValidateScope(_ context.Context, organization, workspace, environment string) (json.RawMessage, error) {
	fake.calls++
	if organization != "pid_71000001-0000-4000-8000-000000000001" || workspace != "pid_71000002-0000-4000-8000-000000000002" || environment != "pid_71000003-0000-4000-8000-000000000003" {
		return nil, errors.New("foreign scope")
	}
	return append(json.RawMessage(nil), fake.payload...), fake.err
}

func (*recoveryJobDatabaseFake) ProjectionPage(context.Context, string, string, string, string, string, string, int) (apiserver.SnapshotProjectionPage, error) {
	return apiserver.SnapshotProjectionPage{}, errors.New("unexpected projection page")
}

func TestRecoveryJobsValidateScopedCountsAndExactProjectionDescriptor(t *testing.T) {
	projection := json.RawMessage(`[{"integration_id":"pid_71000010-0000-4000-8000-000000000010","projection_cursors":[]}]`)
	digest := sha256.Sum256(projection)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	database := &recoveryJobDatabaseFake{payload: json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":` + string(projection) + `}`)}
	base := recoveryJobConfig{PostgresDSN: "postgres://recovery@ep-recovery.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", BranchIP: "10.24.8.7", OrganizationID: "pid_71000001-0000-4000-8000-000000000001", WorkspaceID: "pid_71000002-0000-4000-8000-000000000002", EnvironmentID: "pid_71000003-0000-4000-8000-000000000003", TargetEnvironment: "recovery-test", ProjectionSHA256: hex.EncodeToString(digest[:]), EvidenceSampleSHA256: hex.EncodeToString(evidenceDigest[:])}

	validation := base
	validation.Mode = recoveryJobModePostgresValidation
	var output bytes.Buffer
	if err := runRecoveryJob(context.Background(), validation, database, &output); err != nil {
		t.Fatal(err)
	}
	var validationResult struct {
		SchemaVersion        string                   `json:"schema_version"`
		Counts               apiserver.RecoveryCounts `json:"counts"`
		EvidenceSampleSHA256 string                   `json:"evidence_sample_sha256"`
	}
	if decodeStrictWorkerJSON(output.Bytes(), &validationResult) != nil || validationResult.SchemaVersion != "recovery_validation_job_v1" || validationResult.Counts != (apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}) || validationResult.EvidenceSampleSHA256 != base.EvidenceSampleSHA256 {
		t.Fatalf("validation=%s", output.Bytes())
	}

	for _, kind := range []string{"graph", "search"} {
		projectionConfig := base
		projectionConfig.Mode = recoveryJobMode("recovery-" + kind + "-projection")
		projectionConfig.TargetDirectory = t.TempDir()
		output.Reset()
		if err := runRecoveryJob(context.Background(), projectionConfig, database, &output); err != nil {
			t.Fatal(err)
		}
		var projectionResult struct {
			SchemaVersion        string `json:"schema_version"`
			Kind                 string `json:"kind"`
			ProjectionSHA256     string `json:"projection_sha256"`
			EvidenceSampleSHA256 string `json:"evidence_sample_sha256"`
		}
		if decodeStrictWorkerJSON(output.Bytes(), &projectionResult) != nil || projectionResult.SchemaVersion != "recovery_projection_job_v1" || projectionResult.Kind != kind || projectionResult.ProjectionSHA256 != base.ProjectionSHA256 || projectionResult.EvidenceSampleSHA256 != base.EvidenceSampleSHA256 {
			t.Fatalf("projection=%s", output.Bytes())
		}
	}
	if database.calls != 3 {
		t.Fatalf("calls=%d", database.calls)
	}
}

func TestRecoveryJobsRejectCountOrProjectionDriftWithoutSuccessOutput(t *testing.T) {
	evidenceDigest := sha256.Sum256([]byte("[]"))
	base := recoveryJobConfig{Mode: recoveryJobModeGraphProjection, PostgresDSN: "postgres://recovery@ep-recovery.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", BranchIP: "10.24.8.7", OrganizationID: "pid_71000001-0000-4000-8000-000000000001", WorkspaceID: "pid_71000002-0000-4000-8000-000000000002", EnvironmentID: "pid_71000003-0000-4000-8000-000000000003", TargetEnvironment: "recovery-test", ProjectionSHA256: strings.Repeat("a", 64), EvidenceSampleSHA256: hex.EncodeToString(evidenceDigest[:]), TargetDirectory: t.TempDir()}
	for name, payload := range map[string]json.RawMessage{
		"projection drift": json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":[]}`),
		"count overflow":   json.RawMessage(`{"counts":{"assets":1000000001,"findings":2,"policies":1},"evidence_samples":[],"projection":[]}`),
		"unknown field":    json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":[],"secret":"value"}`),
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := runRecoveryJob(context.Background(), base, &recoveryJobDatabaseFake{payload: payload}, &output); !errors.Is(err, errWorkerExecution) || output.Len() != 0 {
				t.Fatalf("output=%q err=%v", output.String(), err)
			}
		})
	}
	invalidAddress := base
	invalidAddress.BranchIP = "127.0.0.1"
	var output bytes.Buffer
	if err := runRecoveryJob(context.Background(), invalidAddress, &recoveryJobDatabaseFake{payload: json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":[]}`)}, &output); !errors.Is(err, errWorkerExecution) || output.Len() != 0 {
		t.Fatalf("loopback output=%q err=%v", output.String(), err)
	}
}

func TestRecoveryJobBindsExactSampledEvidenceBeforeValidation(t *testing.T) {
	item := recoveryEvidenceSample{
		ArtifactKey: "organizations/pid_71000001-0000-4000-8000-000000000001/raw.json", ArtifactReference: "pid_71000011-0000-4000-8000-000000000011", ArtifactVersionID: "version-evidence-1",
		Checksum: strings.Repeat("1", 64), CollectedAt: "2026-08-24T16:00:00Z", ID: "pid_71000012-0000-4000-8000-000000000012", MediaType: "application/json",
		ObjectReference: "s3://zasp-evidence/organizations/pid_71000001-0000-4000-8000-000000000001/raw.json", SchemaVersion: "raw-v1", SizeBytes: 128,
	}
	digest, err := recoveryEvidenceSampleDigest([]recoveryEvidenceSample{item})
	if err != nil {
		t.Fatal(err)
	}
	projection := json.RawMessage(`[]`)
	projectionDigest := sha256.Sum256(projection)
	payload, err := json.Marshal(map[string]any{"counts": apiserver.RecoveryCounts{}, "evidence_samples": []recoveryEvidenceSample{item}, "projection": json.RawMessage(projection)})
	if err != nil {
		t.Fatal(err)
	}
	config := recoveryJobConfig{
		Mode: recoveryJobModePostgresValidation, PostgresDSN: "postgres://recovery@ep-recovery.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", BranchIP: "10.24.8.7",
		OrganizationID: "pid_71000001-0000-4000-8000-000000000001", WorkspaceID: "pid_71000002-0000-4000-8000-000000000002", EnvironmentID: "pid_71000003-0000-4000-8000-000000000003",
		TargetEnvironment: "recovery-test", ProjectionSHA256: hex.EncodeToString(projectionDigest[:]), EvidenceSampleSHA256: hex.EncodeToString(digest[:]),
	}
	var output bytes.Buffer
	if err := runRecoveryJob(context.Background(), config, &recoveryJobDatabaseFake{payload: payload}, &output); err != nil || !bytes.Contains(output.Bytes(), []byte(config.EvidenceSampleSHA256)) {
		t.Fatalf("sample validation output=%s err=%v", output.Bytes(), err)
	}
	config.EvidenceSampleSHA256 = strings.Repeat("2", 64)
	output.Reset()
	if err := runRecoveryJob(context.Background(), config, &recoveryJobDatabaseFake{payload: payload}, &output); !errors.Is(err, errWorkerExecution) || output.Len() != 0 {
		t.Fatalf("sample drift output=%s err=%v", output.Bytes(), err)
	}
}
