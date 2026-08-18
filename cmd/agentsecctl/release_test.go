package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func validPreflight() PreflightInput {
	return PreflightInput{
		IAMRole: true, IRSABinding: true, S3Evidence: true, KMS: true, Secrets: true,
		Queues: true, DeadLetterQueue: true, QueuePermissions: true,
		OpenSearchReachable: true, OpenSearchIndexAccess: true,
		EKSVersionSupported: true, FargateProfile: true, AttackLabNamespace: true, PrivateNetworking: true,
		NeonMigrationCompatible: true, NeonPoolReachable: true,
		StytchProjectReachable: true, StytchSessionReachable: true,
		SensorMode: "optional", KernelSupported: true, BTFPresent: true, TetragonSupported: true,
	}
}

func validManifest() RecoveryManifest {
	return RecoveryManifest{
		SchemaVersion: 1, OrganizationID: "org-a", DeploymentMode: "single_tenant",
		NeonRecoveryPoint:     "organizations/org-a/neon/recovery-1",
		ConfigurationRefs:     []string{"organizations/org-a/config/release-1"},
		GraphExportReference:  "organizations/org-a/graph/export-1",
		EvidenceReferences:    []string{"organizations/org-a/evidence/archive-1"},
		ExpectedResourceCount: map[string]uint64{"assets": 3, "findings": 2, "policies": 1},
	}
}

func TestEvaluatePreflightSeparatesCoreFeatureAndSensorResults(t *testing.T) {
	input := validPreflight()
	report, err := EvaluatePreflight(input)
	if err != nil || !report.Ready || len(report.Checks) != 8 {
		t.Fatalf("EvaluatePreflight() = %#v, %v", report, err)
	}
	input.FargateProfile = false
	report, err = EvaluatePreflight(input)
	if err != nil || !report.Ready || report.Checks[4].Required || report.Checks[4].Status != checkFail {
		t.Fatalf("feature result = %#v, %v", report, err)
	}
	input.IAMRole = false
	report, err = EvaluatePreflight(input)
	if !errors.Is(err, errPreflightRejected) || report.Ready || report.Checks[0].Hint == "" {
		t.Fatalf("core result = %#v, %v", report, err)
	}
}

func TestEvaluatePreflightHandlesOptionalAndRequiredSensor(t *testing.T) {
	input := validPreflight()
	input.KernelSupported = false
	report, err := EvaluatePreflight(input)
	if err != nil || report.Checks[7].Status != checkWarn {
		t.Fatalf("optional sensor = %#v, %v", report, err)
	}
	input.SensorMode = "required"
	report, err = EvaluatePreflight(input)
	if !errors.Is(err, errPreflightRejected) || report.Checks[7].Status != checkFail {
		t.Fatalf("required sensor = %#v, %v", report, err)
	}
	input.SensorMode = "unknown"
	if _, err := EvaluatePreflight(input); !errors.Is(err, errPreflightRejected) {
		t.Fatalf("unknown sensor mode error = %v", err)
	}
}

func TestBackupManifestIsScopedVersionedAndReferenceOnly(t *testing.T) {
	input := validManifest()
	input.SchemaVersion = 0
	input.ConfigurationRefs = []string{"organizations/org-a/config/z", "organizations/org-a/config/a"}
	manifest, err := BuildBackupManifest(input)
	if err != nil || manifest.SchemaVersion != 1 || manifest.ConfigurationRefs[0] != "organizations/org-a/config/a" {
		t.Fatalf("BuildBackupManifest() = %#v, %v", manifest, err)
	}
	input.GraphExportReference = "organizations/org-b/graph/export-1"
	if _, err := BuildBackupManifest(input); !errors.Is(err, errManifestRejected) {
		t.Fatalf("cross-organization error = %v", err)
	}
}

func TestDecodeRecoveryManifestRejectsUnknownTrailingAndMalformedData(t *testing.T) {
	valid := `{"schema_version":1,"organization_id":"org-a","deployment_mode":"saas","neon_recovery_point":"organizations/org-a/neon/r1","configuration_refs":["organizations/org-a/config/r1"],"graph_export_reference":"organizations/org-a/graph/r1","evidence_references":["organizations/org-a/evidence/r1"],"expected_resource_count":{"assets":1}}`
	if _, err := DecodeRecoveryManifest(strings.NewReader(valid)); err != nil {
		t.Fatalf("DecodeRecoveryManifest() error = %v", err)
	}
	for _, invalid := range []string{valid + `{}`, strings.Replace(valid, `}`, `,"token":"value"}`, 1), strings.Replace(valid, "org-a/graph", "org-b/graph", 1)} {
		if _, err := DecodeRecoveryManifest(strings.NewReader(invalid)); !errors.Is(err, errManifestRejected) {
			t.Fatalf("invalid manifest error = %v", err)
		}
	}
}

func TestRunRestoreRehearsalTracksValidatesAndAlwaysCleans(t *testing.T) {
	runtime := &fakeRestoreRuntime{states: []string{"running", "complete"}, counts: map[string]uint64{"assets": 3, "findings": 2, "policies": 1}}
	result, err := RunRestoreRehearsal(context.Background(), RestoreRequest{SourceEnvironment: "production", TargetEnvironment: "rehearsal-a", DisposableTarget: true, Manifest: validManifest(), PollLimit: 3}, runtime)
	if err != nil || result != (RestoreResult{RehearsalID: "rehearsal-1", State: "complete", Validated: true, Cleaned: true}) || runtime.cleanupCalls != 1 {
		t.Fatalf("RunRestoreRehearsal() = %#v, %v, cleanup=%d", result, err, runtime.cleanupCalls)
	}
}

func TestRunRestoreRehearsalRejectsUnsafeTargetsMismatchAndCleanupFailure(t *testing.T) {
	request := RestoreRequest{SourceEnvironment: "production", TargetEnvironment: "production", DisposableTarget: true, Manifest: validManifest(), PollLimit: 1}
	if _, err := RunRestoreRehearsal(context.Background(), request, &fakeRestoreRuntime{}); !errors.Is(err, errRestoreRejected) {
		t.Fatalf("unsafe target error = %v", err)
	}
	request.TargetEnvironment = "rehearsal-a"
	runtime := &fakeRestoreRuntime{states: []string{"complete"}, counts: map[string]uint64{"assets": 99}}
	if result, err := RunRestoreRehearsal(context.Background(), request, runtime); !errors.Is(err, errRestoreRejected) || !result.Cleaned {
		t.Fatalf("mismatch result = %#v, %v", result, err)
	}
	runtime = &fakeRestoreRuntime{states: []string{"complete"}, counts: validManifest().ExpectedResourceCount, cleanupErr: errors.New("cleanup")}
	if result, err := RunRestoreRehearsal(context.Background(), request, runtime); !errors.Is(err, errRestoreRejected) || result.Cleaned {
		t.Fatalf("cleanup result = %#v, %v", result, err)
	}
}

func TestEvaluateAndRunUpgrade(t *testing.T) {
	input := UpgradeInput{CurrentVersion: "1.4.2", TargetVersion: "1.5.0", MigrationCompatible: true, BundleFormatCompatible: true, RollbackArtifactReference: "oci://zasp/release@sha256:abc", RecoveryReference: "s3://recovery/manifest.json"}
	report, err := EvaluateUpgrade(input)
	if err != nil || !report.Ready || len(report.Checks) != 4 {
		t.Fatalf("EvaluateUpgrade() = %#v, %v", report, err)
	}
	runtime := &fakeUpgradeRuntime{}
	result, err := RunUpgradeFixture(context.Background(), input, runtime)
	if err != nil || result != (UpgradeResult{FixtureID: "fixture-1", ReleaseID: "release-1", MigrationID: "migration-1"}) {
		t.Fatalf("RunUpgradeFixture() = %#v, %v", result, err)
	}
	input.MigrationCompatible = false
	if _, err := RunUpgradeFixture(context.Background(), input, runtime); !errors.Is(err, errUpgradeRejected) {
		t.Fatalf("incompatible error = %v", err)
	}
	input.MigrationCompatible = true
	input.TargetVersion = "1.5.0-extra"
	if _, err := EvaluateUpgrade(input); !errors.Is(err, errUpgradeRejected) {
		t.Fatalf("noncanonical version error = %v", err)
	}
}

func TestReleaseCommandsExposePreflightBackupRestoreAndUpgradeBoundaries(t *testing.T) {
	preflight, _ := jsonBytes(validPreflight())
	manifest, _ := jsonBytes(validManifest())
	upgrade, _ := jsonBytes(UpgradeInput{CurrentVersion: "1.4.2", TargetVersion: "1.5.0", MigrationCompatible: true, BundleFormatCompatible: true, RollbackArtifactReference: "oci://zasp/release@sha256:abc", RecoveryReference: "s3://recovery/manifest.json"})
	for name, fixture := range map[string]struct {
		arguments []string
		input     []byte
	}{
		"preflight":         {arguments: []string{"preflight"}, input: preflight},
		"backup":            {arguments: []string{"backup"}, input: manifest},
		"restore":           {arguments: []string{"restore-validate", "production", "rehearsal-a"}, input: manifest},
		"upgrade-preflight": {arguments: []string{"upgrade-preflight"}, input: upgrade},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := runCommand(&output, bytes.NewReader(fixture.input), fixture.arguments, "dev"); err != nil || output.Len() == 0 {
				t.Fatalf("runCommand() output=%q error=%v", output.String(), err)
			}
		})
	}
}

func jsonBytes(value any) ([]byte, error) {
	var buffer bytes.Buffer
	err := encodeJSON(&buffer, value)
	return buffer.Bytes(), err
}

type fakeRestoreRuntime struct {
	states       []string
	counts       map[string]uint64
	cleanupErr   error
	cleanupCalls int
}

func (*fakeRestoreRuntime) Start(context.Context, string, RecoveryManifest) (string, error) {
	return "rehearsal-1", nil
}
func (runtime *fakeRestoreRuntime) Poll(context.Context, string) (string, error) {
	if len(runtime.states) == 0 {
		return "running", nil
	}
	state := runtime.states[0]
	runtime.states = runtime.states[1:]
	return state, nil
}
func (runtime *fakeRestoreRuntime) Validate(context.Context, string, RecoveryManifest) (map[string]uint64, error) {
	return runtime.counts, nil
}
func (runtime *fakeRestoreRuntime) Cleanup(context.Context, string) error {
	runtime.cleanupCalls++
	return runtime.cleanupErr
}

type fakeUpgradeRuntime struct{}

func (*fakeUpgradeRuntime) StartFixture(context.Context, string) (string, error) {
	return "fixture-1", nil
}
func (*fakeUpgradeRuntime) StartUpgrade(context.Context, string, string) (string, string, error) {
	return "release-1", "migration-1", nil
}
