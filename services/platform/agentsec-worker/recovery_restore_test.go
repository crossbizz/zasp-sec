package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
)

type recoveryRestoreAuthorityFake struct {
	mu            sync.Mutex
	claim         recoveryOperationClaim
	steps         []string
	heartbeats    int
	finished      bool
	observed      apiserver.RecoveryCounts
	validation    apiserver.RecoveryValidationEvidence
	cleanup       apiserver.RecoveryCleanupEvidence
	failedCode    string
	checkpointErr string
}

func (fake *recoveryRestoreAuthorityFake) Ready(context.Context) error { return nil }
func (fake *recoveryRestoreAuthorityFake) Claim(_ context.Context, kind, _, _ string, _, _ int) ([]recoveryOperationClaim, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "claim:"+kind)
	return []recoveryOperationClaim{fake.claim}, nil
}
func (fake *recoveryRestoreAuthorityFake) Heartbeat(context.Context, recoveryOperationLease, int) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.heartbeats++
	fake.steps = append(fake.steps, "heartbeat")
	return nil
}
func (*recoveryRestoreAuthorityFake) BeginHold(context.Context, recoveryOperationLease) error {
	return errWorkerExecution
}
func (*recoveryRestoreAuthorityFake) ReleaseHold(context.Context, recoveryOperationLease) error {
	return errWorkerExecution
}
func (*recoveryRestoreAuthorityFake) CapturePage(context.Context, recoveryOperationLease, string, *string, int) (recoveryCapturePage, error) {
	return recoveryCapturePage{}, errWorkerExecution
}
func (*recoveryRestoreAuthorityFake) FinishBackup(context.Context, recoveryOperationLease, apiserver.RecoveryManifestLocator) error {
	return errWorkerExecution
}
func (fake *recoveryRestoreAuthorityFake) CheckpointRestore(_ context.Context, _ recoveryOperationLease, from, to string, _ any) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "checkpoint:"+from+":"+to)
	if fake.checkpointErr == to {
		return errWorkerExecution
	}
	return nil
}
func (fake *recoveryRestoreAuthorityFake) FinishRestore(_ context.Context, _ recoveryOperationLease, observed apiserver.RecoveryCounts, validation apiserver.RecoveryValidationEvidence, cleanup apiserver.RecoveryCleanupEvidence) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "finish")
	fake.finished, fake.observed, fake.validation, fake.cleanup = true, observed, validation, cleanup
	return nil
}
func (fake *recoveryRestoreAuthorityFake) Fail(_ context.Context, _ recoveryOperationLease, code string, _ time.Duration, cleanup *apiserver.RecoveryCleanupEvidence) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "fail:"+code)
	fake.failedCode = code
	if cleanup != nil {
		fake.cleanup = *cleanup
	}
	return nil
}

type recoveryManifestLoaderFake struct {
	manifest recovery.Manifest
	err      error
	calls    int
}

func (fake *recoveryManifestLoaderFake) Load(context.Context, recoveryOperationClaim) (recovery.Manifest, error) {
	fake.calls++
	return fake.manifest, fake.err
}

type recoveryRestoreInfrastructureFake struct {
	mu            sync.Mutex
	steps         []string
	provisioned   recoveryRestoreTarget
	observed      apiserver.RecoveryCounts
	validation    apiserver.RecoveryArtifactLocator
	rebuildDigest [sha256.Size]byte
	cleanup       apiserver.RecoveryCleanupEvidence
	provisionErr  error
	validateErr   error
	rebuildErr    error
	cleanupErr    error
}

func (*recoveryRestoreInfrastructureFake) Ready(context.Context) error { return nil }
func (fake *recoveryRestoreInfrastructureFake) Provision(_ context.Context, input recoveryRestoreProvisionRequest) (recoveryRestoreTarget, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "provision:"+input.TargetEnvironment)
	return fake.provisioned, fake.provisionErr
}
func (fake *recoveryRestoreInfrastructureFake) Validate(_ context.Context, target recoveryRestoreTarget, _ recovery.Manifest) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "validate:"+target.Namespace)
	return fake.observed, fake.validation, fake.validateErr
}
func (fake *recoveryRestoreInfrastructureFake) Rebuild(_ context.Context, target recoveryRestoreTarget, _ recovery.Manifest) ([sha256.Size]byte, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "rebuild:"+target.Namespace)
	return fake.rebuildDigest, fake.rebuildErr
}
func (fake *recoveryRestoreInfrastructureFake) Cleanup(_ context.Context, target recoveryRestoreTarget) (apiserver.RecoveryCleanupEvidence, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "cleanup:"+target.Namespace)
	return fake.cleanup, fake.cleanupErr
}

func TestRecoveryRestoreVerifiesBeforeProvisionAndFinishesOnlyAfterExactCleanup(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	authority := &recoveryRestoreAuthorityFake{claim: claim}
	loader := &recoveryManifestLoaderFake{manifest: manifest}
	infrastructure := recoveryRestoreInfrastructureFake{
		provisioned:   recoveryRestoreTarget{BranchID: "br-recovery-123456", Namespace: "zasp-recovery-71000004000040008000000000000004", NamespaceUID: "11111111-2222-4333-8444-555555555555", ScopeDigest: "aaaaaaaaaaaaaaaa"},
		observed:      apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1},
		validation:    recoveryEvidenceLocator(scope, "pid_71000008-0000-4000-8000-000000000008", "recovery_validation_v1"),
		rebuildDigest: manifest.Projection.SHA256,
		cleanup:       apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")},
	}
	processor, err := newRecoveryRestoreProcessor(recoveryRestoreProcessorConfig{
		Authority: authority, Loader: loader, Infrastructure: &infrastructure, WorkerID: "recovery-worker-1", LeaseSeconds: 5, BatchSize: 1,
		HeartbeatInterval: 5 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if !authority.finished || authority.failedCode != "" || authority.observed != (apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}) || authority.validation.ExpectedCounts != authority.observed || authority.validation.ObservedCounts != authority.observed || authority.cleanup.State != "deleted" {
		t.Fatalf("finished=%v failed=%q observed=%#v validation=%#v cleanup=%#v steps=%v", authority.finished, authority.failedCode, authority.observed, authority.validation, authority.cleanup, authority.steps)
	}
	wantSteps := []string{"claim:restore", "heartbeat", "checkpoint:verifying:provisioning", "checkpoint:provisioning:validating", "checkpoint:validating:rebuilding", "checkpoint:rebuilding:cleanup_required", "checkpoint:cleanup_required:cleaning", "finish"}
	if !containsOrderedRecoverySteps(authority.steps, wantSteps) {
		t.Fatalf("steps=%v", authority.steps)
	}
	if got := infrastructure.steps; len(got) != 4 || got[0] != "provision:recovery-test" || got[1] != "validate:zasp-recovery-71000004000040008000000000000004" || got[2] != "rebuild:zasp-recovery-71000004000040008000000000000004" || got[3] != "cleanup:zasp-recovery-71000004000040008000000000000004" {
		t.Fatalf("infrastructure steps=%v", got)
	}
}

func TestRecoveryRestoreNeverCallsProviderBeforeManifestAuthorityPasses(t *testing.T) {
	scope := recoveryWorkerScope(t)
	authority := &recoveryRestoreAuthorityFake{claim: recoveryRestoreClaim(scope)}
	loader := &recoveryManifestLoaderFake{err: errRecoverySignatureInvalid}
	infrastructure := &recoveryRestoreInfrastructureFake{}
	processor := mustRecoveryRestoreProcessor(t, authority, loader, infrastructure)
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("err=%v", err)
	}
	if len(infrastructure.steps) != 0 || authority.failedCode != "signature_invalid" || authority.finished {
		t.Fatalf("provider=%v failed=%q finished=%v", infrastructure.steps, authority.failedCode, authority.finished)
	}
}

func TestRecoveryRestoreCleansEveryStartedPathAndPersistsFailedCleanup(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	tests := []struct {
		name        string
		configure   func(*recoveryRestoreInfrastructureFake)
		wantCode    string
		wantCleanup string
	}{
		{name: "validation", configure: func(fake *recoveryRestoreInfrastructureFake) { fake.validateErr = errors.New("validation detail") }, wantCode: "validation_failed", wantCleanup: "deleted"},
		{name: "projection digest", configure: func(fake *recoveryRestoreInfrastructureFake) { fake.rebuildDigest = sha256.Sum256([]byte("wrong")) }, wantCode: "projection_mismatch", wantCleanup: "deleted"},
		{name: "cleanup unknown", configure: func(fake *recoveryRestoreInfrastructureFake) {
			fake.cleanup = apiserver.RecoveryCleanupEvidence{State: "failed", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}
			fake.cleanupErr = errors.New("delete response lost")
		}, wantCode: "cleanup_failed", wantCleanup: "failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &recoveryRestoreAuthorityFake{claim: recoveryRestoreClaim(scope)}
			infrastructure := &recoveryRestoreInfrastructureFake{
				provisioned: recoveryRestoreTarget{BranchID: "br-recovery-123456", Namespace: "zasp-recovery-71000004000040008000000000000004", NamespaceUID: "11111111-2222-4333-8444-555555555555", ScopeDigest: "aaaaaaaaaaaaaaaa"},
				observed:    apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}, validation: recoveryEvidenceLocator(scope, "pid_71000008-0000-4000-8000-000000000008", "recovery_validation_v1"), rebuildDigest: manifest.Projection.SHA256,
				cleanup: apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")},
			}
			test.configure(infrastructure)
			processor := mustRecoveryRestoreProcessor(t, authority, &recoveryManifestLoaderFake{manifest: manifest}, infrastructure)
			if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
				t.Fatalf("err=%v", err)
			}
			if authority.finished || authority.failedCode != test.wantCode || authority.cleanup.State != test.wantCleanup || len(infrastructure.steps) == 0 || infrastructure.steps[len(infrastructure.steps)-1] != "cleanup:zasp-recovery-71000004000040008000000000000004" {
				t.Fatalf("finished=%v failed=%q cleanup=%#v steps=%v", authority.finished, authority.failedCode, authority.cleanup, infrastructure.steps)
			}
		})
	}
}

func TestRecoveryRestoreEvidenceLocatorRejectsUnscopedAndNonCanonicalAuthority(t *testing.T) {
	scope := recoveryWorkerScope(t)
	valid := recoveryEvidenceLocator(scope, "pid_71000008-0000-4000-8000-000000000008", "recovery_validation_v1")
	if !validRecoveryEvidenceLocator(valid, scope, "recovery_validation_v1") {
		t.Fatal("valid recovery evidence locator rejected")
	}
	tests := map[string]func(*apiserver.RecoveryArtifactLocator){
		"zero digest":        func(value *apiserver.RecoveryArtifactLocator) { value.SHA256 = strings.Repeat("0", 64) },
		"non hex digest":     func(value *apiserver.RecoveryArtifactLocator) { value.SHA256 = strings.Repeat("z", 64) },
		"version whitespace": func(value *apiserver.RecoveryArtifactLocator) { value.VersionID = "version 1" },
		"nested artifact":    func(value *apiserver.RecoveryArtifactLocator) { value.Reference += "/foreign" },
		"foreign scope suffix": func(value *apiserver.RecoveryArtifactLocator) {
			value.Reference = strings.Replace(value.Reference, "/artifacts/", "/artifacts/foreign/", 1)
		},
		"invalid bucket": func(value *apiserver.RecoveryArtifactLocator) {
			value.Reference = strings.Replace(value.Reference, "s3://zasp-recovery/", "s3://zasp..recovery/", 1)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if validRecoveryEvidenceLocator(value, scope, "recovery_validation_v1") {
				t.Fatalf("accepted %#v", value)
			}
		})
	}
}

func mustRecoveryRestoreProcessor(t *testing.T, authority recoveryOperationAuthority, loader recoveryManifestLoader, infrastructure recoveryRestoreInfrastructure) *recoveryRestoreProcessor {
	t.Helper()
	processor, err := newRecoveryRestoreProcessor(recoveryRestoreProcessorConfig{Authority: authority, Loader: loader, Infrastructure: infrastructure, WorkerID: "recovery-worker-1", LeaseSeconds: 5, BatchSize: 1, HeartbeatInterval: 5 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil }})
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func recoveryRestoreClaim(scope domain.Scope) recoveryOperationClaim {
	manifest := recoveryWorkerManifest(scope)
	return recoveryOperationClaim{Kind: "restore", Scope: scope, OperationID: "pid_71000004-0000-4000-8000-000000000004", Attempt: 1, TargetEnvironment: "recovery-test", Manifest: &manifest}
}

func recoveryRestoreManifest(t *testing.T, scope domain.Scope) recovery.Manifest {
	t.Helper()
	backupID, _ := domain.ParseProductID("pid_71000004-0000-4000-8000-000000000004")
	configuration := recoveryManifestArtifact(t, scope, "pid_71000005-0000-4000-8000-000000000005", 0x11, "application/vnd.zasp.recovery-configuration+json", "recovery_configuration_v1")
	projection := recoveryManifestArtifact(t, scope, "pid_71000006-0000-4000-8000-000000000006", 0x22, "application/vnd.zasp.recovery-projection+json", "recovery_projection_rebuild_v1")
	evidence := recoveryManifestArtifact(t, scope, "pid_71000007-0000-4000-8000-000000000007", 0x33, "application/json", "raw_v1")
	manifest, _, err := recovery.BuildManifest(recovery.ManifestInput{Scope: scope, BackupID: backupID, CapturedAt: time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC), NeonProjectID: "silent-river-123456", NeonBranchID: "br-falling-sun-123456", PostgresLSN: "0/16B6C50", Configuration: configuration, Projection: projection, Evidence: []recovery.ArtifactLocator{evidence}, ExpectedCounts: map[string]uint64{"assets": 3, "findings": 2, "policies": 1}})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func recoveryManifestArtifact(t *testing.T, scope domain.Scope, id string, fill byte, mediaType, schema string) recovery.ArtifactLocator {
	t.Helper()
	productID, err := domain.ParseProductID(id)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(productID)
	if err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	for index := range digest {
		digest[index] = fill
	}
	return recovery.ArtifactLocator{Scope: scope, Reference: reference, VersionID: "version-1", SHA256: digest, SizeBytes: 128, MediaType: mediaType, Schema: schema}
}

func recoveryEvidenceLocator(scope domain.Scope, id, schema string) apiserver.RecoveryArtifactLocator {
	return apiserver.RecoveryArtifactLocator{Reference: "s3://zasp-recovery/organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + id, VersionID: "version-evidence-1", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", SizeBytes: 128, MediaType: "application/json", Schema: schema}
}

func containsOrderedRecoverySteps(actual, expected []string) bool {
	index := 0
	for _, value := range actual {
		if index < len(expected) && value == expected[index] {
			index++
		}
	}
	return index == len(expected)
}
