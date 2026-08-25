package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recoveryAuthorityFake struct {
	mu         sync.Mutex
	claim      recoveryOperationClaim
	steps      []string
	heartbeats int
	finished   apiserver.RecoveryManifestLocator
	failedCode string
	releaseErr error
	captureErr error
	finishErr  error
}

func (fake *recoveryAuthorityFake) Ready(context.Context) error { return nil }

func (fake *recoveryAuthorityFake) Claim(_ context.Context, kind, worker, token string, _ int, _ int) ([]recoveryOperationClaim, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "claim:"+kind+":"+worker+":"+token)
	return []recoveryOperationClaim{fake.claim}, nil
}

func (fake *recoveryAuthorityFake) Heartbeat(context.Context, recoveryOperationLease, int) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.heartbeats++
	fake.steps = append(fake.steps, "heartbeat")
	return nil
}

func (fake *recoveryAuthorityFake) BeginHold(context.Context, recoveryOperationLease) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "hold")
	return nil
}

func (fake *recoveryAuthorityFake) ReleaseHold(context.Context, recoveryOperationLease) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "release")
	return fake.releaseErr
}

func (fake *recoveryAuthorityFake) CapturePage(_ context.Context, _ recoveryOperationLease, section string, after *string, _ int) (recoveryCapturePage, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "capture:"+section)
	if fake.captureErr != nil {
		return recoveryCapturePage{}, fake.captureErr
	}
	if after != nil {
		return recoveryCapturePage{Section: section, Items: []json.RawMessage{}}, nil
	}
	next := "next"
	if section == "counts" {
		next = ""
	}
	page := recoveryCapturePage{Section: section, Items: []json.RawMessage{json.RawMessage(`{"id":"pid_71000001-0000-4000-8000-000000000001"}`)}}
	if next != "" {
		page.NextCursor = &next
	}
	return page, nil
}

func (fake *recoveryAuthorityFake) FinishBackup(_ context.Context, _ recoveryOperationLease, manifest apiserver.RecoveryManifestLocator) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "finish")
	fake.finished = manifest
	return fake.finishErr
}

func (fake *recoveryAuthorityFake) CheckpointRestore(context.Context, recoveryOperationLease, string, string, any) error {
	return nil
}

func (fake *recoveryAuthorityFake) FinishRestore(context.Context, recoveryOperationLease, apiserver.RecoveryCounts, apiserver.RecoveryValidationEvidence, apiserver.RecoveryCleanupEvidence) error {
	return nil
}

func (fake *recoveryAuthorityFake) Fail(_ context.Context, _ recoveryOperationLease, code string, _ time.Duration, _ *apiserver.RecoveryCleanupEvidence) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.steps = append(fake.steps, "fail:"+code)
	fake.failedCode = code
	return nil
}

type recoveryPublisherFake struct {
	manifest apiserver.RecoveryManifestLocator
	err      error
	delay    time.Duration
	input    recoveryBackupPublication
}

func (fake *recoveryPublisherFake) Publish(ctx context.Context, input recoveryBackupPublication) (apiserver.RecoveryManifestLocator, error) {
	fake.input = input
	if fake.delay > 0 {
		select {
		case <-ctx.Done():
			return apiserver.RecoveryManifestLocator{}, ctx.Err()
		case <-time.After(fake.delay):
		}
	}
	return fake.manifest, fake.err
}

func TestRecoveryBackupProcessorHoldsCapturesPublishesAndFinishesUnderOneLease(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryWorkerManifest(scope)
	authority := &recoveryAuthorityFake{claim: recoveryOperationClaim{
		Kind: "backup", Scope: scope, OperationID: "pid_71000001-0000-4000-8000-000000000001", Attempt: 1, RetentionDays: 30,
	}}
	publisher := &recoveryPublisherFake{manifest: manifest, delay: 20 * time.Millisecond}
	processor, err := newRecoveryBackupProcessor(recoveryBackupProcessorConfig{
		Authority: authority, Publisher: publisher, WorkerID: "recovery-worker-1", LeaseSeconds: 5, BatchSize: 1,
		HeartbeatInterval: 5 * time.Millisecond, PageSize: 100, NewLeaseToken: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.finished != manifest || authority.failedCode != "" || authority.heartbeats < 2 {
		t.Fatalf("finished=%#v failed=%q heartbeats=%d steps=%v", authority.finished, authority.failedCode, authority.heartbeats, authority.steps)
	}
	if len(authority.steps) < 9 || authority.steps[1] != "heartbeat" || authority.steps[2] != "hold" || authority.steps[3] != "capture:configuration" {
		t.Fatalf("ordering=%v", authority.steps)
	}
	if len(publisher.input.Sections["configuration"]) != 1 || len(publisher.input.Sections["projection"]) != 1 || len(publisher.input.Sections["evidence"]) != 1 || len(publisher.input.Sections["counts"]) != 1 {
		t.Fatalf("publication=%#v", publisher.input)
	}
}

func TestRecoveryBackupProcessorReleasesHoldAndPersistsStableFailure(t *testing.T) {
	scope := recoveryWorkerScope(t)
	authority := &recoveryAuthorityFake{claim: recoveryOperationClaim{
		Kind: "backup", Scope: scope, OperationID: "pid_71000001-0000-4000-8000-000000000001", Attempt: 1, RetentionDays: 30,
	}}
	publisher := &recoveryPublisherFake{err: errors.New("provider detail must be redacted")}
	processor, err := newRecoveryBackupProcessor(recoveryBackupProcessorConfig{
		Authority: authority, Publisher: publisher, WorkerID: "recovery-worker-1", LeaseSeconds: 5, BatchSize: 1,
		HeartbeatInterval: 5 * time.Millisecond, PageSize: 100, NewLeaseToken: func() (string, error) { return "0123456789abcdef0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("err=%v", err)
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.failedCode != "outcome_unknown" || len(authority.steps) < 2 || authority.steps[len(authority.steps)-2] != "release" || authority.steps[len(authority.steps)-1] != "fail:outcome_unknown" {
		t.Fatalf("failed=%q steps=%v", authority.failedCode, authority.steps)
	}
}

func recoveryWorkerScope(t *testing.T) domain.Scope {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_71000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_71000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_71000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func recoveryWorkerManifest(scope domain.Scope) apiserver.RecoveryManifestLocator {
	return apiserver.RecoveryManifestLocator{
		Reference: "s3://zasp-recovery/organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/pid_71000004-0000-4000-8000-000000000004",
		VersionID: "version-recovery-1", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 512,
		MediaType: "application/vnd.zasp.recovery-manifest+json", Schema: "recovery_signed_manifest_v1", SigningKeyID: "123e4567-e89b-42d3-a456-426614174000", Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}
