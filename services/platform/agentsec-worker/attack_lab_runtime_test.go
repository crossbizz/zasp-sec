package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestAttackLabProcessorCreatesCollectsCheckpointsDestroysFinishesThenAcknowledges(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7d000001-0000-4000-8000-000000000001")
	sourceRunID := "pid_7d000002-0000-4000-8000-000000000002"
	definitionID := "pid_7d000003-0000-4000-8000-000000000003"
	targetID := "pid_7d000004-0000-4000-8000-000000000004"
	digest := sha256.Sum256([]byte("attack-lab-authority"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 2, SourceRunID: sourceRunID, DefinitionID: definitionID, DefinitionVersion: 1, TargetID: targetID, TargetKind: "agent_endpoint", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	preflight := apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", AllowedDestinations: []string{"canary.attack-lab.internal"}, SuccessCriterion: "Observe the exact canary touch", ExpectedSideEffects: []string{"one test canary mutation"}}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: preflight, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7d000001@123e4567-e89b-12d3-a456-426614174000"}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: sandbox, result: attackLabSandboxResult{Verdict: "verified", CriterionObserved: true, CanaryTouched: true, Evidence: []string{"semantic:criterion observed", "gateway:allowed", "egress:canary.attack-lab.internal", "kubernetes:job complete", "cloud:canary touched"}}}
	evidenceKey := mustAttackLabRuntimeEvidenceKey(t, scope, runID.String(), 1)
	evidence := &recordingAttackLabEvidenceWriter{steps: &steps, artifact: attackLabEvidenceArtifact{Reference: "s3://zasp-attack-lab-evidence/" + evidenceKey, Key: evidenceKey, VersionID: "version-1", Checksum: bytes.Repeat([]byte{0xcc}, sha256.Size), SizeBytes: 512}}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: evidence, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "provisioning", "create", "running", "collect", "evidence", "begin-cleanup", "destroy", "finish-cleanup", "ack"}
	if got := fmt.Sprint(steps); got != fmt.Sprint(want) {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
	if authority.cleanup.RunID != runID.String() || authority.cleanup.Attempt != 1 || authority.cleanup.InputDigest != digest || authority.cleanup.SandboxReference != sandbox.Reference || authority.cleanup.Verdict != "verified" || !bytes.Equal(authority.cleanup.EvidenceChecksum, evidence.artifact.Checksum) {
		t.Fatalf("cleanup=%#v", authority.cleanup)
	}
}

func TestAttackLabProcessorResumesDurableCleanupWithoutRerunningSandbox(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7e000001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-cleanup-resume"))
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 4, SourceRunID: "pid_7e000002-0000-4000-8000-000000000002", DefinitionID: "pid_7e000003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7e000004-0000-4000-8000-000000000004", TargetKind: "mcp_server", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "cleanup", Attempt: 1, CleanupState: "in_progress", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Minute), StartedAt: &started, AttemptStartedAt: &started}
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7e000001@123e4567-e89b-12d3-a456-426614174000"}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "cleanup", Run: run, Checkpoint: apiserver.AttackLabCleanupCheckpoint{Attempt: 1, SandboxReference: sandbox.Reference, EvidenceState: "unavailable", Verdict: "inconclusive", ErrorCode: "outcome_unknown"}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: sandbox}
	evidence := &recordingAttackLabEvidenceWriter{steps: &steps}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: evidence, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("b", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "destroy", "finish-cleanup", "ack"}
	if got := fmt.Sprint(steps); got != fmt.Sprint(want) {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
}

func TestAttackLabProcessorCancellationBeforeSandboxWinsWithoutProviderIO(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f000001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-cancel-before-sandbox"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f000002-0000-4000-8000-000000000002", DefinitionID: "pid_7f000003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f000004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CancelRequested: true, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	cancelled := run
	cancelled.Status, cancelled.CleanupState, cancelled.ErrorCode = "cancelled", "complete", "cancelled"
	completed := now
	cancelled.CompletedAt = &completed
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary touched", ExpectedSideEffects: []string{"test mutation"}}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}, retryTransition: apiserver.AttackLabRunTransition{Run: cancelled}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	provider := &recordingAttackLabProvider{steps: &steps}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps}, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("c", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "retry", "ack"}
	if got := fmt.Sprint(steps); got != fmt.Sprint(want) {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
}

func TestAttackLabProcessorCancellationAfterSandboxPersistsEvidenceBeforeCleanup(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f100001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-cancel-after-sandbox"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f100002-0000-4000-8000-000000000002", DefinitionID: "pid_7f100003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f100004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, heartbeat: apiserver.AttackLabRunHeartbeat{Renewed: true, CancelRequested: true}, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary touched", ExpectedSideEffects: []string{"test mutation"}}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7f100001@123e4567-e89b-12d3-a456-426614174000"}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: sandbox, blockCollectUntilCancel: true}
	evidenceKey := mustAttackLabRuntimeEvidenceKey(t, scope, runID.String(), 1)
	evidence := &recordingAttackLabEvidenceWriter{steps: &steps, rejectCancelledContext: true, artifact: attackLabEvidenceArtifact{Reference: "s3://zasp-attack-lab-evidence/" + evidenceKey, Key: evidenceKey, VersionID: "version-cancelled-1", Checksum: bytes.Repeat([]byte{0xcd}, sha256.Size), SizeBytes: 512}}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: evidence, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("d", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "provisioning", "create", "running", "collect", "evidence", "begin-cleanup", "destroy", "finish-cleanup", "ack"}
	if got := fmt.Sprint(steps); got != fmt.Sprint(want) {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
	if authority.cleanup.Verdict != "inconclusive" || authority.cleanup.ErrorCode != "cancelled" || authority.cleanup.CriterionObserved || authority.cleanup.CanaryTouched {
		t.Fatalf("cleanup=%#v", authority.cleanup)
	}
}

func TestAttackLabProcessorReconcilesLostCreateResponseBeforeCancellationCleanup(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f105001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-lost-create-cancellation"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f105002-0000-4000-8000-000000000002", DefinitionID: "pid_7f105003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f105004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	preflight := apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary touched", ExpectedSideEffects: []string{"test mutation"}}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, heartbeat: apiserver.AttackLabRunHeartbeat{Renewed: true, CancelRequested: true}, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: preflight, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7f105001@123e4567-e89b-12d3-a456-426614174009"}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: sandbox, createWaitForCancel: true, createErr: errors.New("lost create response"), reconcileErrOnce: &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}, reconcileFound: true}
	evidenceKey := mustAttackLabRuntimeEvidenceKey(t, scope, runID.String(), 1)
	evidence := &recordingAttackLabEvidenceWriter{steps: &steps, rejectCancelledContext: true, artifact: attackLabEvidenceArtifact{Reference: "s3://zasp-attack-lab-evidence/" + evidenceKey, Key: evidenceKey, VersionID: "version-lost-create", Checksum: bytes.Repeat([]byte{0xcf}, sha256.Size), SizeBytes: 512}}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: evidence, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("9", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "provisioning", "create", "reconcile", "reconcile", "running", "evidence", "begin-cleanup", "destroy", "finish-cleanup", "ack"}
	if fmt.Sprint(steps) != fmt.Sprint(want) || provider.reconcileContextErr != nil || authority.cleanup.ErrorCode != "cancelled" {
		t.Fatalf("steps=%v reconcile_ctx=%v cleanup=%#v", steps, provider.reconcileContextErr, authority.cleanup)
	}
}

func TestAttackLabProcessorTerminalizesUnambiguousCreateDenialWithoutReconcile(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f106001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-create-denied"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f106002-0000-4000-8000-000000000002", DefinitionID: "pid_7f106003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f106004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	failed := run
	failed.Status, failed.CleanupState, failed.ErrorCode = "failed", "complete", "denied"
	completed := now
	failed.CompletedAt = &completed
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary touched", ExpectedSideEffects: []string{"test mutation"}}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}, retryTransition: apiserver.AttackLabRunTransition{Run: failed}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	provider := &recordingAttackLabProvider{steps: &steps, createErr: &attackLabProviderFailure{code: "denied", retryAfter: 30 * time.Second}}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps}, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return strings.Repeat("7", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "provisioning", "create", "retry", "ack"}
	if fmt.Sprint(steps) != fmt.Sprint(want) {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
}

func TestAttackLabProcessorKeepsAmbiguousCreateProvisioningWithoutRetryOrAck(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f107001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-create-ambiguous"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f107002-0000-4000-8000-000000000002", DefinitionID: "pid_7f107003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f107004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary touched", ExpectedSideEffects: []string{"test mutation"}}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	unknown := &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	provider := &recordingAttackLabProvider{steps: &steps, createErr: unknown, reconcileErr: unknown}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps}, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return strings.Repeat("8", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	if len(steps) != 4+attackLabReconcileAttempts || steps[0] != "consume" || steps[1] != "claim" || steps[2] != "provisioning" || steps[3] != "create" {
		t.Fatalf("steps=%v", steps)
	}
	for _, step := range steps[4:] {
		if step != "reconcile" {
			t.Fatalf("unexpected step=%q steps=%v", step, steps)
		}
	}
}

func TestAttackLabProcessorEvidenceFailureStillCheckpointsAndDestroysSandbox(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f110001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-evidence-failure"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f110002-0000-4000-8000-000000000002", DefinitionID: "pid_7f110003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f110004-0000-4000-8000-000000000004", TargetKind: "agent_endpoint", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: apiserver.AttackLabPreflightSnapshot{Environment: "staging", CredentialClass: "read_only", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary untouched", ExpectedSideEffects: []string{"none"}}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7f110001@123e4567-e89b-12d3-a456-426614174000"}, result: attackLabSandboxResult{Verdict: "not_reproduced", Evidence: []string{"semantic:criterion not observed", "gateway:allowed", "egress:no undeclared egress", "kubernetes:job complete", "cloud:canary untouched"}}}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps, err: errors.New("artifact unavailable")}, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("e", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	want := []string{"consume", "claim", "provisioning", "create", "running", "collect", "evidence", "begin-cleanup", "destroy", "finish-cleanup", "ack"}
	if got := fmt.Sprint(steps); got != fmt.Sprint(want) {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
	if authority.cleanup.Verdict != "inconclusive" || authority.cleanup.ErrorCode != "outcome_unknown" || authority.cleanup.Evidence != nil || authority.cleanup.EvidenceReference != "" || authority.cleanup.EvidenceChecksum != nil {
		t.Fatalf("cleanup=%#v", authority.cleanup)
	}
}

func TestAttackLabProcessorCancellationEvidenceFailureStillDestroysSandbox(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7f115001-0000-4000-8000-000000000001")
	digest := sha256.Sum256([]byte("attack-lab-cancel-evidence-failure"))
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 3, SourceRunID: "pid_7f115002-0000-4000-8000-000000000002", DefinitionID: "pid_7f115003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7f115004-0000-4000-8000-000000000004", TargetKind: "coding_agent", Environment: "test", CredentialClass: "test_write", Destination: "canary.attack-lab.internal", Status: "leased", Attempt: 1, CleanupState: "pending", Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started, AttemptStartedAt: &started}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, heartbeat: apiserver.AttackLabRunHeartbeat{Renewed: true, CancelRequested: true}, claim: apiserver.AttackLabRunClaim{Disposition: "claimed", Run: run, Preflight: apiserver.AttackLabPreflightSnapshot{Environment: "test", CredentialClass: "test_write", Destination: run.Destination, AllowedDestinations: []string{run.Destination}, SuccessCriterion: "Canary touched", ExpectedSideEffects: []string{"test mutation"}}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7f115001@123e4567-e89b-12d3-a456-426614174003"}, blockCollectUntilCancel: true}
	processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps, err: errors.New("artifact unavailable")}, WorkerID: "attack-lab-controller-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("f", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	if authority.cleanup.Verdict != "inconclusive" || authority.cleanup.ErrorCode != "cancelled" || len(authority.cleanup.Evidence) != 0 || authority.cleanup.EvidenceReference != "" {
		t.Fatalf("cleanup=%#v", authority.cleanup)
	}
}

func TestAttackLabEvidenceArtifactRejectsPrefixedObjectPath(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := "pid_7f120001-0000-4000-8000-000000000001"
	key := mustAttackLabRuntimeEvidenceKey(t, scope, runID, 1)
	artifact := attackLabEvidenceArtifact{Reference: "s3://zasp-attack-lab-evidence/" + key, Key: key, VersionID: "version-1", Checksum: bytes.Repeat([]byte{0xce}, sha256.Size), SizeBytes: 512}
	if !validAttackLabEvidenceArtifact(scope, runID, 1, artifact) {
		t.Fatal("exact evidence object path rejected")
	}
	artifact.Reference = "s3://zasp-attack-lab-evidence/foreign-prefix/" + key
	if validAttackLabEvidenceArtifact(scope, runID, 1, artifact) {
		t.Fatal("prefixed evidence object path accepted")
	}
}

func attackLabQueuePayload(t *testing.T, scope domain.Scope, run apiserver.AttackLabRun, digest [sha256.Size]byte) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "run_id": run.ID, "source_run_id": run.SourceRunID, "definition_id": run.DefinitionID, "definition_version": run.DefinitionVersion, "target_id": run.TargetID, "target_kind": run.TargetKind, "input_digest": hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mustAttackLabRuntimeEvidenceKey(t *testing.T, scope domain.Scope, runID string, attempt int) string {
	t.Helper()
	_, key, err := attackLabEvidenceIdentity(scope, runID, attempt)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type recordingAttackLabAuthority struct {
	steps           *[]string
	claim           apiserver.AttackLabRunClaim
	heartbeat       apiserver.AttackLabRunHeartbeat
	cleanup         apiserver.AttackLabCleanupInput
	retryTransition apiserver.AttackLabRunTransition
}

func (*recordingAttackLabAuthority) Ready(context.Context) error { return nil }
func (authority *recordingAttackLabAuthority) ClaimAttackLabRun(context.Context, domain.Scope, string, string, string, int) (apiserver.AttackLabRunClaim, error) {
	*authority.steps = append(*authority.steps, "claim")
	return authority.claim, nil
}
func (authority *recordingAttackLabAuthority) HeartbeatAttackLabRun(context.Context, domain.Scope, string, string, string, int) (apiserver.AttackLabRunHeartbeat, error) {
	if authority.heartbeat == (apiserver.AttackLabRunHeartbeat{}) {
		return apiserver.AttackLabRunHeartbeat{Renewed: true}, nil
	}
	return authority.heartbeat, nil
}
func (authority *recordingAttackLabAuthority) RetryAttackLabRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte, string, time.Time) (apiserver.AttackLabRunTransition, error) {
	*authority.steps = append(*authority.steps, "retry")
	return authority.retryTransition, nil
}
func (authority *recordingAttackLabAuthority) BeginAttackLabProvisioning(_ context.Context, _ domain.Scope, _ apiserver.AttackLabProvisioningInput) (apiserver.AttackLabRunTransition, error) {
	*authority.steps = append(*authority.steps, "provisioning")
	run := authority.claim.Run
	run.Version++
	return apiserver.AttackLabRunTransition{Run: run}, nil
}
func (authority *recordingAttackLabAuthority) MarkAttackLabRunning(_ context.Context, _ domain.Scope, input apiserver.AttackLabRunningInput) (apiserver.AttackLabRunTransition, error) {
	*authority.steps = append(*authority.steps, "running")
	run := authority.claim.Run
	run.Status, run.Version = "running", run.Version+1
	return apiserver.AttackLabRunTransition{Run: run}, nil
}
func (authority *recordingAttackLabAuthority) BeginAttackLabCleanup(_ context.Context, _ domain.Scope, input apiserver.AttackLabCleanupInput) (apiserver.AttackLabRunTransition, error) {
	*authority.steps = append(*authority.steps, "begin-cleanup")
	authority.cleanup = input
	run := authority.claim.Run
	run.Status, run.CleanupState = "cleanup", "in_progress"
	return apiserver.AttackLabRunTransition{Run: run}, nil
}
func (authority *recordingAttackLabAuthority) FinishAttackLabCleanup(context.Context, domain.Scope, string, string, string, [sha256.Size]byte) (apiserver.AttackLabRunTransition, error) {
	*authority.steps = append(*authority.steps, "finish-cleanup")
	run := authority.claim.Run
	run.Status, run.CleanupState, run.Verdict = "complete", "complete", authority.cleanup.Verdict
	if authority.cleanup.ErrorCode == "cancelled" {
		run.Status, run.ErrorCode = "cancelled", "cancelled"
	}
	return apiserver.AttackLabRunTransition{Run: run}, nil
}

type recordingAttackLabQueue struct {
	steps      *[]string
	deliveries []jobqueue.Delivery
}

func (queue *recordingAttackLabQueue) ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error) {
	*queue.steps = append(*queue.steps, "consume")
	return append([]jobqueue.Delivery(nil), queue.deliveries...), nil
}
func (queue *recordingAttackLabQueue) AcknowledgeBatch(context.Context, []jobqueue.Receipt) error {
	*queue.steps = append(*queue.steps, "ack")
	return nil
}
func (*recordingAttackLabQueue) ExtendVisibility(context.Context, []jobqueue.Receipt, time.Duration) error {
	return nil
}

type recordingAttackLabProvider struct {
	steps                   *[]string
	sandbox                 attackLabSandbox
	result                  attackLabSandboxResult
	blockCollectUntilCancel bool
	createWaitForCancel     bool
	createErr               error
	reconcileFound          bool
	reconcileErr            error
	reconcileErrOnce        error
	reconcileContextErr     error
}

func (*recordingAttackLabProvider) Ready(context.Context) error { return nil }
func (provider *recordingAttackLabProvider) Create(ctx context.Context, _ attackLabSandboxRequest) (attackLabSandbox, error) {
	*provider.steps = append(*provider.steps, "create")
	if provider.createWaitForCancel {
		<-ctx.Done()
	}
	return provider.sandbox, provider.createErr
}
func (provider *recordingAttackLabProvider) Reconcile(ctx context.Context, _ attackLabSandboxRequest) (attackLabSandbox, bool, error) {
	*provider.steps = append(*provider.steps, "reconcile")
	provider.reconcileContextErr = ctx.Err()
	if provider.reconcileErrOnce != nil {
		err := provider.reconcileErrOnce
		provider.reconcileErrOnce = nil
		return attackLabSandbox{}, false, err
	}
	found := provider.reconcileFound || provider.sandbox.Reference != ""
	return provider.sandbox, found, provider.reconcileErr
}
func (provider *recordingAttackLabProvider) Collect(ctx context.Context, _ attackLabSandboxRequest, _ attackLabSandbox) (attackLabSandboxResult, error) {
	*provider.steps = append(*provider.steps, "collect")
	if provider.blockCollectUntilCancel {
		<-ctx.Done()
		return attackLabSandboxResult{}, ctx.Err()
	}
	return provider.result, nil
}
func (provider *recordingAttackLabProvider) Destroy(context.Context, attackLabSandbox) error {
	*provider.steps = append(*provider.steps, "destroy")
	return nil
}

type recordingAttackLabEvidenceWriter struct {
	steps                  *[]string
	artifact               attackLabEvidenceArtifact
	rejectCancelledContext bool
	err                    error
}

func (writer *recordingAttackLabEvidenceWriter) Write(ctx context.Context, _ attackLabSandboxRequest, _ attackLabSandbox, _ attackLabSandboxResult) (attackLabEvidenceArtifact, error) {
	*writer.steps = append(*writer.steps, "evidence")
	if writer.rejectCancelledContext && ctx.Err() != nil {
		return attackLabEvidenceArtifact{}, ctx.Err()
	}
	if writer.err != nil {
		return attackLabEvidenceArtifact{}, writer.err
	}
	return writer.artifact, nil
}
