package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestAttackLabProviderContractRejectsUnsupportedCapabilitiesBeforeQueueIO(t *testing.T) {
	for name, mutate := range map[string]func(*attackLabSandboxCapabilities){
		"unspecified":       func(c *attackLabSandboxCapabilities) { *c = attackLabSandboxCapabilities{} },
		"shared process":    func(c *attackLabSandboxCapabilities) { c.Isolation = "shared-process" },
		"direct egress":     func(c *attackLabSandboxCapabilities) { c.AllowsDirectEgress = true },
		"unfenced cleanup":  func(c *attackLabSandboxCapabilities) { c.UIDFencedLifecycle = false },
		"unbounded timeout": func(c *attackLabSandboxCapabilities) { c.Limits.TimeoutSeconds = 0 },
		"wrong cpu":         func(c *attackLabSandboxCapabilities) { c.Limits.CPU = "8" },
		"wrong memory":      func(c *attackLabSandboxCapabilities) { c.Limits.Memory = "64Gi" },
		"wrong storage":     func(c *attackLabSandboxCapabilities) { c.Limits.EphemeralStorage = "1Ti" },
	} {
		t.Run(name, func(t *testing.T) {
			steps := []string{}
			capabilities := productionAttackLabSandboxCapabilities()
			mutate(&capabilities)
			provider := &contractAttackLabProvider{recordingAttackLabProvider: &recordingAttackLabProvider{steps: &steps}, capabilities: capabilities}
			processor, err := newAttackLabProcessor(attackLabProcessorConfig{Authority: &recordingAttackLabAuthority{steps: &steps}, Queue: &recordingAttackLabQueue{steps: &steps}, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps}, WorkerID: "attack-lab-contract-01", LeaseSeconds: 60, BatchSize: 1, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }})
			if err != nil {
				t.Fatal(err)
			}
			if processor.RunOnce(context.Background()) == nil || len(steps) != 0 {
				t.Fatalf("unsupported capabilities reached queue: %v", steps)
			}
			dependencies := &productionAttackLabDependencies{Provider: provider, ready: func(context.Context) error { t.Fatal("unsupported provider reached cloud readiness"); return nil }}
			if dependencies.Ready(context.Background()) == nil {
				t.Fatal("unsupported provider reported ready")
			}
		})
	}
}

func TestAttackLabProviderCapabilitiesAreNotRuntimeReadinessEvidence(t *testing.T) {
	provider := &contractAttackLabProvider{recordingAttackLabProvider: &recordingAttackLabProvider{}, capabilities: productionAttackLabSandboxCapabilities(), readyErr: errors.New("cluster unavailable")}
	if readyAttackLabSandboxProvider(context.Background(), provider) == nil {
		t.Fatal("static capabilities established runtime readiness")
	}
	provider.readyErr, provider.capabilityErr = nil, errors.New("capabilities unavailable")
	if readyAttackLabSandboxProvider(context.Background(), provider) == nil {
		t.Fatal("missing capabilities accepted")
	}
	provider.capabilityErr = nil
	if err := readyAttackLabSandboxProvider(context.Background(), provider); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if readyAttackLabSandboxProvider(ctx, provider) == nil {
		t.Fatal("cancelled readiness accepted")
	}
}

func TestAttackLabProviderRunContractObservesWithoutRecreating(t *testing.T) {
	steps := []string{}
	provider := &recordingAttackLabProvider{steps: &steps, sandbox: attackLabSandbox{Reference: "owned"}}
	var contract attackLabSandboxProvider = provider
	ctx := context.Background()
	capabilities, err := contract.Capabilities(ctx)
	if err != nil || capabilities != productionAttackLabSandboxCapabilities() {
		t.Fatal("capability contract drifted")
	}
	sandbox, err := contract.Create(ctx, attackLabSandboxRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := contract.Run(ctx, attackLabSandboxRequest{}, sandbox); err != nil {
			t.Fatal(err)
		}
	}
	if err := contract.Cancel(ctx, sandbox); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := contract.Destroy(ctx, sandbox); err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(steps) != "[create run run cancel destroy destroy]" {
		t.Fatalf("lifecycle=%v", steps)
	}
}

type contractAttackLabProvider struct {
	*recordingAttackLabProvider
	capabilities            attackLabSandboxCapabilities
	capabilityErr, readyErr error
}

func TestAttackLabCancellationFailureResumesPersistedCleanupWithoutExecution(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_7e000001-0000-4000-8000-000000000001")
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	digest := sha256.Sum256([]byte("cancel-contract-checkpoint"))
	run := apiserver.AttackLabRun{ID: runID.String(), Version: 4, SourceRunID: "pid_7e000002-0000-4000-8000-000000000002", DefinitionID: "pid_7e000003-0000-4000-8000-000000000003", DefinitionVersion: 1, TargetID: "pid_7e000004-0000-4000-8000-000000000004", TargetKind: "mcp_server", Environment: "staging", CredentialClass: "read_only", Destination: "adapter.customer.example", Status: "cleanup", CancelRequested: true, Attempt: 1, CleanupState: "in_progress", Limits: productionAttackLabSandboxCapabilities().Limits, QueuedAt: now.Add(-2 * time.Minute), StartedAt: &started, AttemptStartedAt: &started}
	sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/zasp-attack-lab-7e000001@123e4567-e89b-12d3-a456-426614174000"}
	steps := []string{}
	authority := &recordingAttackLabAuthority{steps: &steps, claim: apiserver.AttackLabRunClaim{Disposition: "cleanup", Run: run, Checkpoint: apiserver.AttackLabCleanupCheckpoint{Attempt: 1, SandboxReference: sandbox.Reference, EvidenceState: "unavailable", Verdict: "inconclusive", ErrorCode: "cancelled"}, InputDigest: digest, LeaseExpiresAt: now.Add(time.Minute)}, cleanup: apiserver.AttackLabCleanupInput{ErrorCode: "cancelled"}}
	queue := &recordingAttackLabQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", AuthorityDigest: digest, Payload: attackLabQueuePayload(t, scope, run, digest)}}}}
	provider := &contractCancellationProvider{recordingAttackLabProvider: &recordingAttackLabProvider{steps: &steps, sandbox: sandbox}, err: errors.New("termination response lost")}
	config := attackLabProcessorConfig{Authority: authority, Queue: queue, Provider: provider, Evidence: &recordingAttackLabEvidenceWriter{steps: &steps}, WorkerID: "attack-lab-contract-01", LeaseSeconds: 60, BatchSize: 1, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("b", 32), nil }}
	processor, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if processor.RunOnce(context.Background()) == nil || fmt.Sprint(steps) != "[consume claim cancel]" {
		t.Fatalf("uncertain cancellation acknowledged or destroyed: %v", steps)
	}
	if authority.claim.Checkpoint.ErrorCode != "cancelled" {
		t.Fatal("durable cancellation intent lost")
	}
	steps = nil
	provider.err = nil
	// A new controller instance sees only the retained authority and resumes cleanup.
	resumed, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.RunOnce(context.Background()); err != nil || fmt.Sprint(steps) != "[consume claim cancel destroy finish-cleanup ack]" {
		t.Fatalf("restart err=%v steps=%v", err, steps)
	}
	steps = nil
	authority.claim.Disposition, authority.claim.Run.Status = "running", "running"
	authority.cleanupErr = errors.New("checkpoint commit unavailable")
	config.Evidence = &recordingAttackLabEvidenceWriter{steps: &steps, err: errors.New("evidence unavailable")}
	beforeCheckpoint, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if beforeCheckpoint.RunOnce(context.Background()) == nil || fmt.Sprint(steps) != "[consume claim evidence begin-cleanup]" {
		t.Fatalf("uncommitted cleanup performed destructive IO: %v", steps)
	}
	testAttackLabControllerWaitsForActualPodCleanup(t, config, authority, provider, &steps)
}

type contractCancellationProvider struct {
	*recordingAttackLabProvider
	err    error
	cancel func(context.Context, attackLabSandbox) error
}

func (provider *contractCancellationProvider) Cancel(ctx context.Context, sandbox attackLabSandbox) error {
	if ctx.Err() != nil || sandbox != provider.sandbox {
		return errors.New("cancellation authority drift")
	}
	*provider.steps = append(*provider.steps, "cancel")
	if provider.cancel != nil {
		return provider.cancel(ctx, sandbox)
	}
	return provider.err
}

func (provider *contractAttackLabProvider) Capabilities(context.Context) (attackLabSandboxCapabilities, error) {
	return provider.capabilities, provider.capabilityErr
}
func (provider *contractAttackLabProvider) Ready(context.Context) error { return provider.readyErr }
