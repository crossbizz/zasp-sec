package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type blockedActionHeartbeatAuthority struct {
	*actionBudgetStopAuthority
	heartbeatOutcome error
}

func (a *blockedActionHeartbeatAuthority) HeartbeatTemporaryPolicyEffect(ctx context.Context, _ apiserver.TemporaryPolicyEffectClaim, _, _ string, _ int) error {
	close(a.heartbeatCalled)
	<-ctx.Done()
	a.heartbeatOutcome = ctx.Err()
	return ctx.Err()
}

func TestSecurityAgentActionProcessorBoundsHeartbeatJoinAndPreservesParentCancellation(t *testing.T) {
	for _, mode := range []string{"parent_cancel", "heartbeat_deadline"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			_, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			claim := apiserver.TemporaryPolicyEffectClaim{
				OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
				RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}},
			}
			authority := &blockedActionHeartbeatAuthority{actionBudgetStopAuthority: &actionBudgetStopAuthority{
				temporaryPolicyAuthorityFixture: &temporaryPolicyAuthorityFixture{}, storeErr: apiserver.ErrSecurityAgentBudgetStopped, heartbeatCalled: make(chan struct{}),
			}}
			ids := 0
			processor, err := newSecurityAgentActionProcessor(securityAgentProcessorConfigForJoin(authority, key, now, &ids))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				result <- processor.process(ctx, claim, "lease-token-000000000001")
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-joined:
				case <-time.After(6 * time.Second):
					t.Error("owned action processor did not join")
				}
				processor.Close()
			})
			select {
			case <-authority.heartbeatCalled:
			case <-time.After(2 * time.Second):
				t.Fatal("heartbeat never started")
			}
			wait, wantHeartbeat := 7*time.Second, error(context.DeadlineExceeded)
			if mode == "parent_cancel" {
				cancel()
				wait, wantHeartbeat = 2*time.Second, context.Canceled
			}
			select {
			case <-joined:
			case <-time.After(wait):
				t.Fatal("heartbeat join exceeded cancellation bound")
			}
			operationErr := <-result
			if !errors.Is(authority.heartbeatOutcome, wantHeartbeat) || (mode == "parent_cancel" && operationErr != nil) || (mode == "heartbeat_deadline" && operationErr != errWorkerExecution) {
				t.Fatalf("operation=%v heartbeat=%v want=%v", operationErr, authority.heartbeatOutcome, wantHeartbeat)
			}
			if authority.stores != 1 || authority.reads != 0 || authority.finishCalls != 0 || ids != 0 {
				t.Fatal("heartbeat join allowed work after the committed stop")
			}
		})
	}
}

func securityAgentProcessorConfigForJoin(authority apiserver.SecurityAgentActionAuthority, key ed25519.PrivateKey, now time.Time, ids *int) securityAgentActionProcessorConfig {
	return securityAgentActionProcessorConfig{
		Authority: authority, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond,
		KeyID: "gateway-key-01", PrivateKey: key, Now: func() time.Time { return now },
		NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil },
		NewProductID:  func() (string, error) { *ids++; return "", errors.New("unexpected artifact allocation") },
	}
}
