package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// A confirmed stop must exit before readback, another target or finish. An
// error with the same text is not authority to treat an operation as stopped.
func TestSecurityAgentActionProcessorConsumesOnlyConfirmedApplyBudgetStop(t *testing.T) {
	for _, tc := range []struct {
		name, phase  string
		storeErr     error
		wantErr      bool
		wantReads    int
		atFinish     bool
		heartbeatErr error
	}{
		{"stopped", "apply", apiserver.ErrSecurityAgentBudgetStopped, false, 0, false, nil},
		{"wrapped", "apply", fmt.Errorf("store: %w", apiserver.ErrSecurityAgentBudgetStopped), false, 0, false, nil},
		{"text_only", "apply", errors.New(apiserver.ErrSecurityAgentBudgetStopped.Error()), true, 1, false, nil},
		{"cleanup_not_exempted", "cleanup", apiserver.ErrSecurityAgentBudgetStopped, true, 1, false, nil},
		{"finish_apply_not_exempted", "apply", apiserver.ErrSecurityAgentBudgetStopped, true, 2, true, nil},
		{"finish_cleanup_not_exempted", "cleanup", apiserver.ErrSecurityAgentBudgetStopped, true, 2, true, nil},
		{"heartbeat_conflict", "apply", apiserver.ErrSecurityAgentBudgetStopped, true, 0, false, apiserver.ErrRepositoryConflict},
		{"heartbeat_unavailable", "apply", apiserver.ErrSecurityAgentBudgetStopped, true, 0, false, apiserver.ErrRepositoryUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
			_, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			claim := apiserver.TemporaryPolicyEffectClaim{
				OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
				RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: tc.phase, InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{
					{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2},
					{DeviceID: "pid_78000005-0000-4000-8000-000000000005", CredentialID: "pid_78000006-0000-4000-8000-000000000006", Sequence: 2, PolicyVersion: 2},
				},
			}
			authority := &actionBudgetStopAuthority{temporaryPolicyAuthorityFixture: &temporaryPolicyAuthorityFixture{}, storeErr: tc.storeErr, atFinish: tc.atFinish, heartbeatErr: tc.heartbeatErr}
			if tc.heartbeatErr != nil {
				authority.heartbeatCalled = make(chan struct{})
			}
			ids := 0
			nextID := sequentialActionProductIDs()
			processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{
				Authority: authority, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 10 * time.Millisecond,
				KeyID: "gateway-key-01", PrivateKey: key, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil },
				NewProductID: func() (string, error) { ids++; return nextID() },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer processor.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = processor.process(ctx, claim, "lease-token-000000000001")
			wantStores, wantFinishes, wantIDs := 1, 0, 0
			if tc.atFinish {
				wantStores, wantFinishes, wantIDs = 2, 1, 2
			}
			if ctx.Err() != nil || (err != nil) != tc.wantErr || authority.stores != wantStores || authority.reads != tc.wantReads || authority.finishCalls != wantFinishes || ids != wantIDs {
				t.Fatalf("err=%v stores=%d reads=%d finishes=%d ids=%d", err, authority.stores, authority.reads, authority.finishCalls, ids)
			}
		})
	}
}

type actionBudgetStopAuthority struct {
	*temporaryPolicyAuthorityFixture
	storeErr        error
	stores, reads   int
	atFinish        bool
	heartbeatErr    error
	heartbeatCalled chan struct{}
}

func (a *actionBudgetStopAuthority) StoreTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, worker, lease string, envelope apiserver.TemporaryPolicyTargetEnvelope) error {
	a.stores++
	if a.atFinish {
		return a.temporaryPolicyAuthorityFixture.StoreTemporaryPolicyTarget(ctx, claim, worker, lease, envelope)
	}
	if a.heartbeatCalled != nil {
		select {
		case <-a.heartbeatCalled:
		case <-time.After(2 * time.Second):
			return errors.New("heartbeat was not observed")
		}
	}
	return a.storeErr
}

func (a *actionBudgetStopAuthority) ReadTemporaryPolicyTarget(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, target apiserver.TemporaryPolicyTarget) (apiserver.TemporaryPolicyTargetEnvelope, error) {
	a.reads++
	if a.atFinish {
		return a.temporaryPolicyAuthorityFixture.ReadTemporaryPolicyTarget(ctx, claim, target)
	}
	return apiserver.TemporaryPolicyTargetEnvelope{}, apiserver.ErrRepositoryConflict
}

func (a *actionBudgetStopAuthority) FinishTemporaryPolicyEffect(context.Context, apiserver.TemporaryPolicyEffectClaim, string, string, string, string, string) (apiserver.TemporaryPolicyFinishResult, error) {
	a.finishCalls++
	return apiserver.TemporaryPolicyFinishResult{}, a.storeErr
}

func (a *actionBudgetStopAuthority) HeartbeatTemporaryPolicyEffect(context.Context, apiserver.TemporaryPolicyEffectClaim, string, string, int) error {
	if a.heartbeatCalled != nil {
		close(a.heartbeatCalled)
	}
	return a.heartbeatErr
}
