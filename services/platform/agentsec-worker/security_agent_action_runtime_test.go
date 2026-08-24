package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentActionProcessorAppliesAndCleansTenantBoundSignedGatewayPolicy(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := apiserver.TemporaryPolicyEffectClaim{
		OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
		RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}},
	}
	authority := &temporaryPolicyAuthorityFixture{claims: []apiserver.TemporaryPolicyEffectClaim{claim}}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{
		Authority: authority, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 10 * time.Millisecond,
		KeyID: "gateway-key-01", PrivateKey: privateKey, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: sequentialActionProductIDs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(authority.stored) != 1 || len(authority.finished) != 1 || authority.finished[0].Phase != "apply" {
		t.Fatalf("stored=%#v finished=%#v", authority.stored, authority.finished)
	}
	stored := authority.stored[0]
	var compiled []policy.CompiledPolicy
	if err := json.Unmarshal(stored.Policies, &compiled); err != nil || len(compiled) != 2 {
		t.Fatalf("compiled=%#v err=%v", compiled, err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-01": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	envelope := gatewayEnvelopeFromStored(t, claim, stored, compiled)
	if _, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.Targets[0].DeviceID}, now); err != nil {
		t.Fatalf("verify apply: %v", err)
	}
	if compiled[0].Action != policy.ActionBlock || compiled[1].Action != policy.ActionBlock {
		t.Fatalf("actions=%#v", compiled)
	}

	cleanup := claim
	cleanup.Phase = "cleanup"
	cleanup.LeaseExpiresAt = now.Add(11 * time.Minute)
	cleanup.Targets[0].Sequence++
	cleanup.Targets[0].PolicyVersion++
	authority.claims = []apiserver.TemporaryPolicyEffectClaim{cleanup}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(authority.stored) != 2 || len(authority.finished) != 2 || authority.finished[1].Phase != "cleanup" {
		t.Fatalf("stored=%#v finished=%#v", authority.stored, authority.finished)
	}
	if string(authority.stored[1].Policies) != "[]" {
		t.Fatalf("cleanup policies=%s", authority.stored[1].Policies)
	}
}

func TestSessionIsolationPoliciesBlockOnlyTheExactSessionAcrossGatewayActions(t *testing.T) {
	targetSession := "pid_78000009-0000-4000-8000-000000000009"
	otherSession := "pid_78000010-0000-4000-8000-000000000010"
	compiled, err := temporaryContainmentPolicies("isolate_session", targetSession, "apply")
	if err != nil || len(compiled) != 2 {
		t.Fatalf("compiled=%#v err=%v", compiled, err)
	}
	for _, value := range compiled {
		input := map[string]string{"session_id": targetSession}
		if value.Trigger == "tool_call" {
			input["tool.name"] = "shell"
		} else {
			input["http.method"] = "POST"
		}
		blocked, blockedErr := policy.Evaluate(context.Background(), value, input)
		input["session_id"] = otherSession
		allowed, allowedErr := policy.Evaluate(context.Background(), value, input)
		if blockedErr != nil || !blocked.Matched || blocked.Action != policy.ActionBlock || allowedErr != nil || allowed.Matched {
			t.Fatalf("policy=%#v blocked=%#v blocked_err=%v allowed=%#v allowed_err=%v", value, blocked, blockedErr, allowed, allowedErr)
		}
	}
	cleanup, err := temporaryContainmentPolicies("isolate_session", targetSession, "cleanup")
	if err != nil || len(cleanup) != 0 {
		t.Fatalf("cleanup=%#v err=%v", cleanup, err)
	}
	for _, invalid := range []struct{ action, session, phase string }{
		{"isolate_session", "", "apply"},
		{"isolate_session", "foreign-session", "apply"},
		{"create_temporary_policy", targetSession, "apply"},
		{"unknown", targetSession, "apply"},
	} {
		if _, err := temporaryContainmentPolicies(invalid.action, invalid.session, invalid.phase); err == nil {
			t.Fatalf("accepted invalid=%#v", invalid)
		}
	}
}

func TestSecurityAgentActionProcessorFailsClosedWhenDurableReadbackDrifts(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := apiserver.TemporaryPolicyEffectClaim{OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003", RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}}}
	authority := &temporaryPolicyAuthorityFixture{claims: []apiserver.TemporaryPolicyEffectClaim{claim}, driftReadback: true}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{Authority: authority, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 10 * time.Millisecond, KeyID: "gateway-key-01", PrivateKey: privateKey, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: sequentialActionProductIDs()})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if err := processor.RunOnce(context.Background()); err != errWorkerExecution || len(authority.finished) != 0 {
		t.Fatalf("err=%v finished=%#v", err, authority.finished)
	}
}

func TestSecurityAgentActionProcessorDoesNotStrandContainmentWhenConnectorReconciliationFails(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := apiserver.TemporaryPolicyEffectClaim{OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003", RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}}}
	authority := &temporaryPolicyAuthorityFixture{claims: []apiserver.TemporaryPolicyEffectClaim{claim}, reconcileErr: errors.New("fixture connector drift")}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{Authority: authority, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 10 * time.Millisecond, KeyID: "gateway-key-01", PrivateKey: privateKey, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: sequentialActionProductIDs()})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if err := processor.RunOnce(context.Background()); err != errWorkerExecution || authority.reconcileCalls != 1 || len(authority.finished) != 1 {
		t.Fatalf("err=%v reconcile_calls=%d finished=%#v", err, authority.reconcileCalls, authority.finished)
	}
}

func TestSecurityAgentActionProcessorAcceptsPostgresJSONBPolicyKeyOrdering(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := apiserver.TemporaryPolicyEffectClaim{
		OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
		RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []apiserver.TemporaryPolicyTarget{{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}},
	}
	authority := &temporaryPolicyAuthorityFixture{claims: []apiserver.TemporaryPolicyEffectClaim{claim}, reorderReadbackPolicies: true}
	processor, err := newSecurityAgentActionProcessor(securityAgentActionProcessorConfig{Authority: authority, WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 10 * time.Millisecond, KeyID: "gateway-key-01", PrivateKey: privateKey, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: sequentialActionProductIDs()})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if err := processor.RunOnce(context.Background()); err != nil || len(authority.finished) != 1 {
		t.Fatalf("err=%v finished=%#v", err, authority.finished)
	}
}

func TestTemporaryPolicyResultDigestBindsRawInputAndSortedTargetDigests(t *testing.T) {
	input := "sha256:" + strings.Repeat("11", sha256.Size)
	first := "sha256:" + strings.Repeat("22", sha256.Size)
	second := "sha256:" + strings.Repeat("33", sha256.Size)
	wantHash := sha256.New()
	for _, value := range []string{input, first, second} {
		digest, err := hex.DecodeString(value[len("sha256:"):])
		if err != nil {
			t.Fatal(err)
		}
		_, _ = wantHash.Write(digest)
	}
	want := "sha256:" + hex.EncodeToString(wantHash.Sum(nil))
	for _, values := range [][]string{{first, second}, {second, first}} {
		got, err := temporaryPolicyResultDigest(input, values)
		if err != nil || got != want {
			t.Fatalf("got=%q want=%q err=%v", got, want, err)
		}
	}
	for _, invalid := range []struct {
		input   string
		targets []string
	}{
		{"sha256:00", []string{first}},
		{input, nil},
		{input, []string{"sha256:00"}},
	} {
		if _, err := temporaryPolicyResultDigest(invalid.input, invalid.targets); err == nil {
			t.Fatalf("accepted input=%q targets=%#v", invalid.input, invalid.targets)
		}
	}
}

type temporaryPolicyAuthorityFixture struct {
	mu                      sync.Mutex
	claims                  []apiserver.TemporaryPolicyEffectClaim
	stored                  []apiserver.TemporaryPolicyTargetEnvelope
	finished                []apiserver.TemporaryPolicyEffectClaim
	driftReadback           bool
	reorderReadbackPolicies bool
	reconcileErr            error
	reconcileCalls          int
}

func (*temporaryPolicyAuthorityFixture) Ready(context.Context) error { return nil }
func (fixture *temporaryPolicyAuthorityFixture) ReconcileConnectorRevocations(context.Context, string, int) (int, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.reconcileCalls++
	return 0, fixture.reconcileErr
}
func (fixture *temporaryPolicyAuthorityFixture) ClaimTemporaryPolicyEffects(context.Context, string, string, int, int) ([]apiserver.TemporaryPolicyEffectClaim, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]apiserver.TemporaryPolicyEffectClaim(nil), fixture.claims...), nil
}
func (*temporaryPolicyAuthorityFixture) HeartbeatTemporaryPolicyEffect(context.Context, apiserver.TemporaryPolicyEffectClaim, string, string, int) error {
	return nil
}
func (fixture *temporaryPolicyAuthorityFixture) StoreTemporaryPolicyTarget(_ context.Context, _ apiserver.TemporaryPolicyEffectClaim, _, _ string, envelope apiserver.TemporaryPolicyTargetEnvelope) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.stored = append(fixture.stored, envelope)
	return nil
}
func (fixture *temporaryPolicyAuthorityFixture) ReadTemporaryPolicyTarget(_ context.Context, _ apiserver.TemporaryPolicyEffectClaim, target apiserver.TemporaryPolicyTarget) (apiserver.TemporaryPolicyTargetEnvelope, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	value := fixture.stored[len(fixture.stored)-1]
	value.Target = target
	if fixture.driftReadback {
		value.EnvelopeDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	if fixture.reorderReadbackPolicies {
		var normalized []map[string]any
		if json.Unmarshal(value.Policies, &normalized) != nil {
			return apiserver.TemporaryPolicyTargetEnvelope{}, errWorkerExecution
		}
		value.Policies, _ = json.Marshal(normalized)
	}
	return value, nil
}
func (fixture *temporaryPolicyAuthorityFixture) FinishTemporaryPolicyEffect(_ context.Context, claim apiserver.TemporaryPolicyEffectClaim, _, _, resultDigest, _, _ string) (apiserver.TemporaryPolicyFinishResult, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.finished = append(fixture.finished, claim)
	state := "cleanup_pending"
	if claim.Phase == "cleanup" {
		state = "cleaned"
	}
	return apiserver.TemporaryPolicyFinishResult{RunID: claim.RunID, StepID: claim.StepID, Phase: claim.Phase, EffectState: state, OutcomeID: "pid_78000007-0000-4000-8000-000000000007", ResultDigest: resultDigest}, nil
}

func sequentialActionProductIDs() func() (string, error) {
	index := 0
	values := []string{"pid_78000008-0000-4000-8000-000000000008", "pid_78000009-0000-4000-8000-000000000009"}
	return func() (string, error) {
		value := values[index%len(values)]
		index++
		return value, nil
	}
}

func gatewayEnvelopeFromStored(t *testing.T, claim apiserver.TemporaryPolicyEffectClaim, stored apiserver.TemporaryPolicyTargetEnvelope, compiled []policy.CompiledPolicy) policy.GatewayPolicyEnvelope {
	t.Helper()
	return policy.GatewayPolicyEnvelope{ContractVersion: 1, KeyID: stored.KeyID, Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: stored.Target.DeviceID, Sequence: uint64(stored.Target.Sequence), PolicyVersion: uint64(stored.Target.PolicyVersion), IssuedAt: stored.IssuedAt, ExpiresAt: stored.ExpiresAt, FailureMode: stored.FailureMode, PayloadDigest: stored.PayloadDigest[len("sha256:"):], Policies: compiled, Signature: base64.RawURLEncoding.EncodeToString(stored.Signature)}
}
