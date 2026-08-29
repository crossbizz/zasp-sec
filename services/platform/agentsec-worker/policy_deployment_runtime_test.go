package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestPolicyDeploymentProcessorPublishesDeterministicPersistentAndTemporaryUnion(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := policy.Compile(policy.Policy{ID: "temporary-containment-mcp-v1", Trigger: "tool_call", Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}, Action: policy.ActionBlock})
	if err != nil {
		t.Fatal(err)
	}
	temporaryExpiresAt := now.Add(15 * time.Minute)
	claim := policyDeploymentClaim{
		OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003",
		DeviceID: "pid_70000004-0000-4000-8000-000000000004", CredentialID: "pid_70000005-0000-4000-8000-000000000005", DesiredGeneration: 4, Sequence: 7, PolicyVersion: 7,
		InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeaseExpiresAt: now.Add(time.Minute),
		PersistentPolicies: []policy.Policy{
			{ID: "policy-runtime", Name: "Runtime", Scope: "environment", Trigger: "runtime", Conditions: []policy.Condition{{Field: "resource", Operator: "equals", Value: "repository"}}, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"},
			{ID: "policy-tool", Name: "Tool", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "write"}}, Action: policy.ActionBlock, Rollout: "monitor", FailureMode: "closed"},
		},
		TemporaryPolicies: []policy.CompiledPolicy{temporary}, TemporaryExpiresAt: &temporaryExpiresAt,
	}
	authority := &policyDeploymentAuthorityFixture{claims: []policyDeploymentClaim{claim}}
	processor, err := newPolicyDeploymentProcessor(policyDeploymentProcessorConfig{
		Authority: authority, WorkerID: "policy-deployment-01", LeaseSeconds: 60, BatchSize: 8, HeartbeatInterval: 10 * time.Millisecond,
		KeyID: "gateway-key-01", PrivateKey: privateKey, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(authority.stored) != 1 || len(authority.finished) != 1 {
		t.Fatalf("stored=%d finished=%d", len(authority.stored), len(authority.finished))
	}
	envelope := authority.stored[0]
	if envelope.Sequence != 7 || envelope.PolicyVersion != 7 || !envelope.ExpiresAt.Equal(temporaryExpiresAt) || envelope.FailureMode != "closed" || len(envelope.Policies) != 3 || envelope.Policies[0].ID != "policy-runtime" || envelope.Policies[1].ID != "policy-tool" || envelope.Policies[1].Action != policy.ActionMonitor || envelope.Policies[2].ID != "temporary-containment-mcp-v1" {
		t.Fatalf("envelope=%+v", envelope)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-01": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if authority.finished[0].DesiredGeneration != claim.DesiredGeneration || authority.finished[0].EnvelopeDigest == "" {
		t.Fatalf("finish=%+v", authority.finished[0])
	}
}

func TestPolicyDeploymentProcessorRejectsConflictingOrDriftedEffectiveInputBeforeFinish(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	persistent := policy.Policy{ID: "policy-conflict", Name: "Persistent", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "write"}}, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
	temporary, err := policy.Compile(policy.Policy{ID: "policy-conflict", Trigger: "tool_call", Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}, Action: policy.ActionBlock})
	if err != nil {
		t.Fatal(err)
	}
	temporaryExpiresAt := now.Add(10 * time.Minute)
	claim := policyDeploymentClaim{OrganizationID: "pid_71000001-0000-4000-8000-000000000001", WorkspaceID: "pid_71000002-0000-4000-8000-000000000002", EnvironmentID: "pid_71000003-0000-4000-8000-000000000003", DeviceID: "pid_71000004-0000-4000-8000-000000000004", CredentialID: "pid_71000005-0000-4000-8000-000000000005", DesiredGeneration: 1, Sequence: 1, PolicyVersion: 1, InputDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", LeaseExpiresAt: now.Add(time.Minute), PersistentPolicies: []policy.Policy{persistent}, TemporaryPolicies: []policy.CompiledPolicy{temporary}, TemporaryExpiresAt: &temporaryExpiresAt}
	authority := &policyDeploymentAuthorityFixture{claims: []policyDeploymentClaim{claim}}
	processor, err := newPolicyDeploymentProcessor(policyDeploymentProcessorConfig{Authority: authority, WorkerID: "policy-deployment-01", LeaseSeconds: 60, BatchSize: 8, HeartbeatInterval: 10 * time.Millisecond, KeyID: "gateway-key-01", PrivateKey: privateKey, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer processor.Close()
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) || len(authority.stored) != 0 || len(authority.finished) != 0 {
		t.Fatalf("err=%v stored=%d finished=%d", err, len(authority.stored), len(authority.finished))
	}

	claim.TemporaryPolicies = nil
	claim.TemporaryExpiresAt = nil
	authority.claims = []policyDeploymentClaim{claim}
	authority.driftReadback = true
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) || len(authority.finished) != 0 {
		t.Fatalf("drift err=%v finished=%d", err, len(authority.finished))
	}
}

type policyDeploymentFinishCall struct {
	DesiredGeneration int64
	EnvelopeDigest    string
}

type policyDeploymentAuthorityFixture struct {
	claims        []policyDeploymentClaim
	stored        []policy.GatewayPolicyEnvelope
	finished      []policyDeploymentFinishCall
	driftReadback bool
}

func (*policyDeploymentAuthorityFixture) Ready(context.Context) error { return nil }

func (fixture *policyDeploymentAuthorityFixture) ClaimPolicyDeployments(context.Context, string, string, int, int) ([]policyDeploymentClaim, error) {
	return append([]policyDeploymentClaim(nil), fixture.claims...), nil
}

func (*policyDeploymentAuthorityFixture) HeartbeatPolicyDeployment(context.Context, policyDeploymentClaim, string, string, int) error {
	return nil
}

func (fixture *policyDeploymentAuthorityFixture) StorePolicyDeployment(_ context.Context, _ policyDeploymentClaim, _, _ string, envelope policy.GatewayPolicyEnvelope) (string, error) {
	fixture.stored = append(fixture.stored, envelope)
	return policyDeploymentEnvelopeDigest(envelope)
}

func (fixture *policyDeploymentAuthorityFixture) ReadPolicyDeployment(context.Context, policyDeploymentClaim) (policy.GatewayPolicyEnvelope, error) {
	if len(fixture.stored) == 0 {
		return policy.GatewayPolicyEnvelope{}, errWorkerExecution
	}
	value := fixture.stored[len(fixture.stored)-1]
	if fixture.driftReadback {
		value.Sequence++
	}
	return value, nil
}

func (fixture *policyDeploymentAuthorityFixture) FinishPolicyDeployment(_ context.Context, claim policyDeploymentClaim, _, _, digest string) error {
	fixture.finished = append(fixture.finished, policyDeploymentFinishCall{DesiredGeneration: claim.DesiredGeneration, EnvelopeDigest: digest})
	return nil
}
