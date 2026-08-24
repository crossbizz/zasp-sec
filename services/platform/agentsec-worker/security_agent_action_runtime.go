package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

type securityAgentActionProcessorConfig struct {
	Authority         apiserver.SecurityAgentActionAuthority
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	KeyID             string
	PrivateKey        ed25519.PrivateKey
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
	NewProductID      func() (string, error)
}

type securityAgentActionProcessor struct {
	config securityAgentActionProcessorConfig
	mu     sync.RWMutex
	closed bool
}

func newSecurityAgentActionProcessor(config securityAgentActionProcessorConfig) (*securityAgentActionProcessor, error) {
	leaseDuration := time.Duration(config.LeaseSeconds) * time.Second
	if config.Authority == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 30 || config.LeaseSeconds > 300 || config.BatchSize < 1 || config.BatchSize > 25 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > leaseDuration/2 || config.Now == nil || config.NewLeaseToken == nil || config.NewProductID == nil || config.Now().IsZero() || config.Now().Location() != time.UTC || len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errWorkerConfiguration
	}
	publicKey, ok := config.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errWorkerConfiguration
	}
	if _, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{config.KeyID: publicKey}); err != nil {
		return nil, errWorkerConfiguration
	}
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &securityAgentActionProcessor{config: config}, nil
}

func (processor *securityAgentActionProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	processor.mu.RLock()
	if processor.closed {
		processor.mu.RUnlock()
		return errWorkerExecution
	}
	var reconciliationErr error
	if authority, ok := processor.config.Authority.(apiserver.SecurityAgentConnectorRevocationAuthority); ok {
		_, reconciliationErr = authority.ReconcileConnectorRevocations(ctx, processor.config.WorkerID, processor.config.BatchSize)
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || len(leaseToken) < 16 || len(leaseToken) > 128 {
		processor.mu.RUnlock()
		return errWorkerExecution
	}
	claims, err := processor.config.Authority.ClaimTemporaryPolicyEffects(ctx, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil {
		processor.mu.RUnlock()
		return errWorkerExecution
	}
	for _, claim := range claims {
		if ctx.Err() != nil {
			processor.mu.RUnlock()
			return nil
		}
		if processor.process(ctx, claim, leaseToken) != nil {
			processor.mu.RUnlock()
			return errWorkerExecution
		}
	}
	processor.mu.RUnlock()
	if reconciliationErr != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *securityAgentActionProcessor) process(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, leaseToken string) error {
	workCtx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(processor.config.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				heartbeatDone <- nil
				return
			case <-ticker.C:
				if err := processor.config.Authority.HeartbeatTemporaryPolicyEffect(workCtx, claim, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds); err != nil {
					heartbeatDone <- err
					cancel()
					return
				}
			}
		}
	}()
	operationErr := processor.applyClaim(workCtx, claim, leaseToken)
	cancel()
	heartbeatErr := <-heartbeatDone
	if ctx.Err() != nil {
		return nil
	}
	if operationErr != nil || heartbeatErr != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *securityAgentActionProcessor) applyClaim(ctx context.Context, claim apiserver.TemporaryPolicyEffectClaim, leaseToken string) error {
	now := processor.config.Now().UTC().Truncate(time.Second)
	compiled, err := temporaryContainmentPolicies(claim.Phase)
	if err != nil {
		return errWorkerExecution
	}
	verifiedDigests := make([]string, 0, len(claim.Targets))
	for _, target := range claim.Targets {
		expiresAt := now.Add(time.Duration(claim.TTLSeconds) * time.Second)
		if claim.Phase == "cleanup" {
			expiresAt = now.Add(5 * time.Minute)
		}
		signed, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{
			KeyID:    processor.config.KeyID,
			Binding:  policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: target.DeviceID},
			Sequence: uint64(target.Sequence), PolicyVersion: uint64(target.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expiresAt, FailureMode: "closed", Policies: compiled,
		}, processor.config.PrivateKey)
		if err != nil {
			return errWorkerExecution
		}
		stored, err := temporaryPolicyRepositoryEnvelope(target, claim.Phase, signed)
		if err != nil {
			return errWorkerExecution
		}
		if err := processor.config.Authority.StoreTemporaryPolicyTarget(ctx, claim, processor.config.WorkerID, leaseToken, stored); err != nil {
			readback, readErr := processor.config.Authority.ReadTemporaryPolicyTarget(ctx, claim, target)
			if readErr != nil || !sameTemporaryPolicyEnvelope(stored, readback) {
				return errWorkerExecution
			}
		}
		readback, err := processor.config.Authority.ReadTemporaryPolicyTarget(ctx, claim, target)
		if err != nil || !sameTemporaryPolicyEnvelope(stored, readback) || processor.verifyReadback(claim, readback, now) != nil {
			return errWorkerExecution
		}
		verifiedDigests = append(verifiedDigests, readback.EnvelopeDigest)
	}
	resultDigest, err := temporaryPolicyResultDigest(claim.InputDigest, verifiedDigests)
	if err != nil {
		return errWorkerExecution
	}
	ids, err := processor.newProductIDs(2)
	if err != nil {
		return errWorkerExecution
	}
	_, err = processor.config.Authority.FinishTemporaryPolicyEffect(ctx, claim, processor.config.WorkerID, leaseToken, resultDigest, ids[0], ids[1])
	return err
}

func (processor *securityAgentActionProcessor) verifyReadback(claim apiserver.TemporaryPolicyEffectClaim, readback apiserver.TemporaryPolicyTargetEnvelope, now time.Time) error {
	var compiled []policy.CompiledPolicy
	if json.Unmarshal(readback.Policies, &compiled) != nil {
		return errWorkerExecution
	}
	publicKey, ok := processor.config.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errWorkerExecution
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{processor.config.KeyID: publicKey})
	if err != nil {
		return errWorkerExecution
	}
	payloadDigest := readback.PayloadDigest
	if len(payloadDigest) != len("sha256:")+sha256.Size*2 || payloadDigest[:len("sha256:")] != "sha256:" {
		return errWorkerExecution
	}
	envelope := policy.GatewayPolicyEnvelope{ContractVersion: 1, KeyID: readback.KeyID, Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: readback.Target.DeviceID, Sequence: uint64(readback.Target.Sequence), PolicyVersion: uint64(readback.Target.PolicyVersion), IssuedAt: readback.IssuedAt, ExpiresAt: readback.ExpiresAt, FailureMode: readback.FailureMode, PayloadDigest: payloadDigest[len("sha256:"):], Policies: compiled, Signature: base64.RawURLEncoding.EncodeToString(readback.Signature)}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return errWorkerExecution
	}
	digest := sha256.Sum256(encoded)
	if readback.EnvelopeDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return errWorkerExecution
	}
	_, err = policy.VerifyGatewayPolicyEnvelope(envelope, keys, policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: readback.Target.DeviceID}, now)
	return err
}

func temporaryPolicyResultDigest(inputDigest string, envelopeDigests []string) (string, error) {
	input, err := decodeActionDigest(inputDigest)
	if err != nil || len(envelopeDigests) == 0 || len(envelopeDigests) > 1000 {
		return "", errWorkerExecution
	}
	sort.Strings(envelopeDigests)
	resultHash := sha256.New()
	_, _ = resultHash.Write(input)
	for _, value := range envelopeDigests {
		digest, decodeErr := decodeActionDigest(value)
		if decodeErr != nil {
			return "", errWorkerExecution
		}
		_, _ = resultHash.Write(digest)
	}
	return "sha256:" + hex.EncodeToString(resultHash.Sum(nil)), nil
}

func decodeActionDigest(value string) ([]byte, error) {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return nil, errWorkerExecution
	}
	digest, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(digest) != sha256.Size {
		return nil, errWorkerExecution
	}
	return digest, nil
}

func temporaryPolicyRepositoryEnvelope(target apiserver.TemporaryPolicyTarget, phase string, signed policy.GatewayPolicyEnvelope) (apiserver.TemporaryPolicyTargetEnvelope, error) {
	policies, err := json.Marshal(signed.Policies)
	if err != nil {
		return apiserver.TemporaryPolicyTargetEnvelope{}, errWorkerExecution
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return apiserver.TemporaryPolicyTargetEnvelope{}, errWorkerExecution
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return apiserver.TemporaryPolicyTargetEnvelope{}, errWorkerExecution
	}
	envelopeDigest := sha256.Sum256(encoded)
	return apiserver.TemporaryPolicyTargetEnvelope{Target: target, Phase: phase, KeyID: signed.KeyID, IssuedAt: signed.IssuedAt, ExpiresAt: signed.ExpiresAt, FailureMode: signed.FailureMode, PayloadDigest: "sha256:" + signed.PayloadDigest, Policies: policies, Signature: signature, EnvelopeDigest: "sha256:" + hex.EncodeToString(envelopeDigest[:])}, nil
}

func temporaryContainmentPolicies(phase string) ([]policy.CompiledPolicy, error) {
	if phase == "cleanup" {
		return []policy.CompiledPolicy{}, nil
	}
	if phase != "apply" {
		return nil, errWorkerExecution
	}
	definitions := []policy.Policy{
		{ID: "temporary-containment-http-v1", Trigger: "http_request", Conditions: []policy.Condition{{Field: "http.method", Operator: "present"}}, Action: policy.ActionBlock},
		{ID: "temporary-containment-mcp-v1", Trigger: "tool_call", Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}, Action: policy.ActionBlock},
	}
	compiled := make([]policy.CompiledPolicy, len(definitions))
	for index, definition := range definitions {
		value, err := policy.Compile(definition)
		if err != nil {
			return nil, errWorkerExecution
		}
		compiled[index] = value
	}
	return compiled, nil
}

func sameTemporaryPolicyEnvelope(left, right apiserver.TemporaryPolicyTargetEnvelope) bool {
	leftPolicies, leftOK := canonicalTemporaryPolicies(left.Policies)
	rightPolicies, rightOK := canonicalTemporaryPolicies(right.Policies)
	return leftOK && rightOK && left.Target == right.Target && left.Phase == right.Phase && left.KeyID == right.KeyID && left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt) && left.FailureMode == right.FailureMode && left.PayloadDigest == right.PayloadDigest && bytes.Equal(leftPolicies, rightPolicies) && bytes.Equal(left.Signature, right.Signature) && left.EnvelopeDigest == right.EnvelopeDigest
}

func canonicalTemporaryPolicies(raw json.RawMessage) ([]byte, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policies []policy.CompiledPolicy
	if decoder.Decode(&policies) != nil {
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, false
	}
	encoded, err := json.Marshal(policies)
	return encoded, err == nil
}

func (processor *securityAgentActionProcessor) newProductIDs(count int) ([]string, error) {
	values := make([]string, count)
	seen := make(map[string]struct{}, count)
	for index := range values {
		value, err := processor.config.NewProductID()
		if err != nil {
			return nil, errWorkerExecution
		}
		if _, err := domain.ParseProductID(value); err != nil {
			return nil, errWorkerExecution
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errWorkerExecution
		}
		seen[value] = struct{}{}
		values[index] = value
	}
	return values, nil
}

func (processor *securityAgentActionProcessor) Close() error {
	if processor == nil {
		return nil
	}
	processor.mu.Lock()
	defer processor.mu.Unlock()
	if processor.closed {
		return nil
	}
	processor.closed = true
	for index := range processor.config.PrivateKey {
		processor.config.PrivateKey[index] = 0
	}
	processor.config.PrivateKey = nil
	return nil
}
