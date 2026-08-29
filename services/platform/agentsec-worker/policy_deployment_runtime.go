package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

type policyDeploymentClaim = apiserver.PolicyDeploymentClaim

type policyDeploymentAuthority interface {
	Ready(context.Context) error
	ClaimPolicyDeployments(context.Context, string, string, int, int) ([]policyDeploymentClaim, error)
	HeartbeatPolicyDeployment(context.Context, policyDeploymentClaim, string, string, int) error
	StorePolicyDeployment(context.Context, policyDeploymentClaim, string, string, policy.GatewayPolicyEnvelope) (string, error)
	ReadPolicyDeployment(context.Context, policyDeploymentClaim) (policy.GatewayPolicyEnvelope, error)
	FinishPolicyDeployment(context.Context, policyDeploymentClaim, string, string, string) error
}

type policyDeploymentProcessorConfig struct {
	Authority         policyDeploymentAuthority
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	KeyID             string
	PrivateKey        ed25519.PrivateKey
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
}

type policyDeploymentProcessor struct {
	config policyDeploymentProcessorConfig
	mu     sync.RWMutex
	closed bool
}

func newPolicyDeploymentProcessor(config policyDeploymentProcessorConfig) (*policyDeploymentProcessor, error) {
	leaseDuration := time.Duration(config.LeaseSeconds) * time.Second
	if config.Authority == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 30 || config.LeaseSeconds > 300 || config.BatchSize < 1 || config.BatchSize > 25 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > leaseDuration/2 || config.Now == nil || config.NewLeaseToken == nil || len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errWorkerConfiguration
	}
	now := config.Now()
	publicKey, keyOK := config.PrivateKey.Public().(ed25519.PublicKey)
	if !keyOK || now.IsZero() || now.Location() != time.UTC {
		return nil, errWorkerConfiguration
	}
	if _, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{config.KeyID: publicKey}); err != nil {
		return nil, errWorkerConfiguration
	}
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &policyDeploymentProcessor{config: config}, nil
}

func (processor *policyDeploymentProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	processor.mu.RLock()
	defer processor.mu.RUnlock()
	if processor.closed {
		return errWorkerExecution
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || len(leaseToken) < 16 || len(leaseToken) > 128 {
		return errWorkerExecution
	}
	claims, err := processor.config.Authority.ClaimPolicyDeployments(ctx, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(claims) > processor.config.BatchSize {
		return errWorkerExecution
	}
	for _, claim := range claims {
		if ctx.Err() != nil {
			return nil
		}
		if processor.process(ctx, claim, leaseToken) != nil {
			return errWorkerExecution
		}
	}
	return nil
}

func (processor *policyDeploymentProcessor) process(ctx context.Context, claim policyDeploymentClaim, leaseToken string) error {
	if !validPolicyDeploymentClaim(claim) {
		return errWorkerExecution
	}
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
				if err := processor.config.Authority.HeartbeatPolicyDeployment(workCtx, claim, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds); err != nil {
					heartbeatDone <- err
					cancel()
					return
				}
			}
		}
	}()
	operationErr := processor.apply(workCtx, claim, leaseToken)
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

func (processor *policyDeploymentProcessor) apply(ctx context.Context, claim policyDeploymentClaim, leaseToken string) error {
	now := processor.config.Now().UTC().Truncate(time.Second)
	compiled, failureMode, err := effectiveGatewayPolicies(claim)
	if err != nil {
		return errWorkerExecution
	}
	expiresAt := now.Add(24 * time.Hour)
	if claim.TemporaryExpiresAt != nil && claim.TemporaryExpiresAt.Before(expiresAt) {
		expiresAt = *claim.TemporaryExpiresAt
	}
	if !expiresAt.After(now) {
		return errWorkerExecution
	}
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{
		KeyID:    processor.config.KeyID,
		Binding:  policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID},
		Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expiresAt, FailureMode: failureMode, Policies: compiled,
	}, processor.config.PrivateKey)
	if err != nil {
		return errWorkerExecution
	}
	digest, err := processor.config.Authority.StorePolicyDeployment(ctx, claim, processor.config.WorkerID, leaseToken, envelope)
	if err != nil {
		readback, readErr := processor.config.Authority.ReadPolicyDeployment(ctx, claim)
		if readErr != nil || !samePolicyDeploymentEnvelope(envelope, readback) {
			return errWorkerExecution
		}
		digest, err = policyDeploymentEnvelopeDigest(readback)
		if err != nil {
			return errWorkerExecution
		}
	}
	readback, err := processor.config.Authority.ReadPolicyDeployment(ctx, claim)
	if err != nil || !samePolicyDeploymentEnvelope(envelope, readback) {
		return errWorkerExecution
	}
	wantDigest, err := policyDeploymentEnvelopeDigest(readback)
	if err != nil || digest != wantDigest {
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
	if _, err := policy.VerifyGatewayPolicyEnvelope(readback, keys, policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, now); err != nil {
		return errWorkerExecution
	}
	if err := processor.config.Authority.FinishPolicyDeployment(ctx, claim, processor.config.WorkerID, leaseToken, digest); err != nil {
		return errWorkerExecution
	}
	return nil
}

func effectiveGatewayPolicies(claim policyDeploymentClaim) ([]policy.CompiledPolicy, string, error) {
	if !validPolicyDeploymentClaim(claim) {
		return nil, "", errWorkerExecution
	}
	values := make([]policy.CompiledPolicy, 0, len(claim.PersistentPolicies)+len(claim.TemporaryPolicies))
	seen := make(map[string]struct{}, cap(values))
	failureMode := "open"
	for _, value := range claim.PersistentPolicies {
		compiled, active, err := policy.CompileGatewayPolicy(value)
		if err != nil {
			return nil, "", errWorkerExecution
		}
		if !active {
			continue
		}
		if _, duplicate := seen[compiled.ID]; duplicate {
			return nil, "", errWorkerExecution
		}
		seen[compiled.ID] = struct{}{}
		values = append(values, compiled)
		if value.FailureMode == "closed" {
			failureMode = "closed"
		}
	}
	for _, compiled := range claim.TemporaryPolicies {
		if _, duplicate := seen[compiled.ID]; duplicate {
			return nil, "", errWorkerExecution
		}
		seen[compiled.ID] = struct{}{}
		values = append(values, compiled)
		failureMode = "closed"
	}
	if len(values) > 100 {
		return nil, "", errWorkerExecution
	}
	sort.Slice(values, func(left, right int) bool { return values[left].ID < values[right].ID })
	return values, failureMode, nil
}

func validPolicyDeploymentClaim(claim policyDeploymentClaim) bool {
	for _, value := range []string{claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.DeviceID, claim.CredentialID} {
		if _, err := domain.ParseProductID(value); err != nil {
			return false
		}
	}
	if claim.DesiredGeneration < 1 || claim.Sequence < 1 || claim.PolicyVersion < 1 || claim.Sequence != claim.PolicyVersion || claim.LeaseExpiresAt.IsZero() || claim.LeaseExpiresAt.Location() != time.UTC || len(claim.PersistentPolicies) > 100 || len(claim.TemporaryPolicies) > 100 || len(claim.PersistentPolicies)+len(claim.TemporaryPolicies) > 100 {
		return false
	}
	if len(claim.TemporaryPolicies) == 0 {
		return claim.TemporaryExpiresAt == nil
	}
	if claim.TemporaryExpiresAt == nil || claim.TemporaryExpiresAt.IsZero() || claim.TemporaryExpiresAt.Location() != time.UTC {
		return false
	}
	_, err := decodeActionDigest(claim.InputDigest)
	return err == nil
}

func samePolicyDeploymentEnvelope(left, right policy.GatewayPolicyEnvelope) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func policyDeploymentEnvelopeDigest(envelope policy.GatewayPolicyEnvelope) (string, error) {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", errWorkerExecution
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (processor *policyDeploymentProcessor) Close() error {
	if processor == nil {
		return nil
	}
	processor.mu.Lock()
	defer processor.mu.Unlock()
	if processor.closed {
		return nil
	}
	processor.closed = true
	clear(processor.config.PrivateKey)
	processor.config.PrivateKey = nil
	processor.config.Authority = nil
	processor.config.NewLeaseToken = nil
	processor.config.Now = nil
	return nil
}

func composePolicyDeploymentWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, privateKey ed25519.PrivateKey) (workerRuntimeDependencies, error) {
	defer clear(privateKey)
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModePolicyDeployment || database == nil || len(privateKey) != ed25519.PrivateKeySize {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewPolicyDeploymentRepository(database)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	ready, err := newBoundedCachedWorkerReadiness(repository.Ready, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newPolicyDeploymentProcessor(policyDeploymentProcessorConfig{
		Authority: repository, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3,
		KeyID: config.GatewaySigningKeyID, PrivateKey: privateKey, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: processor.Close}, nil
}
