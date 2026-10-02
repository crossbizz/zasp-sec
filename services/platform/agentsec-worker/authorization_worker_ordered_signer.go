package main

import (
	"context"
	"crypto/ed25519"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"path/filepath"
)

type workerOrderedPolicySigning struct {
	keyID string
	keys  policy.GatewayPolicyKeys
	sign  authorization.OrderedPolicySigner
	ready func() error
}

func newWorkerOrderedPolicySigning(cfg workerRuntimeConfig) (workerOrderedPolicySigning, error) {
	invalid := workerOrderedPolicySigning{}
	if !filepath.IsAbs(cfg.GatewaySigningPrivateFile) || filepath.Clean(cfg.GatewaySigningPrivateFile) != cfg.GatewaySigningPrivateFile || cfg.GatewaySigningPrivateFile == cfg.GatewayPolicyKeysFile {
		return invalid, errRuntimeUnavailable
	}
	verifier, err := loadWorkerGatewayPolicyVerifier(cfg.GatewayPolicyKeysFile)
	if err != nil || !verifier.keys.HasKeyID(cfg.GatewaySigningKeyID) {
		return invalid, errRuntimeUnavailable
	}
	// Public trust is independent of the mounted private key and pinned for this
	// process. A verifier change requires restart, never an implicit trust swap.
	ready := func() error {
		current, err := loadWorkerGatewayPolicyVerifier(cfg.GatewayPolicyKeysFile)
		if err != nil || current.digest != verifier.digest {
			return errRuntimeUnavailable
		}
		return nil
	}
	sign := func(ctx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
		invalid := policy.GatewayPolicyEnvelope{}
		if ctx == nil || ctx.Err() != nil || input.KeyID != cfg.GatewaySigningKeyID || policy.ValidateGatewayPolicySigningInput(input) != nil || ready() != nil {
			return invalid, errRuntimeUnavailable
		}
		// Only SignOrderedPolicy's authorized, locked transaction may invoke
		// this callback. Construction and readiness never load private material.
		key, err := loadSecurityAgentActionPrivateKey(cfg.GatewaySigningPrivateFile)
		if err != nil {
			return invalid, errRuntimeUnavailable
		}
		defer clear(key)
		public, ok := key.Public().(ed25519.PublicKey)
		if !ok || !verifier.keys.Contains(input.KeyID, public) || ctx.Err() != nil || ready() != nil {
			return invalid, errRuntimeUnavailable
		}
		return policy.SignGatewayPolicyEnvelope(input, key)
	}
	return workerOrderedPolicySigning{keyID: cfg.GatewaySigningKeyID, keys: verifier.keys, sign: sign, ready: ready}, nil
}
