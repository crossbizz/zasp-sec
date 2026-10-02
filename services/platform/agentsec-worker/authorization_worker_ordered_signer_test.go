package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Startup/readiness must depend only on independent public material. The
// private file may be unavailable until an authorized signing callback runs.
func TestOrderedSignerPublicReadinessAndLazyPrivateKey(t *testing.T) {
	dir := t.TempDir()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	publicBody := []byte(`{"keys":[{"key_id":"gateway-key-1","public_key":"` + base64.RawURLEncoding.EncodeToString(public) + `"}]}`)
	cfg := workerRuntimeConfig{GatewaySigningKeyID: "gateway-key-1", GatewayPolicyKeysFile: filepath.Join(dir, "public.json"), GatewaySigningPrivateFile: filepath.Join(dir, "absent-private")}
	if err := os.WriteFile(cfg.GatewayPolicyKeysFile, publicBody, 0o400); err != nil {
		t.Fatal(err)
	}
	signer, err := newWorkerOrderedPolicySigning(cfg)
	if err != nil || signer.ready() != nil || signer.keyID != cfg.GatewaySigningKeyID || !signer.keys.Contains(cfg.GatewaySigningKeyID, public) {
		t.Fatal("public-only startup/readiness required private material")
	}
	now := time.Now().UTC().Truncate(time.Second)
	input := policy.GatewayPolicySigningInput{KeyID: cfg.GatewaySigningKeyID,
		Binding:  policy.GatewayPolicyBinding{OrganizationID: "pid_00000001-0000-4000-8000-000000000001", WorkspaceID: "pid_00000001-0000-4000-8000-000000000002", EnvironmentID: "pid_00000001-0000-4000-8000-000000000003", DeviceID: "pid_00000001-0000-4000-8000-000000000004"},
		Sequence: 1, PolicyVersion: 1, Now: now, IssuedAt: now, ExpiresAt: now.Add(time.Minute), FailureMode: "closed", Policies: []policy.CompiledPolicy{}}
	if policy.ValidateGatewayPolicySigningInput(input) != nil {
		t.Fatal("invalid test signing input")
	}
	if _, err := signer.sign(context.Background(), input); err == nil {
		t.Fatal("missing private key was accepted")
	}
	if err := os.WriteFile(cfg.GatewaySigningPrivateFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o400); err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.sign(context.Background(), input)
	if err != nil {
		t.Fatal("authorized callback could not load matching key")
	}
	if _, err := policy.VerifyGatewayPolicyEnvelope(envelope, signer.keys, input.Binding, now); err != nil {
		t.Fatal("callback did not produce independently verifiable envelope")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if _, err := signer.sign(ctx, input); err == nil {
			t.Fatal("signing accepted absent or cancelled context")
		}
	}
	wrongKey := input
	wrongKey.KeyID = "unknown-key"
	invalidSequence := input
	invalidSequence.Sequence = 0
	for _, bad := range []policy.GatewayPolicySigningInput{wrongKey, invalidSequence} {
		if _, err := signer.sign(context.Background(), bad); err == nil {
			t.Fatal("signing accepted unbound or invalid input")
		}
	}
	for _, mutate := range []func(*workerRuntimeConfig){
		func(c *workerRuntimeConfig) { c.GatewaySigningKeyID = "unknown-key" },
		func(c *workerRuntimeConfig) { c.GatewayPolicyKeysFile = filepath.Join(dir, "missing-public") },
		func(c *workerRuntimeConfig) { c.GatewaySigningPrivateFile = "relative-private" },
		func(c *workerRuntimeConfig) { c.GatewaySigningPrivateFile = c.GatewayPolicyKeysFile },
	} {
		bad := cfg
		mutate(&bad)
		if _, err := newWorkerOrderedPolicySigning(bad); err == nil {
			t.Fatal("constructor accepted invalid independent verifier configuration")
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	// Replace only the private file: the public trust set must not be derived
	// from whatever private key happens to be mounted now.
	if err := os.Chmod(cfg.GatewaySigningPrivateFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.GatewaySigningPrivateFile, []byte(base64.RawURLEncoding.EncodeToString(other)), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.GatewaySigningPrivateFile, 0o400); err != nil {
		t.Fatal(err)
	}
	if signer.ready() != nil {
		t.Fatal("public readiness read changed private key")
	}
	if _, err := signer.sign(context.Background(), input); err == nil {
		t.Fatal("private key replaced public trust")
	}
	if err := os.Chmod(cfg.GatewayPolicyKeysFile, 0o600); err != nil {
		t.Fatal(err)
	}
	changedPublic := bytes.ReplaceAll(publicBody, []byte(base64.RawURLEncoding.EncodeToString(public)), []byte(base64.RawURLEncoding.EncodeToString(other.Public().(ed25519.PublicKey))))
	if err := os.WriteFile(cfg.GatewayPolicyKeysFile, changedPublic, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.GatewayPolicyKeysFile, 0o400); err != nil {
		t.Fatal(err)
	}
	if signer.ready() == nil {
		t.Fatal("changed verifier identity accepted without restart")
	}
	if _, err := signer.sign(context.Background(), input); err == nil {
		t.Fatal("changed verifier accepted by callback")
	}
}
