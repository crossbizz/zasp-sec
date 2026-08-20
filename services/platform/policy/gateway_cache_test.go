package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatewayPolicyEnvelopeBindsKeyAudienceScopeDeviceAndPayload(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	envelope := gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")
	keys, err := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyGatewayPolicyEnvelope(envelope, keys, binding, now)
	if err != nil || verified.Sequence != 1 || verified.PayloadDigest == "" {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}

	mutations := []func(*GatewayPolicyEnvelope){
		func(value *GatewayPolicyEnvelope) { value.KeyID = "gateway-key-2" },
		func(value *GatewayPolicyEnvelope) { value.Algorithm = "HS256" },
		func(value *GatewayPolicyEnvelope) { value.Audience = "runtime-gateway" },
		func(value *GatewayPolicyEnvelope) { value.OrganizationID = "pid_90000009-0000-4000-8000-000000000009" },
		func(value *GatewayPolicyEnvelope) { value.DeviceID = "pid_90000008-0000-4000-8000-000000000008" },
		func(value *GatewayPolicyEnvelope) { value.PayloadDigest = strings.Repeat("0", 64) },
		func(value *GatewayPolicyEnvelope) {
			value.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		func(value *GatewayPolicyEnvelope) { value.IssuedAt = now.Add(2 * time.Minute) },
		func(value *GatewayPolicyEnvelope) { value.ExpiresAt = now },
		func(value *GatewayPolicyEnvelope) { value.Policies = append(value.Policies, value.Policies[0]) },
	}
	for index, mutate := range mutations {
		candidate := cloneGatewayPolicyEnvelope(envelope)
		mutate(&candidate)
		if _, err := VerifyGatewayPolicyEnvelope(candidate, keys, binding, now); err == nil {
			t.Fatalf("mutation %d passed: %+v", index, candidate)
		}
	}
}

func TestGatewayPolicyCacheRejectsRollbackAndAcceptsExactReplay(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, err := NewGatewayPolicyCache(keys, binding, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first := gatewayFixtureEnvelope(t, private, now, binding, 5, 9, "closed")
	if err := cache.Store(first); err != nil || cache.Store(first) != nil {
		t.Fatalf("first/replay err=%v", err)
	}

	rollback := gatewayFixtureEnvelope(t, private, now, binding, 4, 9, "closed")
	if err := cache.Store(rollback); err == nil {
		t.Fatal("sequence rollback accepted")
	}
	versionRollback := gatewayFixtureEnvelope(t, private, now, binding, 6, 8, "closed")
	if err := cache.Store(versionRollback); err == nil {
		t.Fatal("policy version rollback accepted")
	}
	drift := cloneGatewayPolicyEnvelope(first)
	drift.FailureMode = "open"
	if err := resignGatewayFixture(&drift, private); err != nil {
		t.Fatal(err)
	}
	if err := cache.Store(drift); err == nil {
		t.Fatal("same-sequence drift accepted")
	}

	next := gatewayFixtureEnvelope(t, private, now, binding, 6, 10, "open")
	if err := cache.Store(next); err != nil {
		t.Fatal(err)
	}
	current, state, err := cache.Current()
	if err != nil || state != GatewayPolicyValid || current.Sequence != 6 {
		t.Fatalf("current=%+v state=%q err=%v", current, state, err)
	}
	cache.now = func() time.Time { return next.ExpiresAt.Add(time.Second) }
	_, state, err = cache.Current()
	if err != nil || state != GatewayPolicyExpiredOpen {
		t.Fatalf("expired state=%q err=%v", state, err)
	}
}

func TestGatewayPolicyDiskCacheWrites0600AndReverifiesOnRestore(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	path := filepath.Join(gatewayRealTempDir(t), "gateway-policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	envelope := gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")
	if err := cache.Store(envelope); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	restored, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	current, state, err := restored.Current()
	if err != nil || state != GatewayPolicyValid || current.Sequence != 1 {
		t.Fatalf("restored=%+v state=%q err=%v", current, state, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := cache.Store(envelope); err != nil {
		t.Fatalf("exact replay did not repair disk cache: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("repaired cache missing: %v", err)
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bytes[len(bytes)/2] ^= 1
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now }); err == nil {
		t.Fatal("tampered disk cache restored")
	}
}

func TestGatewayPolicyCacheRejectsNoncanonicalDiskAndClockPanic(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	if _, err := NewGatewayPolicyCache(keys, binding, func() time.Time { panic("clock unavailable") }); err == nil {
		t.Fatal("panicking clock accepted")
	}

	path := filepath.Join(gatewayRealTempDir(t), "gateway-policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	envelope := gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")
	if err := cache.Store(envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	noncanonical := append([]byte(" "), raw...)
	if err := os.WriteFile(path, noncanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now }); err == nil {
		t.Fatal("noncanonical disk envelope accepted")
	}
}

func TestGatewayPolicyEnvelopeClonesKeysPoliciesAndConditions(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := NewGatewayPolicyCache(keys, binding, func() time.Time { return now })
	envelope := gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")
	if err := cache.Store(envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Policies[0].Conditions[0].Value = "mutated"
	public[0] ^= 1
	current, _, err := cache.Current()
	if err != nil || current.Policies[0].Conditions[0].Value != "shell" {
		t.Fatalf("current=%+v err=%v", current, err)
	}
	current.Policies[0].Conditions[0].Value = "mutated-again"
	replay, _, _ := cache.Current()
	if replay.Policies[0].Conditions[0].Value != "shell" {
		t.Fatal("cache returned mutable state")
	}
}

func TestGatewayPolicyCacheNeverReactivatesExpiredPolicyAfterClockRollbackOrRestart(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	clock := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	path := filepath.Join(gatewayRealTempDir(t), "gateway-policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	envelope := gatewayFixtureEnvelope(t, private, clock, binding, 1, 1, "closed")
	if err := cache.Store(envelope); err != nil {
		t.Fatal(err)
	}
	clock = envelope.ExpiresAt.Add(time.Second)
	if _, state, err := cache.Current(); err != nil || state != GatewayPolicyExpiredClosed {
		t.Fatalf("first expiry state=%q err=%v", state, err)
	}
	clock = gatewayFixtureTime()
	if _, state, err := cache.Current(); err != nil || state != GatewayPolicyExpiredClosed {
		t.Fatalf("rollback reactivated policy: state=%q err=%v", state, err)
	}
	restored, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, state, err := restored.Current(); err != nil || state != GatewayPolicyExpiredClosed {
		t.Fatalf("restart rollback reactivated policy: state=%q err=%v", state, err)
	}
}

func TestGatewayPolicyDiskCacheRetainsStartupClockFloorBeforeFirstCurrent(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	clock := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	path := filepath.Join(gatewayRealTempDir(t), "gateway-policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	envelope := gatewayFixtureEnvelope(t, private, clock, binding, 1, 1, "closed")
	if err := cache.Store(envelope); err != nil {
		t.Fatal(err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	clock = envelope.ExpiresAt.Add(time.Second)
	restored, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	clock = gatewayFixtureTime()
	if _, state, err := restored.Current(); err != nil || state != GatewayPolicyExpiredClosed {
		t.Fatalf("startup floor rollback state=%q err=%v", state, err)
	}
}

func TestGatewayPolicyDiskCacheCannotDiscardFirstStartupClockSample(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	base := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	path := filepath.Join(gatewayRealTempDir(t), "gateway-policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	envelope := gatewayFixtureEnvelope(t, private, base, binding, 1, 1, "closed")
	if err := cache.Store(envelope); err != nil {
		t.Fatal(err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	samples := []time.Time{envelope.ExpiresAt.Add(time.Second), base, base}
	call := 0
	restored, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time {
		value := samples[call]
		call++
		return value
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, state, err := restored.Current(); err != nil || state != GatewayPolicyExpiredClosed {
		t.Fatalf("discarded first startup sample: state=%q calls=%d err=%v", state, call, err)
	}
}

func TestGatewayPolicyCacheBindsFailureModeToPolicyVersion(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := NewGatewayPolicyCache(keys, binding, func() time.Time { return now })
	first := gatewayFixtureEnvelope(t, private, now, binding, 5, 9, "closed")
	if err := cache.Store(first); err != nil {
		t.Fatal(err)
	}
	drift := gatewayFixtureEnvelope(t, private, now, binding, 6, 9, "open")
	if err := cache.Store(drift); err == nil {
		t.Fatal("same policy version changed failure mode")
	}
}

func TestGatewayPolicyDiskCacheRejectsSymlinkedParentAndLeafReplacement(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	root := gatewayRealTempDir(t)
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGatewayPolicyDiskCache(filepath.Join(symlinkDirectory, "policy.json"), keys, binding, func() time.Time { return now }); err == nil {
		t.Fatal("symlinked parent accepted")
	}

	path := filepath.Join(realDirectory, "policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := cache.Store(gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")); err == nil {
		t.Fatal("symlink leaf replacement accepted")
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "unchanged" {
		t.Fatalf("symlink target changed: %q err=%v", raw, err)
	}
}

func TestGatewayPolicyDiskCachePinsVerifiedParentAcrossRealDirectorySwap(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	root := gatewayRealTempDir(t)
	original := filepath.Join(root, "cache")
	moved := filepath.Join(root, "cache-original")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(original, "policy.json")
	cache, err := NewGatewayPolicyDiskCache(path, keys, binding, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cache.Store(gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "policy.json")); err != nil {
		t.Fatalf("pinned directory did not receive cache: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("replacement directory received cache: %v", err)
	}
}

func TestGatewayPolicyEnvelopeRejectsOversizedOrNoncanonicalSignatureBeforeVerification(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayFixtureTime()
	binding := gatewayFixtureBinding()
	keys, _ := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	envelope := gatewayFixtureEnvelope(t, private, now, binding, 1, 1, "closed")
	for _, signature := range []string{strings.Repeat("A", maximumGatewayPolicyBytes), envelope.Signature + "="} {
		candidate := cloneGatewayPolicyEnvelope(envelope)
		candidate.Signature = signature
		if _, err := VerifyGatewayPolicyEnvelope(candidate, keys, binding, now); err == nil {
			t.Fatalf("signature accepted: length=%d", len(signature))
		}
	}
}

func gatewayFixtureEnvelope(t *testing.T, private ed25519.PrivateKey, now time.Time, binding GatewayPolicyBinding, sequence, policyVersion uint64, failureMode string) GatewayPolicyEnvelope {
	t.Helper()
	compiled, err := Compile(Policy{ID: "policy-1", Trigger: "tool_call", Action: ActionBlock, Conditions: []Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}})
	if err != nil {
		t.Fatal(err)
	}
	envelope := GatewayPolicyEnvelope{
		ContractVersion: 1,
		KeyID:           "gateway-key-1",
		Algorithm:       "Ed25519",
		Audience:        "runtime-gateway-policy",
		OrganizationID:  binding.OrganizationID,
		WorkspaceID:     binding.WorkspaceID,
		EnvironmentID:   binding.EnvironmentID,
		DeviceID:        binding.DeviceID,
		Sequence:        sequence,
		PolicyVersion:   policyVersion,
		IssuedAt:        now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
		FailureMode:     failureMode,
		Policies:        []CompiledPolicy{compiled},
	}
	if err := resignGatewayFixture(&envelope, private); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func resignGatewayFixture(envelope *GatewayPolicyEnvelope, private ed25519.PrivateKey) error {
	digest, payload, err := canonicalGatewayPolicyPayload(*envelope)
	if err != nil {
		return err
	}
	envelope.PayloadDigest = digest
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))
	return nil
}

func gatewayFixtureBinding() GatewayPolicyBinding {
	return GatewayPolicyBinding{
		OrganizationID: "pid_90000001-0000-4000-8000-000000000001",
		WorkspaceID:    "pid_90000002-0000-4000-8000-000000000002",
		EnvironmentID:  "pid_90000003-0000-4000-8000-000000000003",
		DeviceID:       "pid_90000004-0000-4000-8000-000000000004",
	}
}

func gatewayFixtureTime() time.Time {
	return time.Date(2026, 8, 19, 21, 0, 0, 0, time.UTC)
}

func gatewayRealTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
