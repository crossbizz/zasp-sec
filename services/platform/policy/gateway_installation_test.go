package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const installationCredential = "pid_90000005-0000-4000-8000-000000000005"

func installationCacheFixture(t *testing.T) (*GatewayPolicyCache, string, GatewayPolicyKeys, GatewayPolicyEnvelope, *time.Time) {
	t.Helper()
	now := gatewayFixtureTime()
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys, err := NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(gatewayRealTempDir(t), "policy.json")
	cache, err := NewGatewayPolicyInstallationDiskCache(path, keys, gatewayFixtureBinding(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	envelope := gatewayFixtureEnvelope(t, private, now, gatewayFixtureBinding(), 1, 1, "closed")
	return cache, path, keys, envelope, &now
}
func TestGatewayInstallationCacheDurableOriginalObservationAndRestart(t *testing.T) {
	cache, path, keys, envelope, now := installationCacheFixture(t)
	original := *now
	if err := cache.StoreInstallation(envelope, installationCredential, 7); err != nil {
		t.Fatal(err)
	}
	raw, err := cache.PendingInstallation(installationCredential, 7)
	if err != nil || len(raw) == 0 {
		t.Fatal("missing durable observation", err)
	}
	var value struct {
		InstalledObservedAt  time.Time `json:"installed_observed_at"`
		CredentialGeneration uint64    `json:"credential_generation"`
		Sequence             uint64    `json:"sequence"`
	}
	if json.Unmarshal(raw, &value) != nil || !value.InstalledObservedAt.Equal(original) || value.CredentialGeneration != 7 || value.Sequence != 1 {
		t.Fatal("original identity/time not retained")
	}
	*now = now.Add(time.Minute)
	if _, _, err := cache.Current(); err != nil {
		t.Fatal(err)
	}
	if cache.StoreInstallation(envelope, installationCredential, 7) != nil {
		t.Fatal("same source replay failed")
	}
	again, _ := cache.PendingInstallation(installationCredential, 7)
	if !bytes.Equal(raw, again) {
		t.Fatal("replay restamped")
	}
	if cache.Close() != nil {
		t.Fatal("close")
	}
	restored, err := NewGatewayPolicyInstallationDiskCache(path, keys, gatewayFixtureBinding(), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	again, err = restored.PendingInstallation(installationCredential, 7)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("restart changed original body", err)
	}
}
func TestGatewayInstallationCacheCompareClearAndSupersession(t *testing.T) {
	cache, _, _, first, now := installationCacheFixture(t)
	if cache.StoreInstallation(first, installationCredential, 7) != nil {
		t.Fatal("first store")
	}
	old, _ := cache.PendingInstallation(installationCredential, 7)
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	next := gatewayFixtureEnvelope(t, private, *now, gatewayFixtureBinding(), 2, 2, "closed")
	if cache.StoreInstallation(next, installationCredential, 7) != nil {
		t.Fatal("new source blocked by pending ACK")
	}
	current, _ := cache.PendingInstallation(installationCredential, 7)
	if bytes.Equal(old, current) {
		t.Fatal("new source retained old witness")
	}
	if cache.ConfirmInstallation(old) == nil {
		t.Fatal("old response cleared newer pending")
	}
	again, _ := cache.PendingInstallation(installationCredential, 7)
	if !bytes.Equal(current, again) {
		t.Fatal("pending changed")
	}
	if cache.ConfirmInstallation(current) != nil {
		t.Fatal("exact receipt not persisted")
	}
	again, err := cache.PendingInstallation(installationCredential, 7)
	if err != nil || len(again) != 0 {
		t.Fatal("confirmed observation remains pending", err)
	}
}
func TestGatewayInstallationCacheLegacyMemoryAndRotationNeverFabricate(t *testing.T) {
	cache, path, keys, envelope, now := installationCacheFixture(t)
	cache.Close()
	legacy, err := NewGatewayPolicyDiskCache(path, keys, gatewayFixtureBinding(), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Store(envelope) != nil {
		t.Fatal("legacy store")
	}
	legacy.Close()
	selected, err := NewGatewayPolicyInstallationDiskCache(path, keys, gatewayFixtureBinding(), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	raw, err := selected.PendingInstallation(installationCredential, 7)
	if err != nil || len(raw) != 0 {
		t.Fatal("legacy load fabricated observation", err)
	}
	if selected.StoreInstallation(envelope, installationCredential, 7) != nil {
		t.Fatal("same legacy source must remain usable")
	}
	raw, _ = selected.PendingInstallation(installationCredential, 7)
	if len(raw) != 0 {
		t.Fatal("same legacy source backfilled installation")
	}
	memory, _ := NewGatewayPolicyCache(keys, gatewayFixtureBinding(), func() time.Time { return *now })
	defer memory.Close()
	if memory.StoreInstallation(envelope, installationCredential, 7) == nil {
		t.Fatal("memory ACK admitted")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	next := gatewayFixtureEnvelope(t, private, *now, gatewayFixtureBinding(), 2, 2, "closed")
	if selected.StoreInstallation(next, installationCredential, 7) != nil {
		t.Fatal("new source")
	}
	raw, err = selected.PendingInstallation(installationCredential, 8)
	if err != nil || len(raw) != 0 {
		t.Fatal("rotation relabeled witness", err)
	}
}
func TestGatewayInstallationCacheFailedWriteCannotEmitPending(t *testing.T) {
	cache, path, _, envelope, _ := installationCacheFixture(t)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if cache.StoreInstallation(envelope, installationCredential, 7) == nil {
		t.Fatal("failed durable write accepted")
	}
	raw, _ := cache.PendingInstallation(installationCredential, 7)
	if len(raw) != 0 {
		t.Fatal("failed write emitted ACK")
	}
	if _, _, err := cache.Current(); err == nil {
		t.Fatal("failed store installed in memory")
	}
}
func TestGatewayInstallationCacheLegacyWritesPreserveCurrentWitness(t *testing.T) {
	cache, _, _, envelope, now := installationCacheFixture(t)
	if cache.StoreInstallation(envelope, installationCredential, 7) != nil {
		t.Fatal("store")
	}
	raw, _ := cache.PendingInstallation(installationCredential, 7)
	*now = now.Add(time.Minute)
	if cache.Store(envelope) != nil {
		t.Fatal("legacy same-source refresh")
	}
	again, _ := cache.PendingInstallation(installationCredential, 7)
	if !bytes.Equal(raw, again) {
		t.Fatal("legacy same-source write silently erased witness")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	next := gatewayFixtureEnvelope(t, private, *now, gatewayFixtureBinding(), 2, 2, "closed")
	if cache.Store(next) != nil {
		t.Fatal("legacy new source")
	}
	again, err := cache.PendingInstallation(installationCredential, 7)
	if err != nil || len(again) != 0 {
		t.Fatal("legacy new source emitted incompatible witness", err)
	}
}
func TestGatewayInstallationCacheRejectsCorruptWitnessWithoutCredentialRelabel(t *testing.T) {
	cache, path, keys, envelope, now := installationCacheFixture(t)
	if cache.StoreInstallation(envelope, installationCredential, 7) != nil {
		t.Fatal("store")
	}
	for _, generation := range []uint64{0, 1 << 63} {
		if cache.StoreInstallation(envelope, installationCredential, generation) == nil {
			t.Fatal("invalid generation accepted on same source")
		}
	}
	cache.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), raw...)
	raw = bytes.Replace(raw, []byte(`"credential_generation":7`), []byte(`"credential_generation":0`), 1)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write corruption")
	}
	bad, err := NewGatewayPolicyInstallationDiskCache(path, keys, gatewayFixtureBinding(), func() time.Time { return *now })
	if err == nil || bad != nil {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("corrupted witness accepted")
	}
	var state map[string]json.RawMessage
	if json.Unmarshal(original, &state) != nil {
		t.Fatal("state fixture")
	}
	state["observed_at"], _ = json.Marshal(now.Add(-time.Second))
	corrupted, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the canonical disk field order so this specifically reaches the
	// witness/floor invariant instead of merely rejecting key order.
	var typed gatewayPolicyDiskState
	if json.Unmarshal(corrupted, &typed) != nil {
		t.Fatal("typed state fixture")
	}
	corrupted, err = marshalGatewayPolicyState(typed.Envelope, typed.ObservedAt, typed.Version, typed.Installation)
	if err != nil || os.WriteFile(path, corrupted, 0600) != nil {
		t.Fatal("floor corruption fixture", err)
	}
	bad, err = NewGatewayPolicyInstallationDiskCache(path, keys, gatewayFixtureBinding(), func() time.Time { return *now })
	if err == nil || bad != nil {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("witness beyond persisted floor accepted")
	}
}

func TestGatewayInstallationCacheSelectedFileIsOneGeneration(t *testing.T) {
	cache, path, _, envelope, _ := installationCacheFixture(t)
	if cache.StoreInstallation(envelope, installationCredential, 7) != nil {
		t.Fatal("store")
	}
	raw, _ := cache.PendingInstallation(installationCredential, 7)
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(disk, []byte(`"envelope"`)) || !bytes.Contains(disk, []byte(`"installation"`)) || !bytes.Contains(disk, []byte(wire.ObservationSchema)) {
		t.Fatal("envelope and original observation not same durable generation")
	}
	if len(raw) == 0 {
		t.Fatal("no emitted body")
	}
}
