package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestGatewayEvidencePinnedDirectorySupportsDatabaseOpen(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent, root, pinned, _, path, err := openGatewayEvidenceDirectory(filepath.Join(directory, "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	database, err := badger.Open(badger.LSMOnlyOptions(path).WithLogger(nil).WithExternalMagic(gatewayEvidenceStoreMagic))
	if err != nil {
		t.Fatalf("open pinned database: %v", err)
	}
	if database.Close() != nil || pinned.Close() != nil || root.Close() != nil || parent.Close() != nil {
		t.Fatal("close pinned database")
	}
}

func TestGatewayEvidenceDiskStoreRestoresPendingDecisionsExactly(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expected := gatewayRuntimeAuthority()
	path := filepath.Join(directory, "evidence")
	store, err := newGatewayEvidenceDiskStore(path, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if store.database.Opts().CompactL0OnClose {
		t.Fatal("production evidence close must not run an unbounded L0 compaction")
	}
	event := gatewayDecisionEvent{
		CredentialID: expected.CredentialID, DeviceID: expected.DeviceID, EventID: gatewayRuntimeID(9),
		ExpectedFloor: 4, NextFloor: 5, PolicyVersion: 3, Decision: "block", ActionKind: "mcp",
		Classification: gatewayRuntimeClassification("blocked"), OccurredAt: gatewayRuntimeTime(),
	}
	quarantinedEvent := gatewayDecisionEvent{
		CredentialID: expected.CredentialID, DeviceID: expected.DeviceID, EventID: gatewayRuntimeID(8),
		ExpectedFloor: 3, NextFloor: 4, PolicyVersion: 2, Decision: "monitor", ActionKind: "http",
		Classification: gatewayRuntimeClassification("monitored"), OccurredAt: gatewayRuntimeTime().Add(-25 * time.Hour),
	}
	quarantined := gatewayQuarantinedDecisionEvent{Event: quarantinedEvent, Reason: gatewayEvidenceExpiredReason, QuarantinedAt: gatewayRuntimeTime()}
	pendingDigest := sha256.Sum256([]byte(`{"event_id":"` + event.EventID + `","action_kind":"mcp","attributes":{"tool.name":"shell"},"classification":{"category":"runtime","outcome":"blocked","resource_class":"tool","route_class":"local"}}`))
	quarantinedDigest := sha256.Sum256([]byte(`{"event_id":"` + quarantinedEvent.EventID + `","action_kind":"http","attributes":{"http.method":"GET","http.route_class":"read"},"classification":{"category":"runtime","outcome":"monitored","resource_class":"tool","route_class":"local"}}`))
	receipts := []gatewayEvaluationReceipt{
		{EventID: quarantinedEvent.EventID, RequestDigest: quarantinedDigest, Result: gatewayEvaluationResult{Decision: "monitor", PolicyVersion: 2, CacheState: "valid", MatchedPolicyIDs: []string{"policy-2"}}, EvaluatedAt: quarantinedEvent.OccurredAt},
		{EventID: event.EventID, RequestDigest: pendingDigest, Result: gatewayEvaluationResult{Decision: "block", PolicyVersion: 3, CacheState: "valid", MatchedPolicyIDs: []string{"policy-1"}}, EvaluatedAt: event.OccurredAt},
	}
	state := gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: 4, ObservedAt: gatewayRuntimeTime(), Pending: []gatewayDecisionEvent{event}, Quarantined: []gatewayQuarantinedDecisionEvent{quarantined}, Receipts: receipts}
	if err := store.Store(state); err != nil || store.Close() != nil {
		t.Fatalf("store err=%v", err)
	}
	restored, err := newGatewayEvidenceDiskStore(path, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restored.Load()
	if err != nil || !loaded.AuthorityConfirmed || loaded.ConfirmedFloor != 4 || !loaded.ObservedAt.Equal(gatewayRuntimeTime()) || len(loaded.Pending) != 1 || !sameGatewayDecisionEvent(loaded.Pending[0], event) || len(loaded.Quarantined) != 1 || !sameGatewayDecisionEvent(loaded.Quarantined[0].Event, quarantinedEvent) || loaded.Quarantined[0].Reason != gatewayEvidenceExpiredReason || !loaded.Quarantined[0].QuarantinedAt.Equal(gatewayRuntimeTime()) || len(loaded.Receipts) != 2 || loaded.Receipts[0].RequestDigest != quarantinedDigest || loaded.Receipts[1].RequestDigest != pendingDigest {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	if restored.Close() != nil {
		t.Fatal("close failed")
	}
}

func TestGatewayEvidenceDiskStoreRejectsUnsafeDirectories(t *testing.T) {
	expected := gatewayRuntimeAuthority()
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{name: "regular file", mutate: func(path string) error { return os.WriteFile(path, []byte("{}\n"), 0o600) }},
		{name: "world writable", mutate: func(path string) error {
			if err := os.Mkdir(path, 0o700); err != nil {
				return err
			}
			return os.Chmod(path, 0o770)
		}},
		{name: "symlink", mutate: func(path string) error {
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return os.Symlink(target, path)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "evidence")
			if err := test.mutate(path); err != nil {
				t.Fatal(err)
			}
			if store, err := newGatewayEvidenceDiskStore(path, expected, 8, 16<<20); err == nil || store != nil {
				t.Fatalf("store=%#v err=%v", store, err)
			}
		})
	}
}

func TestGatewayEvidenceDiskStoreRejectsUnsafeExistingFilesBeforeRecovery(t *testing.T) {
	expected := gatewayRuntimeAuthority()
	for _, test := range []struct {
		name  string
		setup func(string, string) error
	}{
		{name: "unexpected file", setup: func(path, _ string) error {
			return os.WriteFile(filepath.Join(path, "unexpected"), []byte("unsafe"), 0o600)
		}},
		{name: "group readable database file", setup: func(path, _ string) error {
			return os.WriteFile(filepath.Join(path, "000001.sst"), []byte("unsafe"), 0o640)
		}},
		{name: "database symlink", setup: func(path, target string) error { return os.Symlink(target, filepath.Join(path, "000001.sst")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "evidence")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(directory, "target")
			if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.setup(path, target); err != nil {
				t.Fatal(err)
			}
			if store, err := newGatewayEvidenceDiskStore(path, expected, 8, 16<<20); err == nil || store != nil {
				t.Fatalf("store=%#v err=%v", store, err)
			}
			raw, err := os.ReadFile(target)
			if err != nil || string(raw) != "unchanged" {
				t.Fatalf("target=%q err=%v", raw, err)
			}
		})
	}
}

func TestGatewayEvidenceDiskStorePinsSecureDirectoryAndRejectsReplacement(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "evidence")
	store, err := newGatewayEvidenceDiskStore(path, gatewayRuntimeAuthority(), 8, 16<<20)
	if err != nil {
		entries, _ := os.ReadDir(path)
		for _, entry := range entries {
			info, _ := entry.Info()
			t.Logf("entry=%s mode=%v", entry.Name(), info.Mode())
		}
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	entries, readErr := os.ReadDir(path)
	if err != nil || readErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || len(entries) == 0 {
		t.Fatalf("info=%#v entries=%#v err=%v read_err=%v", info, entries, err, readErr)
	}
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil || !entryInfo.Mode().IsRegular() || entryInfo.Mode().Perm() != 0o600 {
			t.Fatalf("entry=%s info=%#v err=%v", entry.Name(), entryInfo, err)
		}
	}
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("load after directory replacement=%v", err)
	}
	if err := store.Close(); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("close after directory replacement=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("repeated close=%v", err)
	}
}

func TestGatewayRuntimeRestoresCachedOfflineEvidenceAndDrainsAfterReconnect(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	expected := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, expected, now, "closed")
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cachePath := filepath.Join(directory, "policy.json")
	evidencePath := filepath.Join(directory, "evidence")

	cache, err := policy.NewGatewayPolicyDiskCache(cachePath, keys, expected.Binding(), func() time.Time { return now })
	if err != nil || cache.Store(envelope) != nil {
		t.Fatalf("cache err=%v", err)
	}
	store, err := newGatewayEvidenceDiskStore(evidencePath, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	offline := &gatewayControlStub{authority: expected, readyErr: errGatewayRuntime}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: offline, Cache: cache, Evidence: store, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")})
	if err != nil || result.Decision != "block" || runtime.SyncOnce(context.Background()) == nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if cache.Close() != nil || store.Close() != nil {
		t.Fatal("close failed")
	}

	restoredCache, err := policy.NewGatewayPolicyDiskCache(cachePath, keys, expected.Binding(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	restoredStore, err := newGatewayEvidenceDiskStore(evidencePath, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	online := &gatewayControlStub{authority: expected}
	restarted, err := newGatewayRuntime(gatewayRuntimeConfig{Control: online, Cache: restoredCache, Evidence: restoredStore, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || restarted.SyncOnce(context.Background()) != nil || restarted.RecordOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", restarted, err)
	}
	if len(online.events) != 1 || online.events[0].EventID != gatewayRuntimeID(9) || online.events[0].ExpectedFloor != 0 || online.events[0].NextFloor != 1 {
		t.Fatalf("events=%#v", online.events)
	}
	loaded, err := restoredStore.Load()
	if err != nil || !loaded.AuthorityConfirmed || loaded.ConfirmedFloor != 1 || len(loaded.Pending) != 0 {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
}

func TestGatewayRuntimePreservesClockFloorAcrossRestart(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	expected := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, expected, now, "closed")
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cachePath := filepath.Join(directory, "policy.json")
	evidencePath := filepath.Join(directory, "evidence")
	cache, err := policy.NewGatewayPolicyDiskCache(cachePath, keys, expected.Binding(), func() time.Time { return now })
	if err != nil || cache.Store(envelope) != nil {
		t.Fatalf("cache err=%v", err)
	}
	store, err := newGatewayEvidenceDiskStore(evidencePath, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: expected}, Cache: cache, Evidence: store, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.Ready(context.Background()) != nil || cache.Close() != nil || store.Close() != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}

	now = now.Add(-time.Minute)
	restoredCache, err := policy.NewGatewayPolicyDiskCache(cachePath, keys, expected.Binding(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	restoredStore, err := newGatewayEvidenceDiskStore(evidencePath, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: expected}, Cache: restoredCache, Evidence: restoredStore, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready after restart clock rollback=%v", err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if result, err := restarted.Evaluate(context.Background(), request); !errors.Is(err, errGatewayRuntime) || result.Decision != "" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	now = gatewayRuntimeTime()
	if err := restarted.Ready(context.Background()); err != nil {
		t.Fatalf("ready after clock recovery=%v", err)
	}
}

func TestGatewayRuntimeRestoresDrainedEvaluationReplayReceipt(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	expected := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, expected, now, "closed")
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cachePath := filepath.Join(directory, "policy.json")
	evidencePath := filepath.Join(directory, "evidence")
	cache, err := policy.NewGatewayPolicyDiskCache(cachePath, keys, expected.Binding(), func() time.Time { return now })
	if err != nil || cache.Store(envelope) != nil {
		t.Fatalf("cache err=%v", err)
	}
	store, err := newGatewayEvidenceDiskStore(evidencePath, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	control := &gatewayControlStub{authority: expected}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: store, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	first, err := runtime.Evaluate(context.Background(), request)
	if err != nil || runtime.RecordOnce(context.Background()) != nil || len(control.events) != 1 || cache.Close() != nil || store.Close() != nil {
		t.Fatalf("first=%#v events=%#v err=%v", first, control.events, err)
	}

	restoredCache, err := policy.NewGatewayPolicyDiskCache(cachePath, keys, expected.Binding(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	restoredStore, err := newGatewayEvidenceDiskStore(evidencePath, expected, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	restartedControl := &gatewayControlStub{authority: expected}
	restarted, err := newGatewayRuntime(gatewayRuntimeConfig{Control: restartedControl, Cache: restoredCache, Evidence: restoredStore, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Evaluate(context.Background(), request)
	if err != nil || replayed.Decision != first.Decision || replayed.PolicyVersion != first.PolicyVersion || replayed.CacheState != first.CacheState || len(replayed.MatchedPolicyIDs) != 1 || replayed.MatchedPolicyIDs[0] != first.MatchedPolicyIDs[0] || len(restartedControl.events) != 0 || len(restarted.pending) != 0 || restarted.confirmedFloor != 1 {
		t.Fatalf("first=%#v replayed=%#v events=%#v pending=%#v floor=%d err=%v", first, replayed, restartedControl.events, restarted.pending, restarted.confirmedFloor, err)
	}
}

func TestGatewayEvidenceDiskStorePrunesOnlyExpiredInactiveReceipts(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := gatewayRuntimeAuthority()
	now := gatewayRuntimeTime()
	store, err := newGatewayEvidenceDiskStore(filepath.Join(directory, "evidence"), authority, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	completedEvent, completedReceipt := gatewayEvidenceStoreFixture(authority, gatewayRuntimeSequenceID(101), 0, now.Add(-25*time.Hour), false)
	activeEvent, activeReceipt := gatewayEvidenceStoreFixture(authority, gatewayRuntimeSequenceID(102), 1, now.Add(-24*time.Hour), false)
	if err := store.Store(gatewayEvidenceState{
		AuthorityConfirmed: true, ConfirmedFloor: 0, ObservedAt: now,
		Pending:  []gatewayDecisionEvent{completedEvent, activeEvent},
		Receipts: []gatewayEvaluationReceipt{completedReceipt, activeReceipt},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(gatewayEvidenceState{
		AuthorityConfirmed: true, ConfirmedFloor: 1, ObservedAt: now,
		Pending:  []gatewayDecisionEvent{activeEvent},
		Receipts: []gatewayEvaluationReceipt{activeReceipt},
	}); err != nil {
		t.Fatal(err)
	}
	usage, err := store.Maintain(now)
	if err != nil || usage.ReceiptCount != 1 || usage.ReceiptBytes == 0 {
		t.Fatalf("usage=%#v err=%v", usage, err)
	}
	if _, found, err := store.Receipt(completedEvent.EventID, now); err != nil || found {
		t.Fatalf("completed found=%t err=%v", found, err)
	}
	if receipt, found, err := store.Receipt(activeEvent.EventID, now); err != nil || !found || receipt.EventID != activeEvent.EventID {
		t.Fatalf("active=%#v found=%t err=%v", receipt, found, err)
	}
	if err := store.Store(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: 2, ObservedAt: now, Pending: []gatewayDecisionEvent{}, Receipts: []gatewayEvaluationReceipt{}}); err != nil {
		t.Fatal(err)
	}
	usage, err = store.Maintain(now)
	if err != nil || usage.ReceiptCount != 0 || usage.ReceiptBytes != 0 {
		t.Fatalf("final usage=%#v err=%v", usage, err)
	}
}

func TestGatewayEvidenceDiskStoreRejectsCapacityWithoutPartialReceipt(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := gatewayRuntimeAuthority()
	now := gatewayRuntimeTime()
	store, err := newGatewayEvidenceDiskStore(filepath.Join(directory, "evidence"), authority, 1, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	accepted := 0
	failedEventID := ""
	for index := 0; index < 32; index++ {
		observedAt := now.Add(time.Duration(index) * time.Second)
		event, receipt := gatewayEvidenceStoreFixture(authority, gatewayRuntimeSequenceID(200+index), uint64(index), observedAt, true)
		state := gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: uint64(index), ObservedAt: observedAt, Pending: []gatewayDecisionEvent{event}, Receipts: []gatewayEvaluationReceipt{receipt}}
		if err := store.Store(state); err != nil {
			failedEventID = event.EventID
			break
		}
		accepted++
		if err := store.Store(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: uint64(index + 1), ObservedAt: observedAt, Pending: []gatewayDecisionEvent{}, Receipts: []gatewayEvaluationReceipt{}}); err != nil {
			t.Fatal(err)
		}
	}
	if accepted < 1 || accepted >= 32 || failedEventID == "" {
		t.Fatalf("accepted=%d failed=%q", accepted, failedEventID)
	}
	usage, err := store.Maintain(now.Add(time.Hour))
	if err != nil || usage.ReceiptCount != uint64(accepted) || usage.ReceiptBytes == 0 || usage.ReceiptBytes > usage.MaximumBytes || usage.DatabaseBytes == 0 || usage.MaximumDatabaseBytes != gatewayEvidenceMinimumPhysicalBytes || usage.DatabaseBytes >= usage.MaximumDatabaseBytes {
		t.Fatalf("usage=%#v accepted=%d err=%v", usage, accepted, err)
	}
	if _, found, err := store.Receipt(failedEventID, now.Add(time.Hour)); err != nil || found {
		t.Fatalf("partial receipt found=%t err=%v", found, err)
	}
	if receipt, found, err := store.Receipt(gatewayRuntimeSequenceID(200+accepted-1), now.Add(time.Hour)); err != nil || !found || receipt.EventID == "" {
		t.Fatalf("last receipt=%#v found=%t err=%v", receipt, found, err)
	}
}

func TestGatewayEvidenceDiskStoreFailsClosedBeforePhysicalCapacityIsExhausted(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := gatewayRuntimeAuthority()
	now := gatewayRuntimeTime()
	store, err := newGatewayEvidenceDiskStore(filepath.Join(directory, "evidence"), authority, 1, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	usage, err := store.Maintain(now)
	if err != nil || usage.DatabaseBytes == 0 {
		t.Fatalf("initial usage=%#v err=%v", usage, err)
	}
	event, receipt := gatewayEvidenceStoreFixture(authority, gatewayRuntimeSequenceID(900), 0, now, false)
	state := gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: 0, ObservedAt: now, Pending: []gatewayDecisionEvent{event}, Receipts: []gatewayEvaluationReceipt{receipt}}
	store.maximumDatabaseBytes = usage.DatabaseBytes + gatewayEvidencePhysicalWriteReserve - 1
	if err := store.Store(state); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("physical-capacity store=%v", err)
	}
	if _, found, err := store.Receipt(event.EventID, now); err != nil || found {
		t.Fatalf("partial receipt found=%t err=%v", found, err)
	}
	store.maximumDatabaseBytes = usage.DatabaseBytes + gatewayEvidencePhysicalWriteReserve
	if err := store.Store(state); err != nil {
		t.Fatalf("store with exact reserve=%v", err)
	}
	usage, err = store.Maintain(now)
	if err != nil || usage.DatabaseBytes == 0 || usage.DatabaseBytes >= usage.MaximumDatabaseBytes {
		t.Fatalf("final usage=%#v err=%v", usage, err)
	}
}

func TestGatewayEvidenceDiskStoreMeasuresPhysicalUsageAfterReceiptChurn(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := gatewayRuntimeAuthority()
	now := gatewayRuntimeTime()
	store, err := newGatewayEvidenceDiskStore(filepath.Join(directory, "evidence"), authority, 1, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index := 0; index < 64; index++ {
		observedAt := now.Add(time.Duration(index) * time.Second)
		event, receipt := gatewayEvidenceStoreFixture(authority, gatewayRuntimeSequenceID(1000+index), uint64(index), observedAt, false)
		if err := store.Store(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: uint64(index), ObservedAt: observedAt, Pending: []gatewayDecisionEvent{event}, Receipts: []gatewayEvaluationReceipt{receipt}}); err != nil {
			t.Fatalf("store %d: %v", index, err)
		}
		if err := store.Store(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: uint64(index + 1), ObservedAt: observedAt, Pending: []gatewayDecisionEvent{}, Receipts: []gatewayEvaluationReceipt{}}); err != nil {
			t.Fatalf("drain %d: %v", index, err)
		}
	}
	usage, err := store.Maintain(now.Add(gatewayEvidenceRecordWindow + time.Hour))
	if err != nil || usage.ReceiptCount != 0 || usage.ReceiptBytes != 0 || usage.DatabaseBytes == 0 || usage.DatabaseBytes >= usage.MaximumDatabaseBytes {
		t.Fatalf("churn usage=%#v err=%v", usage, err)
	}
}

func BenchmarkGatewayEvidenceStoreReceiptLifecycle(b *testing.B) {
	directory, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	authority := gatewayRuntimeAuthority()
	store, err := newGatewayEvidenceDiskStore(filepath.Join(directory, "evidence"), authority, 1, 64<<30)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	now := gatewayRuntimeTime()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		observedAt := now.Add(time.Duration(index) * time.Second)
		event, receipt := gatewayEvidenceStoreFixture(authority, gatewayRuntimeSequenceID(1000+index), uint64(index), observedAt, false)
		if err := store.Store(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: uint64(index), ObservedAt: observedAt, Pending: []gatewayDecisionEvent{event}, Receipts: []gatewayEvaluationReceipt{receipt}}); err != nil {
			b.Fatal(err)
		}
		if err := store.Store(gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: uint64(index + 1), ObservedAt: observedAt, Pending: []gatewayDecisionEvent{}, Receipts: []gatewayEvaluationReceipt{}}); err != nil {
			b.Fatal(err)
		}
	}
}

func gatewayEvidenceStoreFixture(authority gatewayAuthority, eventID string, expectedFloor uint64, occurredAt time.Time, large bool) (gatewayDecisionEvent, gatewayEvaluationReceipt) {
	event := gatewayDecisionEvent{
		CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: eventID,
		ExpectedFloor: expectedFloor, NextFloor: expectedFloor + 1, PolicyVersion: 1, Decision: "block", ActionKind: "mcp",
		Classification: gatewayRuntimeClassification("blocked"), OccurredAt: occurredAt,
	}
	matched := []string{"policy-1"}
	if large {
		matched = make([]string, 512)
		for index := range matched {
			matched[index] = fmt.Sprintf("policy-%03d-%s", index, strings.Repeat("x", 110))
		}
	}
	return event, gatewayEvaluationReceipt{
		EventID: eventID, RequestDigest: sha256.Sum256([]byte(eventID)),
		Result: gatewayEvaluationResult{Decision: "block", PolicyVersion: 1, CacheState: policy.GatewayPolicyValid, MatchedPolicyIDs: matched}, EvaluatedAt: occurredAt,
	}
}
