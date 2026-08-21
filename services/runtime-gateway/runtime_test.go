package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestGatewayRuntimeSyncsSignedPolicyAndEvaluatesWithoutControlPlaneCall(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope, recorded: make(chan struct{}, 1)}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	controlCalls := control.calls
	result, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")})
	if err != nil || result.Decision != "block" || result.PolicyVersion != 1 || len(result.MatchedPolicyIDs) != 1 || control.calls != controlCalls {
		t.Fatalf("result=%#v err=%v calls=%d/%d", result, err, control.calls, controlCalls)
	}
	if runtime.RecordOnce(context.Background()) != nil || len(control.events) != 1 || control.events[0].Decision != "block" || control.events[0].Classification["outcome"] != "blocked" || control.events[0].NextFloor != 1 {
		t.Fatalf("events=%#v", control.events)
	}
}

func TestGatewayRuntimeBindsBlockedCapabilityEvidence(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	classification := gatewayRuntimeCapabilityClassification("data_write", "write")
	result, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: classification})
	if err != nil || result.Decision != "block" || runtime.RecordOnce(context.Background()) != nil || len(control.events) != 1 {
		t.Fatalf("result=%#v events=%#v err=%v", result, control.events, err)
	}
	for key, value := range classification {
		if control.events[0].Classification[key] != value {
			t.Fatalf("classification=%#v want %s=%s", control.events[0].Classification, key, value)
		}
	}
	allow := gatewayEvaluationRequest{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "read"}, Classification: gatewayRuntimeCapabilityClassification("data_read", "read")}
	if result, err := runtime.Evaluate(context.Background(), allow); !errors.Is(err, errGatewayRuntime) || result.Decision != "" {
		t.Fatalf("allow binding result=%#v err=%v", result, err)
	}
}

func TestGatewayRuntimeAppliesDeterministicOfflineFailureMode(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	authority := gatewayRuntimeAuthority()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	for _, test := range []struct{ mode, decision string }{{"open", "allow"}, {"closed", "block"}} {
		cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), gatewayRuntimeTime)
		runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: test.mode, MaximumPendingEvents: 2, Now: gatewayRuntimeTime})
		if err != nil {
			t.Fatal(err)
		}
		result, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(8), ActionKind: "http", Attributes: map[string]string{"http.method": "GET", "http.route_class": "read"}, Classification: gatewayRuntimeClassification(test.decision)})
		if err != nil || result.Decision != test.decision || result.CacheState != "unavailable_"+test.mode {
			t.Fatalf("mode=%s result=%#v err=%v", test.mode, result, err)
		}
	}
}

func TestGatewayRuntimeRejectsRawOrUnboundEvaluationData(t *testing.T) {
	authority := gatewayRuntimeAuthority()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), gatewayRuntimeTime)
	runtime, _ := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 2, Now: gatewayRuntimeTime})
	for _, request := range []gatewayEvaluationRequest{
		{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.arguments": "secret"}, Classification: gatewayRuntimeClassification("block")},
		{EventID: gatewayRuntimeID(8), ActionKind: "http", Attributes: map[string]string{"http.body": "secret"}, Classification: gatewayRuntimeClassification("block")},
		{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: map[string]string{"category": "runtime", "outcome": "block", "authorization": "secret"}},
		{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "blocked", "agent_id": gatewayRuntimeID(6)}},
		{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeCapabilityClassification("data_read", "write")},
	} {
		if result, err := runtime.Evaluate(context.Background(), request); !errors.Is(err, errGatewayRuntime) || result.Decision != "" {
			t.Fatalf("request=%#v result=%#v err=%v", request, result, err)
		}
	}
}

func TestGatewayRuntimeBackgroundSyncsAndDrainsEvidence(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope, recorded: make(chan struct{}, 1)}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	runtime, _ := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if runtime.SyncOnce(context.Background()) != nil {
		t.Fatal("initial sync failed")
	}
	if _, err := runtime.Evaluate(context.Background(), gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx, 10*time.Millisecond, time.Millisecond) }()
	select {
	case <-control.recorded:
	case <-time.After(time.Second):
		t.Fatal("evidence did not drain")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayRuntimeDoesNotAcknowledgeEvidenceBeforeDurableQueueState(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	evidence.fail = true
	if result, err := runtime.Evaluate(context.Background(), request); !errors.Is(err, errGatewayRuntime) || result.Decision != "" || len(runtime.pending) != 0 {
		t.Fatalf("result=%#v pending=%#v err=%v", result, runtime.pending, err)
	}
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready after failed evaluate store=%v", err)
	}
	evidence.fail = false
	if _, err := runtime.Evaluate(context.Background(), request); err != nil || len(runtime.pending) != 1 {
		t.Fatalf("pending=%#v err=%v", runtime.pending, err)
	}
	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("ready after recovered evaluate store=%v", err)
	}
	evidence.fail = true
	if err := runtime.RecordOnce(context.Background()); !errors.Is(err, errGatewayRuntime) || len(runtime.pending) != 1 || len(control.events) != 1 {
		t.Fatalf("pending=%#v events=%#v err=%v", runtime.pending, control.events, err)
	}
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready after failed record store=%v", err)
	}
	evidence.fail = false
	if err := runtime.RecordOnce(context.Background()); err != nil || len(runtime.pending) != 0 || len(control.events) != 2 || !sameGatewayDecisionEvent(control.events[0], control.events[1]) {
		t.Fatalf("pending=%#v events=%#v err=%v", runtime.pending, control.events, err)
	}
	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("ready after recovered record store=%v", err)
	}
}

func TestGatewayRuntimeReconcilesCommittedEvidenceAfterLostStoreAcknowledgment(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	evidence.failAfterStore = true
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	result, err := runtime.Evaluate(context.Background(), request)
	if err != nil || result.Decision != "block" || len(runtime.pending) != 1 || len(evidence.state.Pending) != 1 || evidence.state.Pending[0].EventID != request.EventID {
		t.Fatalf("result=%#v pending=%#v stored=%#v err=%v", result, runtime.pending, evidence.state.Pending, err)
	}
	evidence.failAfterStore = true
	if err := runtime.RecordOnce(context.Background()); err != nil || len(runtime.pending) != 0 || len(evidence.state.Pending) != 0 || evidence.state.ConfirmedFloor != 1 || len(control.events) != 1 {
		t.Fatalf("pending=%#v stored=%#v events=%#v err=%v", runtime.pending, evidence.state, control.events, err)
	}
}

func TestGatewayRuntimeQuarantinesExpiredEvidenceAndDrainsNewerEvents(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	eventNow := now.Add(-24 * time.Hour)
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return eventNow }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	first := gatewayEvaluationRequest{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	second := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if _, err := runtime.Evaluate(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	eventNow = now.Add(-23 * time.Hour)
	if _, err := runtime.Evaluate(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	eventNow = now
	control.recordErr = errGatewayRecordExpired
	if err := runtime.RecordOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := evidence.state
	if len(control.events) != 0 || len(state.Quarantined) != 1 || state.Quarantined[0].Event.EventID != first.EventID || state.Quarantined[0].Reason != gatewayEvidenceExpiredReason || !state.Quarantined[0].QuarantinedAt.Equal(now) || len(state.Pending) != 1 || state.Pending[0].EventID != second.EventID || state.Pending[0].ExpectedFloor != 0 || state.Pending[0].NextFloor != 1 || state.ConfirmedFloor != 0 {
		t.Fatalf("events=%#v state=%#v", control.events, state)
	}
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready with quarantined evidence=%v", err)
	}
	control.recordErr = nil
	if err := runtime.RecordOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	state = evidence.state
	if len(control.events) != 1 || control.events[0].EventID != second.EventID || control.events[0].ExpectedFloor != 0 || control.events[0].NextFloor != 1 || state.ConfirmedFloor != 1 || len(state.Pending) != 0 || len(state.Quarantined) != 1 {
		t.Fatalf("events=%#v state=%#v", control.events, state)
	}
	third := gatewayEvaluationRequest{EventID: gatewayRuntimeID(7), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if result, err := runtime.Evaluate(context.Background(), third); !errors.Is(err, errGatewayRuntime) || result.Decision != "" || len(evidence.state.Pending) != 0 {
		t.Fatalf("result=%#v state=%#v err=%v", result, evidence.state, err)
	}
}

func TestGatewayRuntimeNeverQuarantinesAmbiguousExpiredRecordFailure(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	eventNow := now.Add(-gatewayEvidenceMaximumAge - time.Second)
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope, recordErr: errors.New("temporary control-plane failure")}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return eventNow }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(8), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if _, err := runtime.Evaluate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	eventNow = now
	if err := runtime.RecordOnce(context.Background()); !errors.Is(err, errGatewayRuntime) || len(evidence.state.Pending) != 1 || len(evidence.state.Quarantined) != 0 {
		t.Fatalf("state=%#v err=%v", evidence.state, err)
	}
}

func TestGatewayRuntimeReconcilesLateExactRecordReplayBeforeQuarantine(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if _, err := runtime.Evaluate(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	control.recordErr = errors.New("lost record acknowledgement")
	if err := runtime.RecordOnce(context.Background()); !errors.Is(err, errGatewayRuntime) || len(evidence.state.Pending) != 1 {
		t.Fatalf("first record err=%v state=%#v", err, evidence.state)
	}
	control.recordErr = nil
	control.authority.ReplayFloor = 1
	now = now.Add(gatewayEvidenceMaximumAge + time.Second)
	if err := runtime.RecordOnce(context.Background()); err != nil {
		t.Fatalf("late exact replay=%v", err)
	}
	if len(control.events) != 1 || len(evidence.state.Pending) != 0 || len(evidence.state.Quarantined) != 0 || evidence.state.ConfirmedFloor != 1 {
		t.Fatalf("events=%#v state=%#v", control.events, evidence.state)
	}
}

func TestGatewayRuntimeRejectsInProcessClockRollbackBeforeEvaluation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}

	now = now.Add(-time.Minute)
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready after clock rollback=%v", err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if result, err := runtime.Evaluate(context.Background(), request); !errors.Is(err, errGatewayRuntime) || result.Decision != "" || len(evidence.state.Pending) != 0 {
		t.Fatalf("result=%#v state=%#v err=%v", result, evidence.state, err)
	}
}

func TestGatewayRuntimeReadinessPersistsAdvancedClockFloorBeforeRollback(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	initial := now
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	now = initial.Add(31 * time.Second)
	if err := runtime.Ready(context.Background()); err != nil || !evidence.state.ObservedAt.Equal(now) {
		t.Fatalf("observed=%v ready=%v", evidence.state.ObservedAt, err)
	}
	now = initial.Add(time.Second)
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready after observed clock rollback=%v", err)
	}
}

func TestGatewayRuntimeReadinessRecoversAfterEvidenceStoreReturns(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope, readyErr: errors.New("offline")}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(gatewayEvidenceClockPersist + time.Second)
	evidence.fail = true
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("ready during evidence outage=%v", err)
	}
	evidence.fail = false
	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("ready after evidence recovery=%v", err)
	}
	if !evidence.state.ObservedAt.Equal(now) {
		t.Fatalf("persisted observed_at=%v want=%v", evidence.state.ObservedAt, now)
	}
}

func TestGatewayRuntimeReplaysDrainedEvaluationWithoutAllocatingAnotherFloor(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	first, err := runtime.Evaluate(context.Background(), request)
	if err != nil || runtime.RecordOnce(context.Background()) != nil || len(control.events) != 1 || evidence.state.ConfirmedFloor != 1 || len(evidence.state.Pending) != 0 {
		t.Fatalf("first=%#v events=%#v state=%#v err=%v", first, control.events, evidence.state, err)
	}

	replayed, err := runtime.Evaluate(context.Background(), request)
	if err != nil || replayed.Decision != first.Decision || replayed.PolicyVersion != first.PolicyVersion || replayed.CacheState != first.CacheState || len(replayed.MatchedPolicyIDs) != 1 || replayed.MatchedPolicyIDs[0] != first.MatchedPolicyIDs[0] || len(control.events) != 1 || evidence.state.ConfirmedFloor != 1 || len(evidence.state.Pending) != 0 {
		t.Fatalf("first=%#v replayed=%#v events=%#v state=%#v err=%v", first, replayed, control.events, evidence.state, err)
	}
	drifted := request
	drifted.Attributes = map[string]string{"tool.name": "different"}
	if result, err := runtime.Evaluate(context.Background(), drifted); !errors.Is(err, errGatewayRuntime) || result.Decision != "" || len(evidence.state.Pending) != 0 {
		t.Fatalf("result=%#v state=%#v err=%v", result, evidence.state, err)
	}
}

func TestGatewayRuntimePersistsAllowAndExpiredDecisionReplayReceipts(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	evidence := &gatewayEvidenceStoreStub{}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	allowRequest := gatewayEvaluationRequest{EventID: gatewayRuntimeID(8), ActionKind: "http", Attributes: map[string]string{"http.method": "GET", "http.route_class": "read"}, Classification: gatewayRuntimeClassification("allowed")}
	allow, err := runtime.Evaluate(context.Background(), allowRequest)
	if err != nil || allow.Decision != "allow" || allow.CacheState != policy.GatewayPolicyValid || allow.MatchedPolicyIDs == nil || len(allow.MatchedPolicyIDs) != 0 || runtime.RecordOnce(context.Background()) != nil {
		t.Fatalf("allow=%#v receipts=%#v err=%v", allow, evidence.state.Receipts, err)
	}

	now = now.Add(2 * time.Hour)
	expiredRequest := gatewayEvaluationRequest{EventID: gatewayRuntimeID(9), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	expired, err := runtime.Evaluate(context.Background(), expiredRequest)
	if err != nil || expired.Decision != "block" || expired.CacheState != policy.GatewayPolicyExpiredClosed || expired.MatchedPolicyIDs == nil || len(expired.MatchedPolicyIDs) != 0 || len(evidence.state.Receipts) != 1 || len(evidence.receipts) != 2 {
		t.Fatalf("expired=%#v active_receipts=%#v durable_receipts=%#v err=%v", expired, evidence.state.Receipts, evidence.receipts, err)
	}
}

func TestGatewayRuntimeRetainsDrainedReceiptsWithoutPendingQueueThroughputCap(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	envelope := signedGatewayRuntimeEnvelope(t, private, authority, now, "closed")
	control := &gatewayControlStub{authority: authority, envelope: &envelope}
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(directory, "evidence")
	evidence, err := newGatewayEvidenceDiskStore(evidencePath, authority, 1, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 1, Now: func() time.Time { return now }})
	if err != nil || runtime.SyncOnce(context.Background()) != nil {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	for id := 1; id <= 100; id++ {
		request := gatewayEvaluationRequest{EventID: gatewayRuntimeSequenceID(id), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
		if _, err := runtime.Evaluate(context.Background(), request); err != nil || runtime.RecordOnce(context.Background()) != nil {
			t.Fatalf("id=%d err=%v", id, err)
		}
	}
	loaded, err := evidence.Load()
	usage, usageErr := evidence.Maintain(now)
	if err != nil || usageErr != nil || len(loaded.Receipts) != 0 || usage.ReceiptCount != 100 || runtime.Ready(context.Background()) != nil {
		t.Fatalf("loaded=%#v usage=%#v err=%v usage_err=%v ready=%v", loaded, usage, err, usageErr, runtime.Ready(context.Background()))
	}
	if evidence.Close() != nil {
		t.Fatal("close failed")
	}
	restored, err := newGatewayEvidenceDiskStore(evidencePath, authority, 1, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: restored, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 1, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	replay := gatewayEvaluationRequest{EventID: gatewayRuntimeSequenceID(1), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	if result, err := restarted.Evaluate(context.Background(), replay); err != nil || result.Decision != "block" || result.PolicyVersion != 1 || len(restarted.pending) != 0 {
		t.Fatalf("result=%#v pending=%#v err=%v", result, restarted.pending, err)
	}
}

func TestGatewayEvidenceExpiryPreservesFullRequestAndClockSkewBudget(t *testing.T) {
	now := gatewayRuntimeTime()
	event := gatewayDecisionEvent{OccurredAt: now.Add(-gatewayEvidenceMaximumAge + time.Second)}
	if gatewayEvidenceExpired(event, now) {
		t.Fatal("event expired before the complete safety margin")
	}
	event.OccurredAt = now.Add(-gatewayEvidenceMaximumAge)
	if !gatewayEvidenceExpired(event, now) {
		t.Fatal("event remained recordable at the safety-margin boundary")
	}
}

func TestGatewayRuntimeMetricsExposeEvidenceCapacityWithoutAuthorityLabels(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	authority := gatewayRuntimeAuthority()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), gatewayRuntimeTime)
	evidence := &gatewayEvidenceStoreStub{usage: gatewayEvidenceUsage{ReceiptBytes: 2, MaximumBytes: 10, ReceiptCount: 1, DatabaseBytes: 4, MaximumDatabaseBytes: 20}}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: gatewayRuntimeTime})
	if err != nil {
		t.Fatal(err)
	}
	metrics := runtime.Metrics()
	for _, expected := range []string{
		"zasp_gateway_evidence_receipt_bytes 2\n",
		"zasp_gateway_evidence_receipt_capacity_bytes 10\n",
		"zasp_gateway_evidence_receipt_utilization_ratio 0.2\n",
		"zasp_gateway_evidence_receipts 1\n",
		"zasp_gateway_evidence_database_bytes 4\n",
		"zasp_gateway_evidence_database_capacity_bytes 20\n",
		"zasp_gateway_evidence_database_utilization_ratio 0.2\n",
		"zasp_gateway_evidence_pending 0\n",
		"zasp_gateway_evidence_quarantined 0\n",
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("missing %q in %s", expected, metrics)
		}
	}
	if strings.Contains(metrics, authority.OrganizationID) || strings.Contains(metrics, authority.DeviceID) || strings.Contains(metrics, authority.CredentialID) {
		t.Fatalf("metrics exposed authority: %s", metrics)
	}
}

func TestGatewayRuntimeReadinessFailsAtPhysicalDatabaseBoundary(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	authority := gatewayRuntimeAuthority()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), gatewayRuntimeTime)
	evidence := &gatewayEvidenceStoreStub{usage: gatewayEvidenceUsage{MaximumBytes: 16 << 20, DatabaseBytes: 32 << 20, MaximumDatabaseBytes: 32 << 20}}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: gatewayRuntimeTime})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Ready(context.Background()); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("physical-boundary readiness=%v", err)
	}
}

func TestGatewayRuntimeAcknowledgesOnlyExactAuthorityBoundQuarantine(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	authority.ReplayFloor = 7
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	firstRequest := gatewayEvaluationRequest{EventID: gatewayRuntimeSequenceID(901), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	secondRequest := gatewayEvaluationRequest{EventID: gatewayRuntimeSequenceID(902), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "read"}, Classification: gatewayRuntimeClassification("blocked")}
	firstDigest, _ := gatewayEvaluationRequestDigest(firstRequest)
	secondDigest, _ := gatewayEvaluationRequestDigest(secondRequest)
	firstEvent := gatewayDecisionEvent{CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: firstRequest.EventID, ExpectedFloor: 6, NextFloor: 7, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", Classification: gatewayRuntimeClassification("blocked"), OccurredAt: now.Add(-gatewayEvidenceMaximumAge)}
	secondEvent := gatewayDecisionEvent{CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: secondRequest.EventID, ExpectedFloor: 5, NextFloor: 6, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", Classification: gatewayRuntimeClassification("blocked"), OccurredAt: now.Add(-gatewayEvidenceMaximumAge + time.Second)}
	firstReceipt := gatewayEvaluationReceipt{EventID: firstEvent.EventID, RequestDigest: firstDigest, Result: gatewayEvaluationResult{Decision: "block", PolicyVersion: 1, CacheState: policy.GatewayPolicyValid, MatchedPolicyIDs: []string{"policy-1"}}, EvaluatedAt: firstEvent.OccurredAt}
	secondReceipt := gatewayEvaluationReceipt{EventID: secondEvent.EventID, RequestDigest: secondDigest, Result: gatewayEvaluationResult{Decision: "block", PolicyVersion: 1, CacheState: policy.GatewayPolicyValid, MatchedPolicyIDs: []string{"policy-1"}}, EvaluatedAt: secondEvent.OccurredAt}
	evidence := &gatewayEvidenceStoreStub{
		state: gatewayEvidenceState{
			AuthorityConfirmed: true, ConfirmedFloor: 7, ObservedAt: now, Pending: []gatewayDecisionEvent{},
			Quarantined: []gatewayQuarantinedDecisionEvent{{Event: firstEvent, Reason: gatewayEvidenceExpiredReason, QuarantinedAt: now}, {Event: secondEvent, Reason: gatewayEvidenceExpiredReason, QuarantinedAt: now}},
			Receipts:    []gatewayEvaluationReceipt{firstReceipt, secondReceipt},
		},
		receipts: map[string]gatewayEvaluationReceipt{firstReceipt.EventID: firstReceipt, secondReceipt.EventID: secondReceipt},
	}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: &gatewayControlStub{authority: authority}, Cache: cache, Evidence: evidence, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	acknowledgment := gatewayQuarantineAcknowledgment{EventID: firstEvent.EventID, RequestDigest: firstDigest, ConfirmedFloor: 7, IncidentID: gatewayRuntimeSequenceID(903)}
	if err := runtime.AcknowledgeQuarantine(context.Background(), acknowledgment); err != nil {
		t.Fatal(err)
	}
	if len(evidence.state.Quarantined) != 1 || evidence.state.Quarantined[0].Event.EventID != secondEvent.EventID || len(evidence.state.Receipts) != 1 || evidence.state.Receipts[0].EventID != secondEvent.EventID || evidence.state.ConfirmedFloor != 7 || !evidence.state.ObservedAt.Equal(now) {
		t.Fatalf("state=%#v", evidence.state)
	}
	if replayed, err := runtime.Evaluate(context.Background(), firstRequest); err != nil || replayed.Decision != "block" || replayed.PolicyVersion != 1 {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	if err := runtime.AcknowledgeQuarantine(context.Background(), gatewayQuarantineAcknowledgment{EventID: secondEvent.EventID, RequestDigest: firstDigest, ConfirmedFloor: 7, IncidentID: gatewayRuntimeSequenceID(904)}); !errors.Is(err, errGatewayRuntime) {
		t.Fatalf("mismatched digest err=%v", err)
	}
	if len(evidence.state.Quarantined) != 1 || evidence.state.Quarantined[0].Event.EventID != secondEvent.EventID {
		t.Fatalf("mismatched acknowledgment mutated state=%#v", evidence.state)
	}
}

func TestGatewayRuntimeReplaysDurableQuarantineAcknowledgmentAfterRestart(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	now := gatewayRuntimeTime()
	authority := gatewayRuntimeAuthority()
	authority.ReplayFloor = 3
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": public})
	cache, _ := policy.NewGatewayPolicyCache(keys, authority.Binding(), func() time.Time { return now })
	request := gatewayEvaluationRequest{EventID: gatewayRuntimeSequenceID(911), ActionKind: "mcp", Attributes: map[string]string{"tool.name": "shell"}, Classification: gatewayRuntimeClassification("blocked")}
	digest, _ := gatewayEvaluationRequestDigest(request)
	event := gatewayDecisionEvent{CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: request.EventID, ExpectedFloor: 2, NextFloor: 3, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", Classification: gatewayRuntimeClassification("blocked"), OccurredAt: now.Add(-gatewayEvidenceMaximumAge)}
	receipt := gatewayEvaluationReceipt{EventID: event.EventID, RequestDigest: digest, Result: gatewayEvaluationResult{Decision: "block", PolicyVersion: 1, CacheState: policy.GatewayPolicyValid, MatchedPolicyIDs: []string{"policy-1"}}, EvaluatedAt: event.OccurredAt}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "evidence")
	store, err := newGatewayEvidenceDiskStore(path, authority, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	state := gatewayEvidenceState{AuthorityConfirmed: true, ConfirmedFloor: 3, ObservedAt: now, Pending: []gatewayDecisionEvent{}, Quarantined: []gatewayQuarantinedDecisionEvent{{Event: event, Reason: gatewayEvidenceExpiredReason, QuarantinedAt: now}}, Receipts: []gatewayEvaluationReceipt{receipt}}
	if err := store.Store(state); err != nil {
		t.Fatal(err)
	}
	control := &gatewayControlStub{authority: authority}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: store, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	acknowledgment := gatewayQuarantineAcknowledgment{EventID: event.EventID, RequestDigest: digest, ConfirmedFloor: 3, IncidentID: gatewayRuntimeSequenceID(912)}
	if err := runtime.AcknowledgeQuarantine(context.Background(), acknowledgment); err != nil || store.Close() != nil {
		t.Fatalf("first acknowledgment err=%v", err)
	}
	restored, err := newGatewayEvidenceDiskStore(path, authority, 8, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restarted, err := newGatewayRuntime(gatewayRuntimeConfig{Control: control, Cache: cache, Evidence: restored, ExpectedAuthority: authority, CredentialID: authority.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.AcknowledgeQuarantine(context.Background(), acknowledgment); err != nil {
		t.Fatalf("replayed acknowledgment err=%v", err)
	}
	loaded, err := restored.Load()
	if err != nil || loaded.ConfirmedFloor != 3 || len(loaded.Pending) != 0 || len(loaded.Quarantined) != 0 || len(loaded.Receipts) != 0 {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
}

type gatewayControlStub struct {
	authority gatewayAuthority
	envelope  *policy.GatewayPolicyEnvelope
	readyErr  error
	events    []gatewayDecisionEvent
	calls     int
	recorded  chan struct{}
	recordErr error
}

type gatewayEvidenceStoreStub struct {
	state           gatewayEvidenceState
	receipts        map[string]gatewayEvaluationReceipt
	acknowledgments map[string]gatewayQuarantineAcknowledgment
	usage           gatewayEvidenceUsage
	fail            bool
	failAfterStore  bool
}

func (stub *gatewayEvidenceStoreStub) Load() (gatewayEvidenceState, error) {
	if stub.fail {
		return gatewayEvidenceState{}, errGatewayRuntime
	}
	return cloneGatewayEvidenceState(stub.state), nil
}

func (stub *gatewayEvidenceStoreStub) Store(state gatewayEvidenceState) error {
	if stub.fail {
		return errGatewayRuntime
	}
	if stub.receipts == nil {
		stub.receipts = make(map[string]gatewayEvaluationReceipt)
	}
	for _, receipt := range state.Receipts {
		if existing, found := stub.receipts[receipt.EventID]; found && (existing.RequestDigest != receipt.RequestDigest || existing.Result.Decision != receipt.Result.Decision || existing.Result.PolicyVersion != receipt.Result.PolicyVersion || !existing.EvaluatedAt.Equal(receipt.EvaluatedAt)) {
			return errGatewayRuntime
		}
		stub.receipts[receipt.EventID] = cloneGatewayEvaluationReceipts([]gatewayEvaluationReceipt{receipt})[0]
	}
	stub.state = cloneGatewayEvidenceState(state)
	if stub.failAfterStore {
		stub.failAfterStore = false
		return errGatewayRuntime
	}
	return nil
}

func (stub *gatewayEvidenceStoreStub) Receipt(eventID string, now time.Time) (gatewayEvaluationReceipt, bool, error) {
	if stub.fail {
		return gatewayEvaluationReceipt{}, false, errGatewayRuntime
	}
	receipt, found := stub.receipts[eventID]
	if !found || !gatewayEvidenceEventActive(stub.state, eventID) && !receipt.EvaluatedAt.After(now.Add(-gatewayEvidenceRecordWindow)) {
		return gatewayEvaluationReceipt{}, false, nil
	}
	return cloneGatewayEvaluationReceipts([]gatewayEvaluationReceipt{receipt})[0], true, nil
}

func (stub *gatewayEvidenceStoreStub) Maintain(now time.Time) (gatewayEvidenceUsage, error) {
	if stub.fail {
		return gatewayEvidenceUsage{}, errGatewayRuntime
	}
	for eventID, receipt := range stub.receipts {
		if !gatewayEvidenceEventActive(stub.state, eventID) && !receipt.EvaluatedAt.After(now.Add(-gatewayEvidenceRecordWindow)) {
			delete(stub.receipts, eventID)
		}
	}
	if stub.usage.MaximumBytes > 0 {
		return stub.usage, nil
	}
	return gatewayEvidenceUsage{ReceiptCount: uint64(len(stub.receipts)), ReceiptBytes: uint64(len(stub.receipts)), MaximumBytes: 16 << 20, DatabaseBytes: 1, MaximumDatabaseBytes: 128 << 20}, nil
}

func (stub *gatewayEvidenceStoreStub) Acknowledge(state gatewayEvidenceState, acknowledgment gatewayQuarantineAcknowledgment, _ time.Time) (bool, error) {
	if stub.fail || !validGatewayQuarantineAcknowledgment(acknowledgment) {
		return false, errGatewayRuntime
	}
	if existing, found := stub.acknowledgments[acknowledgment.EventID]; found {
		if !sameGatewayQuarantineAcknowledgment(existing, acknowledgment) {
			return false, errGatewayRuntime
		}
		stub.state = cloneGatewayEvidenceState(state)
		return true, nil
	}
	found := false
	for _, quarantined := range stub.state.Quarantined {
		if quarantined.Event.EventID == acknowledgment.EventID {
			receipt, exists := stub.receipts[acknowledgment.EventID]
			if !exists || receipt.RequestDigest != acknowledgment.RequestDigest || !gatewayReceiptMatchesEvent(receipt, quarantined.Event) || stub.state.ConfirmedFloor != acknowledgment.ConfirmedFloor {
				return false, errGatewayRuntime
			}
			found = true
			break
		}
	}
	if !found {
		return false, errGatewayRuntime
	}
	if stub.acknowledgments == nil {
		stub.acknowledgments = make(map[string]gatewayQuarantineAcknowledgment)
	}
	stub.acknowledgments[acknowledgment.EventID] = acknowledgment
	stub.state = cloneGatewayEvidenceState(state)
	return false, nil
}

func (*gatewayEvidenceStoreStub) Close() error { return nil }

func (stub *gatewayControlStub) Ready(context.Context) error { stub.calls++; return stub.readyErr }
func (stub *gatewayControlStub) Authority(context.Context, string) (gatewayAuthority, error) {
	stub.calls++
	return stub.authority, nil
}
func (stub *gatewayControlStub) Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error) {
	stub.calls++
	if stub.envelope == nil {
		return nil, nil
	}
	copy := *stub.envelope
	return &copy, nil
}
func (stub *gatewayControlStub) Record(_ context.Context, event gatewayDecisionEvent) error {
	stub.calls++
	if stub.recordErr != nil {
		return stub.recordErr
	}
	stub.events = append(stub.events, event)
	if stub.recorded != nil {
		select {
		case stub.recorded <- struct{}{}:
		default:
		}
	}
	return nil
}

func gatewayRuntimeAuthority() gatewayAuthority {
	return gatewayAuthority{OrganizationID: gatewayRuntimeID(1), WorkspaceID: gatewayRuntimeID(2), EnvironmentID: gatewayRuntimeID(3), DeviceID: gatewayRuntimeID(4), CredentialID: gatewayRuntimeID(5), ReplayFloor: 0}
}

func gatewayRuntimeID(value int) string {
	return "pid_9000000" + string(rune('0'+value)) + "-0000-4000-8000-00000000000" + string(rune('0'+value))
}

func gatewayRuntimeSequenceID(value int) string {
	return fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value)
}

func gatewayRuntimeTime() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }

func gatewayRuntimeClassification(outcome string) map[string]string {
	return map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": outcome}
}

func gatewayRuntimeCapabilityClassification(category, outcome string) map[string]string {
	classification := gatewayRuntimeClassification("blocked")
	classification["agent_id"] = gatewayRuntimeID(6)
	classification["target_id"] = gatewayRuntimeID(7)
	classification["capability_category"] = category
	classification["capability_outcome"] = outcome
	return classification
}

func signedGatewayRuntimeEnvelope(t *testing.T, private ed25519.PrivateKey, authority gatewayAuthority, now time.Time, failureMode string) policy.GatewayPolicyEnvelope {
	t.Helper()
	compiled, err := policy.Compile(policy.Policy{ID: "policy-1", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "equals", Value: "shell"}}})
	if err != nil {
		t.Fatal(err)
	}
	envelope := policy.GatewayPolicyEnvelope{ContractVersion: 1, KeyID: "gateway-key-1", Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, Sequence: 1, PolicyVersion: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), FailureMode: failureMode, Policies: []policy.CompiledPolicy{compiled}}
	policies := append([]policy.CompiledPolicy(nil), envelope.Policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	payload, _ := json.Marshal(struct {
		ContractVersion int                     `json:"contract_version"`
		KeyID           string                  `json:"key_id"`
		Algorithm       string                  `json:"algorithm"`
		Audience        string                  `json:"audience"`
		OrganizationID  string                  `json:"organization_id"`
		WorkspaceID     string                  `json:"workspace_id"`
		EnvironmentID   string                  `json:"environment_id"`
		DeviceID        string                  `json:"device_id"`
		Sequence        uint64                  `json:"sequence"`
		PolicyVersion   uint64                  `json:"policy_version"`
		IssuedAt        time.Time               `json:"issued_at"`
		ExpiresAt       time.Time               `json:"expires_at"`
		FailureMode     string                  `json:"failure_mode"`
		Policies        []policy.CompiledPolicy `json:"policies"`
	}{envelope.ContractVersion, envelope.KeyID, envelope.Algorithm, envelope.Audience, envelope.OrganizationID, envelope.WorkspaceID, envelope.EnvironmentID, envelope.DeviceID, envelope.Sequence, envelope.PolicyVersion, envelope.IssuedAt, envelope.ExpiresAt, envelope.FailureMode, policies})
	digest := sha256.Sum256(payload)
	envelope.PayloadDigest = hex.EncodeToString(digest[:])
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))
	return envelope
}
