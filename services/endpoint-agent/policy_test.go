package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	b      *broker
	now    time.Time
	signer ed25519.PrivateKey
	p      Policy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	// testing.T.TempDir can use the runner's umask for its leaf. The
	// production store requires an owner-only directory on every host.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	pub, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, device, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	binding := Binding{Organization: "org", Workspace: "workspace", Environment: "staging", Device: "test-device", Generation: 1}
	now := time.Now().UTC().Truncate(time.Second)
	store, e := openStore(dir, device.Seed(), binding)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{now: now, signer: signer, p: Policy{Audience: policyAudience, Binding: binding, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Mode: "monitor", Tool: ticketTool, AllowedDestination: "internal"}}
	f.b = &broker{binding: binding, uid: os.Geteuid(), key: device, policyKey: pub, policyFile: filepath.Join(dir, "policy.json"), store: store, now: func() time.Time { return f.now }}
	f.publish(t, f.p)
	return f
}

func (f *fixture) publish(t *testing.T, p Policy) Signed {
	t.Helper()
	envelope, err := sign(p, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, f.b.policyFile, envelope)
	return envelope
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	content, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func event(session, id, destination string) []byte {
	raw, _ := json.Marshal(map[string]any{"session_id": session, "tool_use_id": id, "hook_event_name": "PreToolUse", "tool_name": ticketTool, "tool_input": map[string]string{"destination": destination, "body": "private-body-never-in-receipts"}, "cwd": "/private/fixture/path"})
	return raw
}

func TestSnapshotScopeExpiryAndSignature(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Policy)
	}{
		{"gateway audience", func(p *Policy) { p.Audience = "runtime-gateway-policy" }},
		{"wrong generation", func(p *Policy) { p.Binding.Generation++ }},
		{"wrong tenant", func(p *Policy) { p.Binding.Environment = "other" }},
		{"wrong device", func(p *Policy) { p.Binding.Device = "other" }},
		{"unknown operation", func(p *Policy) { p.Tool = "other" }},
		{"oversized lease", func(p *Policy) { p.ExpiresAt = f.now.Add(25 * time.Hour) }},
		{"future issuance", func(p *Policy) { p.IssuedAt = f.now.Add(time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := f.p
			tc.change(&p)
			s, _ := sign(p, f.signer)
			if _, e := s.policy(f.b.policyKey, f.b.binding, f.now); e == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	s := f.publish(t, f.p)
	s.Signature[0] ^= 0xff
	if _, err := s.policy(f.b.policyKey, f.b.binding, f.now); err == nil {
		t.Fatal("tamper accepted")
	}
	f.now = f.p.ExpiresAt.Add(time.Second)
	// No previously accepted control can be installed from an expired snapshot.
	if _, status := f.b.policy(f.now); status != "policy_unavailable" {
		t.Fatal(status)
	}
}

func TestMonotonicCacheOutagesAndEvidence(t *testing.T) {
	f := newFixture(t)
	d, err := f.b.evaluate(event("s1", "one", "external"))
	if err != nil || d.Verdict != "continue" {
		t.Fatal(d, err)
	}
	var item Observation
	rec := f.b.store.state.Decisions[d.ReceiptID].Receipt
	if !ed25519.Verify(f.b.key.Public().(ed25519.PublicKey), rec.Payload, rec.Signature) || json.Unmarshal(rec.Payload, &item) != nil || !item.WouldBlock || item.SkillUsage != "unknown" || item.TargetEffect != "unknown" {
		t.Fatal("invalid receipt")
	}
	for _, pii := range []string{"external", "private-body", "fixture/path", `"s1"`} {
		if bytes.Contains(rec.Payload, []byte(pii)) {
			t.Fatal("unneeded data retained", pii)
		}
	}
	retry, err := f.b.evaluate(event("s1", "one", "external"))
	if err != nil || d != retry || len(f.b.store.state.Decisions) != 1 {
		t.Fatal("retry", retry, err)
	}
	conflict, _ := f.b.evaluate(event("s1", "one", "different"))
	if conflict.Reason != "action_id_conflict" {
		t.Fatal(conflict)
	}
	p := f.p
	p.Revision = 2
	p.Mode = "enforce"
	f.publish(t, p)
	denied, _ := f.b.evaluate(event("s2", "one", "external"))
	if denied.Verdict != "deny" {
		t.Fatal(denied)
	}
	replay, _ := f.b.evaluate(event("s1", "one", "external"))
	if replay.Verdict != "deny" || replay.Reason != "action_replayed" {
		t.Fatal(replay)
	}
	f.publish(t, f.p)
	denied, _ = f.b.evaluate(event("s3", "one", "external"))
	if denied.Verdict != "deny" {
		t.Fatal("rolled back signed policy")
	}
	if err = os.Remove(f.b.policyFile); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(f.b.store.dir, f.b.key.Seed(), f.b.binding)
	if err != nil {
		t.Fatal(err)
	}
	f.b.store = reopened
	allowed, _ := f.b.evaluate(event("s4", "one", "internal"))
	if allowed.Verdict != "continue" {
		t.Fatal(allowed)
	}
	f.now = p.ExpiresAt
	offline, _ := f.b.evaluate(event("s5", "one", "internal"))
	if offline.Verdict != "unavailable" || offline.Reason != "policy_expired" {
		t.Fatal(offline)
	}
	f.now = p.IssuedAt
	offline, _ = f.b.evaluate(event("s6", "one", "internal"))
	if offline.Reason != "policy_expired" {
		t.Fatal("clock moved backward", offline)
	}
	disk, err := os.ReadFile(filepath.Join(f.b.store.dir, "state.enc"))
	if err != nil || bytes.Contains(disk, []byte("internal")) || bytes.Contains(disk, []byte(ticketTool)) {
		t.Fatal("unencrypted state", err)
	}
	disk[0] ^= 13
	if err = os.WriteFile(filepath.Join(f.b.store.dir, "state.enc"), disk, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openStore(f.b.store.dir, f.b.key.Seed(), f.b.binding); err == nil {
		t.Fatal("corrupt store accepted")
	}
}

func TestBrokerAdmissionAndNarrowInputs(t *testing.T) {
	f := newFixture(t)
	for _, op := range []string{"export", "archive", "pre-tool", "status"} {
		if r := f.b.process(request{Operation: op, Hook: event("s", "c", "internal")}, os.Geteuid()+1); r.Error != "peer_denied" {
			t.Fatal(op, r)
		}
	}
	for _, body := range []string{
		`{"tool_name":"x","tool_name":"y"}`,
		`{"session_id":"x","session_id":"y"}{}`,
		strings.Repeat("[", 40) + strings.Repeat("]", 40),
	} {
		if _, _, err := parseHook([]byte(body)); err == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
	p := f.p
	p.Mode = "enforce"
	f.publish(t, p)
	missing := bytes.Replace(event("s", "c", "internal"), []byte(`"destination":"internal"`), []byte(`"confirmation":true`), 1)
	d, err := f.b.evaluate(missing)
	if err != nil || d.Verdict != "deny" {
		t.Fatal(d, err)
	}
	unsupported := bytes.Replace(event("s", "c", "internal"), []byte(ticketTool), []byte("OtherTool"), 1)
	d, err = f.b.evaluate(unsupported)
	if err != nil || d.Reason != "out_of_scope" || d.ReceiptID != "" {
		t.Fatal(d, err)
	}
}

func TestArchiveAndBackpressure(t *testing.T) {
	f := newFixture(t)
	d, _ := f.b.evaluate(event("s1", "one", "internal"))
	item := f.b.store.state.Decisions[d.ReceiptID]
	if err := f.b.ackArchive(map[string]string{d.ReceiptID: "wrong"}); err == nil || len(f.b.store.state.Decisions) != 1 {
		t.Fatal("lost receipt without matching signature")
	}
	if err := f.b.ackArchive(map[string]string{d.ReceiptID: signatureID(item.Receipt)}); err != nil {
		t.Fatal(err)
	}
	replayed, _ := f.b.evaluate(event("s1", "one", "internal"))
	if replayed.Reason != "action_replayed" {
		t.Fatal(replayed)
	}
	for i := 0; i < maxReceipts; i++ {
		f.b.store.state.Decisions[string(rune(i+32))] = item
	}
	p := f.p
	p.Mode = "enforce"
	p.Revision++
	f.publish(t, p)
	full, _ := f.b.evaluate(event("new", "call", "external"))
	if full.Verdict != "deny" || f.b.store.state.Gaps != 1 {
		t.Fatal(full, f.b.store.state.Gaps)
	}
	allowed, _ := f.b.evaluate(event("new", "other", "internal"))
	if allowed.Verdict != "unavailable" || allowed.Reason != "spool_full" || f.b.store.state.Gaps != 2 {
		t.Fatal(allowed)
	}
}

func TestHookWakesTransportWithoutNetworkInDecision(t *testing.T) {
	f := newFixture(t)
	f.b.syncRequested = make(chan struct{}, 1)
	for _, id := range []string{"first", "second"} {
		r := f.b.process(request{Operation: "pre-tool", Hook: event("one", id, "external")}, f.b.uid)
		if r.Error != "" || r.Decision == nil || r.Decision.Verdict != "continue" {
			t.Fatal(r)
		}
	}
	if len(f.b.syncRequested) != 1 || len(f.b.store.state.Decisions) != 2 {
		t.Fatal("background wake was lost or coupled to receipt selection")
	}
}
