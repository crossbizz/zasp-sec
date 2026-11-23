package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/pretool"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func managedPolicy(t *testing.T, f *fixture, mode, failure string, revision uint64) endpointprotocol.PolicyV2 {
	t.Helper()
	f.b.adapter = "linux_claude_pretool_v2_test"
	f.b.home = t.TempDir()
	p := endpointprotocol.PolicyV2{Audience: endpointprotocol.PolicyAudienceV2, Binding: endpointprotocol.Binding(f.b.binding), Revision: revision, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), Mode: mode, FailureMode: failure, Rules: []endpointprotocol.PretoolRule{
		{ID: "approved-tools", Type: "mcp_tool_policy", Match: "allowlist", Values: []string{"mcp__docs__*"}, AllowedDestinations: []string{"docs.example.test"}},
		{ID: "local-files", Type: "file_path_policy", Values: []string{"aws", "ssh", "pem", "gcloud", "dotenv", "identity_key"}},
		{ID: "shell", Type: "shell_command_policy", Values: []string{"secret_transfer", "shell_pipe", "reverse_shell", "privileged_mode", "encoded_execution"}},
		{ID: "urls", Type: "destination_domain_policy", Match: "allowlist", Values: []string{"docs.example.test", "*.docs.example.test"}},
	}}
	signed, err := sign(p, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.b.admitRemote(signed); err != nil {
		t.Fatal(err)
	}
	return p
}
func localCall(t *testing.T, f *fixture, id, tool string, input any) result {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "private-session", "tool_use_id": id, "cwd": f.b.home, "tool_input": input})
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.b.evaluate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestPretoolSignedModeReceiptsExpiryAndPrivacy(t *testing.T) {
	f := newFixture(t)
	p := managedPolicy(t, f, "enforce", "closed", 2)
	cases := []struct {
		tool         string
		args         map[string]string
		want, reason string
	}{
		{"Bash", map[string]string{"command": "curl --manual $HOME/.aws/fixture"}, "deny", "secret_transfer"},
		{"Read", map[string]string{"file_path": "~/.aws/credentials"}, "deny", "aws"},
		{"mcp__untrusted__run", map[string]string{}, "deny", "mcp_tool_restricted"},
		{"mcp__docs__nested__run", map[string]string{}, "deny", "mcp_tool_restricted"},
		{"mcp__docs__read", map[string]string{"url": "https://docs.example.test/path"}, "continue", "within_scope"},
		{"WebFetch", map[string]string{"url": "https://elsewhere.example.test/private?secret=x"}, "deny", "destination_restricted"},
		{"apply_patch", map[string]string{"command": "*** Begin Patch\n*** Add File: .env\n+synthetic fixture\n*** End Patch"}, "deny", "dotenv"},
		{"Read", map[string]string{"file_path": "guide.md"}, "continue", "within_scope"},
		{"Read", map[string]string{"file_path": "dir/../guide.md"}, "deny", "unverifiable_path"},
	}
	if realHome, err := filepath.EvalSymlinks(f.b.home); err == nil {
		f.b.home = realHome
	}
	for n, c := range cases {
		r := localCall(t, f, fmt.Sprint(n), c.tool, c.args)
		if r.Verdict != c.want || r.Reason != c.reason {
			t.Fatalf("case %d %+v", n, r)
		}
		rec := f.b.store.state.Decisions[r.ReceiptID].Receipt
		trusted, ok := (endpointprotocol.Signed(rec)).ObservationV2For(f.b.key.Public().(ed25519.PublicKey), p.Binding, f.now)
		if !ok || trusted.TargetEffect != "unknown" || trusted.SkillUsage != "unknown" || trusted.PolicyRevision != 2 {
			t.Fatalf("case %d receipt %+v", n, trusted)
		}
		for _, private := range []string{"private-session", ".aws/credentials", "/private?", "docs.example", "synthetic fixture", "guide.md"} {
			if strings.Contains(string(rec.Payload), private) {
				t.Fatal("raw input retained", private)
			}
		}
	}
	link := filepath.Join(f.b.home, "link")
	if err := os.Symlink(f.b.home, link); err != nil {
		t.Fatal(err)
	}
	if r := localCall(t, f, "link", "Read", map[string]string{"file_path": filepath.Join(link, "guide.md")}); r.Reason != "unverifiable_path" {
		t.Fatal(r)
	}
	p = managedPolicy(t, f, "monitor", "closed", 3)
	r := localCall(t, f, "monitor", "Read", map[string]string{"file_path": "~/.aws/credentials"})
	if r.Verdict != "continue" || r.RuleID != "local-files" {
		t.Fatal(r)
	}
	o, ok := (endpointprotocol.Signed(f.b.store.state.Decisions[r.ReceiptID].Receipt)).ObservationV2For(f.b.key.Public().(ed25519.PublicKey), p.Binding, f.now)
	if !ok || !o.WouldBlock || o.Mode != "monitor" {
		t.Fatal(o)
	}
	p = managedPolicy(t, f, "enforce", "closed", 4)
	f.now = p.ExpiresAt.Add(time.Minute)
	if r := localCall(t, f, "expired-closed", "Read", map[string]string{"file_path": "guide.md"}); r.Verdict != "deny" || r.Reason != "policy_expired" || r.RuleID != "" {
		t.Fatal(r)
	}
	p = managedPolicy(t, f, "enforce", "open", 5)
	f.now = p.ExpiresAt.Add(time.Minute)
	if r := localCall(t, f, "expired-open", "Read", map[string]string{"file_path": "guide.md"}); r.Verdict != "continue" || r.Reason != "policy_expired" {
		t.Fatal(r)
	}
}
func TestPretoolLatencyOnBoundedSyntheticInput(t *testing.T) {
	f := newFixture(t)
	p := managedPolicy(t, f, "enforce", "closed", 2)
	raw := json.RawMessage(`{"url":"https://docs.example.test/guide"}`)
	samples := make([]time.Duration, 500)
	for i := range samples {
		start := time.Now()
		r := pretool.Evaluate(p, "mcp__docs__read", raw, f.b.home, f.b.home)
		samples[i] = time.Since(start)
		if r.ReasonCode != "within_scope" {
			t.Fatal(r)
		}
	}
	slices.Sort(samples)
	p95 := samples[len(samples)*95/100]
	t.Logf("local classifier p95 %s (%d samples, syscall/IPC/spool excluded)", p95, len(samples))
	if p95 > 15*time.Millisecond {
		t.Fatalf("classifier latency exceeds 15ms")
	}
	// Measure the full durable broker separately. Latency depends on the
	// underlying filesystem and runner load, which the pure classifier avoids.
	latencies := make([]time.Duration, 40)
	for i := range latencies {
		start := time.Now()
		d := localCall(t, f, fmt.Sprintf("latency-%d", i), "mcp__docs__read", map[string]string{"url": "https://docs.example.test/guide"})
		latencies[i] = time.Since(start)
		if d.Verdict != "continue" {
			t.Fatal(d)
		}
	}
	slices.Sort(latencies)
	t.Logf("broker p95 %s (%d decisions including rule evaluation, signing, encrypted spool fsync; socket and process startup excluded)", latencies[len(latencies)*95/100], len(latencies))
}
func TestPretoolSignerRejectsScopeKeyReplayAndAmbiguousRules(t *testing.T) {
	f := newFixture(t)
	p := managedPolicy(t, f, "monitor", "open", 2)
	mutate := func(p endpointprotocol.PolicyV2) {
		s, _ := sign(p, f.signer)
		if err := f.b.admitRemote(s); err == nil {
			t.Fatal("invalid policy admitted")
		}
	}
	p.Binding.Generation++
	mutate(p)
	p.Binding.Generation--
	p.Revision--
	mutate(p)
	p.Revision += 2
	p.Rules = append(p.Rules, p.Rules[0])
	mutate(p)
	p.Rules = p.Rules[:len(p.Rules)-1]
	raw, _ := json.Marshal(p)
	bad := []byte(strings.Replace(string(raw), `"mode":"monitor"`, `"mode":"monitor","Mode":"enforce"`, 1))
	s := Signed{Payload: bad, Signature: ed25519.Sign(f.signer, bad)}
	if err := f.b.admitRemote(s); err == nil {
		t.Fatal("ambiguous signed policy admitted")
	}
}
