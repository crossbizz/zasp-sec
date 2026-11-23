//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

// Runs the compiled program as both daemon and managed hook. An independent
// target records synthetic writes after the harness applies the hook response.
func TestExecutableTicketControl(t *testing.T) {
	f := newFixture(t)
	dir := f.b.store.dir
	exe := filepath.Join(dir, "zasp-endpoint")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	// AF_UNIX has a fixed pathname bound independently of the runner's
	// scratch path and the length of its test name.
	socketDir, err := os.MkdirTemp("/tmp", "ze-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "agent.sock")
	uid := os.Geteuid()
	cfg := configuration{Adapter: "linux_claude_pretool_v2_test", Binding: f.b.binding, UID: &uid, PolicyKey: f.b.policyKey, PolicyFile: f.b.policyFile, StateDir: dir, Socket: socket, SeedFile: filepath.Join(dir, "key")}
	if err := os.WriteFile(cfg.SeedFile, []byte(base64.StdEncoding.EncodeToString(f.b.key.Seed())), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	writeJSON(t, config, cfg)
	if _, err := loadConfig(config); err != nil {
		t.Fatalf("fixture failed daemon configuration validation: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "serve", "--config", config)
	var log bytes.Buffer
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if err := cmd.Wait(); err != nil {
			t.Errorf("daemon: %v %s", err, log.String())
		}
	}()
	for i := 0; ; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if i >= 300 {
			t.Fatal("socket startup timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	invoke := func(session, id, target string) (bool, error) {
		h := exec.CommandContext(ctx, exe, "claude-pre-tool", "--socket", socket, "--on-unavailable", "deny")
		h.Stdin = bytes.NewReader(event(session, id, target))
		raw, err := h.Output()
		if err != nil {
			return false, err
		}
		var parsed struct {
			Output *permissionResponse `json:"hookSpecificOutput"`
		}
		err = json.Unmarshal(raw, &parsed)
		if err != nil {
			return false, err
		}
		if parsed.Output != nil && (parsed.Output.Event != "PreToolUse" || parsed.Output.Decision != "deny") {
			return false, errInvalid
		}
		return parsed.Output == nil, nil
	}
	path := filepath.Join(dir, "ticket-receipts")
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, e := io.ReadAll(io.LimitReader(r.Body, 32))
		if e != nil {
			http.Error(w, "invalid", 400)
			return
		}
		file, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if e != nil {
			http.Error(w, "failed", 500)
			return
		}
		_, err := file.Write(append(id, '\n'))
		if err == nil {
			err = file.Sync()
		}
		_ = file.Close()
		if err != nil {
			http.Error(w, "failed", 500)
			return
		}
		w.WriteHeader(204)
	}))
	defer httpTarget.Close()
	dispatch := func(session, id, target string) {
		allow, err := invoke(session, id, target)
		if err != nil {
			t.Error(err)
			return
		}
		if allow {
			resp, err := http.Post(httpTarget.URL, "text/plain", bytes.NewBufferString(id))
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 204 {
				t.Error(resp.Status)
			}
		}
	}
	dispatch("monitor-session", "monitor", "external")
	p := f.p
	p.Mode = "enforce"
	p.Revision = 2
	f.publish(t, p)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); dispatch("allowed-session", "allowed", "internal") }()
	go func() { defer wg.Done(); dispatch("blocked-session", "blocked", "external") }()
	wg.Wait()
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "monitor\nallowed\n" {
		t.Fatalf("target receipts %s: %v", raw, err)
	}
	resp, err := call(socket, request{Operation: "status"})
	if err != nil || resp.Status == nil || resp.Status.Revision != 2 || resp.Status.Queued != 3 {
		t.Fatal(resp, err)
	}
	r, err := call(socket, request{Operation: "export"})
	if err != nil || len(r.Receipts) != 3 {
		t.Fatal(r, err)
	}
	seen := map[string]int{}
	for _, rec := range r.Receipts {
		var obs Observation
		if !ed25519.Verify(f.b.key.Public().(ed25519.PublicKey), rec.Payload, rec.Signature) || strictJSON(rec.Payload, &obs) != nil {
			t.Fatal("bad receipt")
		}
		seen[obs.Mode+"/"+obs.Verdict]++
	}
	for _, key := range []string{"monitor/continue", "enforce/continue", "enforce/deny"} {
		if seen[key] != 1 {
			t.Fatal(seen)
		}
	}
	dst := filepath.Join(dir, "archive.json")
	if out, err := exec.CommandContext(ctx, exe, "archive", "--socket", socket, "--out", dst).CombinedOutput(); err != nil {
		t.Fatalf("archive: %v %s", err, out)
	}
	resp, err = call(socket, request{Operation: "status"})
	if err != nil || resp.Status.Queued != 0 {
		t.Fatal("archive failed", resp, err)
	}
	// A newer verified revision restores the prior mode. Read back the
	// independent recorder after dispatching the previously restricted class.
	p.Revision++
	p.Mode = "monitor"
	f.publish(t, p)
	dispatch("restored-session", "restored", "external")
	raw, err = os.ReadFile(path)
	if err != nil || string(raw) != "monitor\nallowed\nrestored\n" {
		t.Fatalf("rollback target receipts %q: %v", raw, err)
	}
	resp, err = call(socket, request{Operation: "status"})
	if err != nil || resp.Status == nil || resp.Status.Revision != 3 || resp.Status.Mode != "monitor" {
		t.Fatal("rollback acknowledgement", resp, err)
	}

	t.Run("normal isolated proof command", func(t *testing.T) {
		out := filepath.Join(dir, "standalone-proof")
		c := exec.CommandContext(ctx, exe, "prove-ticket", "--out", out, "--window", "2s")
		raw, err := c.CombinedOutput()
		var verdict redteam.TicketVerification
		if err != nil || json.Unmarshal(raw, &verdict) != nil || verdict.Verdict != "passed" {
			t.Fatalf("produce: %v %s", err, raw)
		}
		var bundle redteam.TicketProofBundle
		for name, dst := range map[string]any{"scenario": &bundle.Scenario, "adapter": &bundle.Adapter, "recorder": &bundle.Recorder} {
			raw, err = os.ReadFile(filepath.Join(out, name+".json"))
			if err != nil || redteam.DecodeTicketExport(raw, dst) != nil {
				t.Fatalf("invalid %s", name)
			}
		}
		if !bundle.Archivable() || bundle.Scenario.AdapterID != "isolated_linux_ticket_fixture" || len(bundle.Recorder.Writes) != 1 || bundle.Recorder.Writes[0].ActionID != bundle.Scenario.ControlActionID {
			t.Fatal("incorrect fixture evidence")
		}
		v, e := redteam.VerifyTicketProof(bundle.Scenario, bundle.Adapter, bundle.Recorder, time.Now())
		if e != nil || v != verdict {
			t.Fatal("independent verification differs", v, e)
		}
		var source struct {
			Key      []byte   `json:"device_public_key"`
			Receipts []Signed `json:"receipts"`
		}
		raw, err = os.ReadFile(filepath.Join(out, "device-receipts.json"))
		if err != nil || json.Unmarshal(raw, &source) != nil || len(source.Receipts) != 2 {
			t.Fatal("missing two raw source receipts")
		}
		sessions := map[string]bool{}
		for _, receipt := range source.Receipts {
			var actual Observation
			if !ed25519.Verify(source.Key, receipt.Payload, receipt.Signature) || strictJSON(receipt.Payload, &actual) != nil {
				t.Fatal("invalid source signature")
			}
			sessions[actual.Session] = true
		}
		if len(sessions) != 2 {
			t.Fatal("proof reused one session")
		}
		if exec.CommandContext(ctx, exe, "prove-ticket", "--out", out).Run() == nil {
			t.Fatal("previous proof overwritten")
		}
		if exec.CommandContext(ctx, exe, "prove-ticket", "--out", filepath.Join(dir, "misbound"), "--run-id", bundle.Scenario.RunID).Run() == nil {
			t.Fatal("isolated fixture accepted a product identity")
		}
	})

	t.Run("signed_pretool_codex_and_claude_shims", func(t *testing.T) {
		pre := endpointprotocol.PolicyV2{Audience: endpointprotocol.PolicyAudienceV2, Binding: endpointprotocol.Binding(f.b.binding), Revision: 4, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), Mode: "enforce", FailureMode: "closed", Rules: []endpointprotocol.PretoolRule{{ID: "private-config", Type: "file_path_policy", Values: []string{"dotenv"}}}}
		assigned, e := sign(pre, f.signer)
		if e != nil {
			t.Fatal(e)
		}
		writeJSON(t, f.b.policyFile, assigned)
		inputs := []struct {
			entry, tool string
			args        map[string]string
		}{
			{"codex-pre-tool", "apply_patch", map[string]string{"command": "*** Begin Patch\n*** Add File: .env\n+fixture\n*** End Patch"}},
			{"claude-pre-tool", "Read", map[string]string{"file_path": "~/.env"}},
		}
		for _, in := range inputs {
			c := exec.CommandContext(ctx, exe, in.entry, "--socket", socket, "--on-unavailable", "deny")
			raw, _ := json.Marshal(map[string]any{"session_id": "v2-shim", "hook_event_name": "PreToolUse", "tool_use_id": in.tool, "cwd": dir, "tool_name": in.tool, "tool_input": in.args})
			c.Stdin = bytes.NewReader(raw)
			out, e := c.Output()
			var reply struct {
				Hook *permissionResponse `json:"hookSpecificOutput"`
			}
			if e != nil || json.Unmarshal(out, &reply) != nil || reply.Hook == nil || reply.Hook.Decision != "deny" || !bytes.Contains(out, []byte("private-config")) {
				t.Fatalf("%s failed: %s %v", in.entry, out, e)
			}
			var reason struct {
				Action string `json:"action_id"`
				Rule   string `json:"rule_id"`
				Rev    int    `json:"policy_revision"`
				Code   string `json:"reason_code"`
				Hint   string `json:"next_step_hint"`
			}
			if json.Unmarshal([]byte(reply.Hook.Reason), &reason) != nil || !endpointprotocol.Digest.MatchString(reason.Action) || reason.Rule != "private-config" || reason.Rev != 4 || reason.Code != "dotenv" || reason.Hint != "review_endpoint_policy" {
				t.Fatalf("structured decision missing for %s", in.entry)
			}
		}
		captured, e := call(socket, request{Operation: "export"})
		if e != nil {
			t.Fatal(e)
		}
		n := 0
		for _, rec := range captured.Receipts {
			if o, ok := (endpointprotocol.Signed(rec)).ObservationV2For(f.b.key.Public().(ed25519.PublicKey), pre.Binding, time.Now()); ok && o.RuleID == "private-config" && o.TargetEffect == "unknown" {
				n++
			}
		}
		if n != 2 {
			t.Fatalf("verified V2 receipts=%d", n)
		}
	})

}
