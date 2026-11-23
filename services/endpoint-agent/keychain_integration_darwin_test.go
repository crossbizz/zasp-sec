//go:build darwin

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in only on the disposable hosted runner. Exercise the shipping binary's
// real System Keychain, native socket peer UID and distinct service/user roles.
func TestDisposableMacKeychainTicketHook(t *testing.T) {
	if os.Getenv("ZASP_DISPOSABLE_MAC_E2E") != "1" {
		t.Skip("requires an explicitly disposable managed test host")
	}
	exe := os.Getenv("ZASP_DISPOSABLE_MAC_BINARY")
	uid, e1 := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	gid, e2 := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32)
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || uid == 0 || !filepath.IsAbs(exe) {
		t.Fatal("run as root with a nonprivileged invoking user and an absolute test binary")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	account := fmt.Sprintf("zasp-ci-%x", nonce)
	const item = "ai.zasp.endpoint.receipt.v1"
	const chain = "/Library/Keychains/System.keychain"
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	security := func(verb string) error {
		c, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		// No password export flag. Lookup output is discarded.
		return exec.CommandContext(c, "/usr/bin/security", verb, "-s", item, "-a", account, chain).Run()
	}
	absent := func(err error) bool { var ex *exec.ExitError; return errors.As(err, &ex) && ex.ExitCode() == 44 }
	if !absent(security("find-generic-password")) {
		t.Fatal("synthetic Keychain account must be absent before creation")
	}
	t.Cleanup(func() {
		if err := security("delete-generic-password"); err != nil && !absent(err) {
			t.Errorf("remove synthetic Keychain item: %v", err)
		}
		if !absent(security("find-generic-password")) {
			t.Error("synthetic Keychain item still visible after cleanup")
		}
	})
	initKey := func() ed25519.PublicKey {
		raw, err := exec.CommandContext(ctx, exe, "init-device-key", "--account", account).Output()
		if err != nil {
			t.Fatalf("native bootstrap: %v", err)
		}
		var data struct {
			Public []byte `json:"device_public_key"`
		}
		if strictJSON(raw, &data) != nil || len(data.Public) != ed25519.PublicKeySize {
			t.Fatal("invalid public bootstrap result")
		}
		return data.Public
	}
	key := initKey()
	if !bytes.Equal(key, initKey()) {
		t.Fatal("repeat bootstrap rotated identity")
	}
	f := newFixture(t)
	p := f.p
	p.Mode = "enforce"
	f.publish(t, p)
	socketDir, err := os.MkdirTemp("/tmp", "ze-ci-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	if err = os.Chmod(socketDir, 0755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDir, "device.sock")
	allowed := int(uid)
	cfg := configuration{Adapter: "macos_claude_pretool_v2", Binding: f.b.binding, UID: &allowed, PolicyKey: f.b.policyKey, PolicyFile: f.b.policyFile, StateDir: f.b.store.dir, Socket: socket, KeychainAccount: account}
	// newFixture provisioned encrypted state using its own Linux-test seed;
	// this fresh state directory belongs to the real System Keychain identity.
	cfg.StateDir = filepath.Join(f.b.store.dir, "native-state")
	if err = os.Mkdir(cfg.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(f.b.store.dir, "native-config.json")
	writeJSON(t, config, cfg)
	cmd := exec.CommandContext(ctx, exe, "serve", "--config", config)
	var output bytes.Buffer
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if err := cmd.Wait(); err != nil {
			t.Errorf("native service: %v %s", err, output.String())
		}
	}()
	user := func(input []byte, args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, exe, append(args, "--socket", socket)...)
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
		c.Stdin = bytes.NewReader(input)
		return c.Output()
	}
	start := time.Now()
	for {
		if _, err := user(nil, "status"); err == nil {
			break
		}
		if time.Since(start) > 8*time.Second {
			t.Fatal("assigned user could not read the real service socket")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, tc := range []struct {
		id, dest string
		deny     bool
	}{{"positive", "internal", false}, {"negative", "external", true}} {
		out, err := user(event("native-session", tc.id, tc.dest), "claude-pre-tool", "--on-unavailable", "deny")
		var reply struct {
			Hook *permissionResponse `json:"hookSpecificOutput"`
		}
		if err != nil || json.Unmarshal(out, &reply) != nil || (reply.Hook != nil) != tc.deny || (reply.Hook != nil && reply.Hook.Decision != "deny") {
			t.Fatalf("unexpected %s decision: %v %s", tc.id, err, out)
		}
	}
	if _, err := user(nil, "export"); err == nil {
		t.Fatal("employee received a service-only export")
	}
	export, err := call(socket, request{Operation: "export"})
	if err != nil || len(export.Receipts) != 2 {
		t.Fatalf("service export: %v, %d receipts", err, len(export.Receipts))
	}
	for _, r := range export.Receipts {
		if !ed25519.Verify(key, r.Payload, r.Signature) {
			t.Fatal("receipt signer differs from System Keychain registration")
		}
	}
	// Upgrade this enrolled Mac in place and invoke both shipping shims as
	// the managed employee. Both continue to use the same System Keychain key.
	pre := endpointprotocol.PolicyV2{Audience: endpointprotocol.PolicyAudienceV2, Binding: endpointprotocol.Binding(f.b.binding), Revision: 2, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), Mode: "enforce", FailureMode: "closed", Rules: []endpointprotocol.PretoolRule{{ID: "native-files", Type: "file_path_policy", Values: []string{"dotenv"}}}}
	assigned, err := sign(pre, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, f.b.policyFile, assigned)
	for _, test := range []struct {
		entry, name string
		input       map[string]string
		adapter     string
	}{
		{"claude-pre-tool", "Read", map[string]string{"file_path": "~/.env"}, "macos_claude_pretool_v2"},
		{"codex-pre-tool", "apply_patch", map[string]string{"command": "*** Begin Patch\n*** Add File: .env\n+fixture\n*** End Patch"}, "macos_codex_pretool_v2"},
	} {
		event, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "native", "tool_use_id": "shared-call", "tool_name": test.name, "tool_input": test.input, "cwd": "/tmp"})
		raw, err := user(event, test.entry, "--on-unavailable", "deny")
		var response struct {
			Output *permissionResponse `json:"hookSpecificOutput"`
		}
		if err != nil || json.Unmarshal(raw, &response) != nil || response.Output == nil || !strings.Contains(response.Output.Reason, "native-files") {
			t.Fatalf("native v2 decision missing for %s", test.entry)
		}
		export, err = call(socket, request{Operation: "export"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rec := range export.Receipts {
			if obs, ok := (endpointprotocol.Signed(rec)).ObservationV2For(key, pre.Binding, time.Now()); ok && obs.Adapter == test.adapter && obs.RuleID == "native-files" && obs.Verdict == "deny" {
				found = true
			}
		}
		if !found {
			t.Fatalf("no authentic native v2 receipt for %s", test.entry)
		}
	}
}
