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
	cfg := configuration{Binding: f.b.binding, UID: &uid, PolicyKey: f.b.policyKey, PolicyFile: f.b.policyFile, StateDir: dir, Socket: socket, SeedFile: filepath.Join(dir, "key")}
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

}
