package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

// The fixed product GETs are served by an owned test TLS endpoint; the device
// broker, signed policy, hook processes, local recorder and evidence are real.
func TestTicketWatchExecutableOnApprovedProductRun(t *testing.T) {
	f := newFixture(t)
	dir := f.b.store.dir
	c := watchConsentFixture(time.Now().UTC())
	f.p.Binding = c.Binding
	f.p.Mode = "enforce"
	var mu sync.Mutex
	runID := watchID(18)
	fired := time.Now().UTC().Add(-time.Hour)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/api/v1/devices/"+c.Binding.Device+"/policy-bundle" {
			body, _ := io.ReadAll(r.Body)
			loc, proof, err := endpointprotocol.Parse(r.Header, c.Binding.Organization, c.Binding.Workspace, c.Binding.Environment, "fetchEndpointPolicy", body, time.Now())
			if err != nil || r.Method != "GET" || loc.Binding != endpointprotocol.Binding(c.Binding) || !endpointprotocol.Verify(r.Header, f.b.key.Public().(ed25519.PublicKey), proof) || r.Header.Get("Authorization") != "Bearer test-device-private-token" {
				w.WriteHeader(403)
				return
			}
			s, _ := sign(f.p, f.signer)
			_ = json.NewEncoder(w).Encode(map[string]any{"bundle": s})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-read-only-product-token" || r.Method != "GET" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("X-Zasp-Verified-Scope", strings.Join([]string{c.Binding.Organization, c.Binding.Workspace, c.Binding.Environment}, "/"))
		switch r.URL.Path {
		case "/api/v1/tests/" + c.Definition:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": c.Definition, "version": 1, "target_id": c.Target, "target_kind": "mcp_server", "enabled": true, "safety": map[string]any{"environment": "test", "credential_class": "test_write", "expected_side_effects": []string{"synthetic_ticket_update"}}})
		case "/api/v1/tests/" + c.Definition + "/schedule":
			_ = json.NewEncoder(w).Encode(map[string]any{"definition_id": c.Definition, "version": 2, "enabled": true, "last_run_id": runID, "last_outcome": "queued", "last_fired_at": fired})
		case "/api/v1/test-runs/" + runID:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": runID, "definition_id": c.Definition, "definition_version": 1, "status": "queued", "queued_at": fired})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save := func(name string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(dir, name), raw)
	}
	sockDir, err := os.MkdirTemp("/tmp", "zw-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	uid := os.Geteuid()
	cfg := configuration{Remote: &remoteConfig{Origin: srv.URL, TokenFile: filepath.Join(dir, "device-token")}, Binding: c.Binding, UID: &uid, PolicyKey: f.b.policyKey, PolicyFile: filepath.Join(dir, "policy.json"), StateDir: dir, Socket: filepath.Join(sockDir, "sock"), SeedFile: filepath.Join(dir, "seed")}
	s, _ := sign(f.p, f.signer)
	save("policy.json", s)
	save("config.json", cfg)
	save("ticket-watch.json", c)
	write(filepath.Join(dir, "ticket-watch-schema.json"), schemaFixture(c, watchHash("a"), watchHash("f"), watchHash("c")))
	write(cfg.Remote.TokenFile, []byte("test-device-private-token"))
	write(filepath.Join(dir, "ticket-watch.read-token"), []byte("test-read-only-product-token"))
	write(cfg.SeedFile, []byte(base64.StdEncoding.EncodeToString(f.b.key.Seed())))
	ca := filepath.Join(dir, "trusted.pem")
	write(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	exe := filepath.Join(dir, "endpoint")
	if out, err := exec.Command("go", "build", "-p", "1", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build %s %v", out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cfgPath := filepath.Join(dir, "config.json")
	command := func(args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
		return cmd
	}
	daemon := command("serve", "--config", cfgPath)
	var logs bytes.Buffer
	daemon.Stderr = &logs
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = daemon.Process.Signal(syscall.SIGTERM)
		if err := daemon.Wait(); err != nil {
			t.Errorf("daemon: %v %s", err, logs.String())
		}
	}()
	for i := 0; ; i++ {
		if _, err := os.Lstat(cfg.Socket); err == nil {
			break
		}
		if i >= 300 {
			t.Fatal("device broker failed to start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	step := func(want string) watchResult {
		t.Helper()
		raw, err := command("watch-ticket", "--managed-config", cfgPath).CombinedOutput()
		var got watchResult
		if err != nil || json.Unmarshal(raw, &got) != nil || got.Status != want {
			t.Fatalf("wanted %s, got %s err %v", want, raw, err)
		}
		return got
	}
	step("baseline")
	step("already_observed")
	mu.Lock()
	f.p.Revision++
	s, _ = sign(f.p, f.signer)
	mu.Unlock()
	step("pending_local_evidence")
	save("policy.json", s)
	step("pending_approved_schedule")
	mu.Lock()
	fired = time.Now().UTC().Truncate(time.Microsecond)
	runID = watchID(19)
	mu.Unlock()
	got := step("passed")
	if got.Run != runID {
		t.Fatal("wrong authorized run")
	}
	step("already_observed")
	var bundle redteam.TicketProofBundle
	for file, dest := range map[string]any{"scenario": &bundle.Scenario, "adapter": &bundle.Adapter, "recorder": &bundle.Recorder} {
		raw, err := os.ReadFile(filepath.Join(got.Directory, file+".json"))
		if err != nil || json.Unmarshal(raw, dest) != nil {
			t.Fatal(file, err)
		}
	}
	verdict, err := redteam.VerifyTicketProof(bundle.Scenario, bundle.Adapter, bundle.Recorder, time.Now())
	if err != nil || verdict.Verdict != "passed" || verdict.RunID != runID || bundle.Scenario.PolicyRevision != "2" || len(bundle.Recorder.Writes) != 1 {
		t.Fatalf("independent result %+v err %v", verdict, err)
	}
	if err := os.Remove(filepath.Join(dir, "ticket-watch-schema.json")); err != nil {
		t.Fatal(err)
	}
	step("pending_local_evidence")
}
