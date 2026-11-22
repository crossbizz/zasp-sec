package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

// Drive the actual endpoint synchronizer through tenant-authorized HTTP and the
// installed product database. The test listener supplies only routing and TLS.
func exerciseInstalledEndpoint(t *testing.T, b *installedBaseline, h http.Handler, repo *PostgresRepository, binding endpointprotocol.Binding, key ed25519.PrivateKey, issuer ed25519.PublicKey, rawPAT string, admin installedPrincipal) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("managed Mac needs a provisioned System Keychain identity")
	}
	dir, err := os.MkdirTemp("/tmp", "zasp-fleet-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	exe := filepath.Join(dir, "endpoint")
	module := filepath.Join("..", "..", "endpoint-agent")
	if out, err := exec.Command("go", "-C", module, "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	base := "/api/v1/devices/" + binding.Device
	// Queue an approved staging definition, drive the real supervisor against
	// the currently enrolled broker, then import the three unedited files.
	runID, target, definition := b.id(), b.id(), b.id()
	class := b.text("SELECT environment_class FROM public.zasp_environments WHERE id=$1", b.e)
	if class != "test" && class != "staging" {
		t.Fatal("expected disposable staging or test Environment", class)
	}
	b.seed(func() {
		b.exec(`INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Supervised ticket proof',$5,'agent_endpoint','["tool_abuse"]',jsonb_build_object('environment',$7::text,'credential_class','test_write','expected_side_effects',jsonb_build_array('synthetic_ticket_update')),$6)`, b.o, b.w, b.e, definition, target, admin.identity.PrincipalID.String(), class)
		b.exec(`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest,queued_at) VALUES($1,$2,$3,$4,$5,1,$6,decode(repeat('cd',32),'hex'),clock_timestamp())`, b.o, b.w, b.e, runID, definition, admin.identity.PrincipalID.String())
	})
	// Installed authorization fixtures keep one pgx connection per service
	// login. Serialize test-harness database calls across HTTP and the operator.
	var dbMu sync.Mutex
	queryCount := func(query string, args ...any) string {
		dbMu.Lock()
		defer dbMu.Unlock()
		return b.text(query, args...)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dbMu.Lock()
		defer dbMu.Unlock()
		header := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		i, err := repo.Authenticate(r.Context(), Credential{Kind: CredentialBearerToken, Value: header})
		if err != nil {
			t.Errorf("compiled endpoint PAT rejected: %v", err)
			http.Error(w, "unauthorized", 401)
			return
		}
		routes := map[string]string{"/api/v1/device-enrollments/exchange": "exchangeEndpointEnrollment", base + "/policy-bundle": "fetchEndpointPolicy", base + "/heartbeat": "recordEndpointHeartbeat", "/api/v1/runtime/observations": "recordEndpointObservations", base + "/inventory-snapshots": "recordEndpointInventory"}
		op, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		args := map[string]string{}
		if strings.HasPrefix(r.URL.Path, base+"/") {
			args["id"] = binding.Device
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		headers := map[string]string{}
		for _, name := range []string{"X-Zasp-Device-Proof", "X-Zasp-Device-Signature"} {
			headers[name] = r.Header.Get(name)
		}
		res := b.serve(h, installedPrincipal{identity: i, binding: i.credentialBinding}, op, r.Method, r.URL.Path, args, string(raw), headers)
		if res.Code != 200 {
			t.Logf("%s returned %d: %s", op, res.Code, res.Body.String())
		}
		t.Logf("endpoint operation %s, HTTP %d", op, res.Code)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.Code)
		_, _ = w.Write(res.Body.Bytes())
	}))
	defer server.Close()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	cert, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ca := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	socket := filepath.Join(dir, "endpoint.sock")
	cfg := map[string]any{"binding": binding, "allowed_uid": os.Geteuid(), "policy_public_key": []byte(issuer), "policy_file": filepath.Join(dir, "optional-mdm-policy.json"), "state_dir": dir, "socket": socket, "seed_file": write("seed", []byte(base64.StdEncoding.EncodeToString(key.Seed()))), "control_plane": map[string]any{"origin": server.URL, "token_file": write("pat", []byte(rawPAT)), "inventory_enabled": true}}
	cfgBytes, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	configPath := write("endpoint.json", cfgBytes)
	cmd := exec.CommandContext(ctx, exe, "serve", "--config", configPath)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
	var serviceLog bytes.Buffer
	cmd.Stderr = &serviceLog
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if e := cmd.Wait(); e != nil {
			t.Errorf("endpoint exit: %v %s", e, serviceLog.String())
		}
	}()
	run := func(stdin string, args ...string) ([]byte, error) {
		c := exec.CommandContext(ctx, exe, append(args, "--socket", socket)...)
		c.Stdin = strings.NewReader(stdin)
		return c.CombinedOutput()
	}
	await := func(rev, queued int) {
		t.Helper()
		limit := time.Now().Add(90 * time.Second)
		var last []byte
		for time.Now().Before(limit) {
			raw, _ := run("", "status")
			last = raw
			var report struct {
				Status struct {
					Rev    int    `json:"policy_revision"`
					Queued int    `json:"queued_receipts"`
					Remote string `json:"remote_state"`
				}
			}
			if json.Unmarshal(raw, &report) == nil && report.Status.Remote == "connected" && report.Status.Rev == rev && report.Status.Queued == queued {
				return
			}
			time.Sleep(35 * time.Millisecond)
		}
		t.Fatalf("endpoint did not acknowledge revision/queue: %s", last)
	}
	await(2, 0)
	targetWrites := 0
	for _, c := range []struct {
		id, dest string
		deny     bool
	}{{"binary-allowed", "internal", false}, {"binary-denied", "external", true}} {
		body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "binary-session-" + c.id, "tool_use_id": c.id, "tool_name": endpointprotocol.TicketTool, "tool_input": map[string]string{"destination": c.dest}})
		out, e := run(string(body), "claude-pre-tool", "--on-unavailable", "deny")
		if e != nil {
			t.Fatal(e)
		}
		var result struct {
			Hook *struct {
				Decision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		}
		if e = json.Unmarshal(out, &result); e != nil || (result.Hook != nil) != c.deny || (result.Hook != nil && result.Hook.Decision != "deny") {
			t.Fatalf("unexpected hook response: %s", out)
		}
		if result.Hook == nil {
			targetWrites++
		}
	}
	if targetWrites != 1 {
		t.Fatal("wrong permitted action count")
	}
	await(2, 0)
	if count := queryCount("SELECT count(*)::text FROM public.zasp_endpoint_observations WHERE device_id=$1 AND observation->>'policy_revision'='2'", binding.Device); count != "2" {
		t.Fatal("server did not retain both real adapter receipts", count)
	}
	outDir := filepath.Join(dir, "ticket-proof")
	producer := exec.CommandContext(ctx, exe, "prove-ticket", "--managed-config", configPath, "--out", outDir, "--run-id", runID, "--target-id", target, "--cohort", "pilot", "--environment-class", class, "--window", "5s")
	if out, err := producer.CombinedOutput(); err != nil {
		t.Fatalf("ticket producer: %v %s", err, out)
	}
	var bundle redteam.TicketProofBundle
	for name, dst := range map[string]any{"scenario": &bundle.Scenario, "adapter": &bundle.Adapter, "recorder": &bundle.Recorder} {
		raw, err := os.ReadFile(filepath.Join(outDir, name+".json"))
		if err != nil || redteam.DecodeTicketExport(raw, dst) != nil {
			t.Fatalf("unreadable real %s export", name)
		}
	}
	if !bundle.Archivable() || bundle.Scenario.AdapterID != "linux_claude_ticket_test" || bundle.Scenario.PolicyRevision != "2" || bundle.Scenario.CohortID != "pilot" {
		t.Fatal("unexpected supervisor binding")
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	imported := func() *httptest.ResponseRecorder {
		dbMu.Lock()
		defer dbMu.Unlock()
		return b.serve(&discoveryWorkflowSurface{evidenceDB: b.product}, admin, "putTicketVerification", "PUT", "/api/v1/test-runs/"+runID+"/ticket-verification", map[string]string{"id": runID}, string(payload), nil)
	}()
	var stored struct {
		Source string                     `json:"evidence_source"`
		Result redteam.TicketVerification `json:"result"`
	}
	if imported.Code != 200 || json.Unmarshal(imported.Body.Bytes(), &stored) != nil || stored.Source != "operator_import" || stored.Result.Verdict != "passed" || stored.Result.RunID != runID {
		t.Fatalf("imported producer result: %d %s", imported.Code, imported.Body)
	}
	await(2, 0)
	if count := queryCount("SELECT count(*)::text FROM public.zasp_endpoint_observations WHERE device_id=$1 AND action_id IN ($2,$3)", binding.Device, bundle.Scenario.ControlActionID, bundle.Scenario.ProtectedActionID); count != "2" {
		t.Fatal("proof action IDs do not join actual enrolled observations", count)
	}

}
