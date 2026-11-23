//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/windowsinventory"
	"github.com/zasp-ai/zasp-sec/services/platform/delegation"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
	"golang.org/x/sys/windows"
)

var nativePipeDir = flag.String("zasp-test-pipe-root", "", "private disposable native Windows test root")
var nativePipeRole = flag.String("zasp-test-pipe-role", "", "system or employee integration participant")

func TestHookFallbackAndCacheHeartbeat(t *testing.T) {
	for _, closed := range []bool{false, true} {
		var out bytes.Buffer
		if err := pipeHook(`\\.\pipe\zasp-never-created-`+t.Name(), closed, strings.NewReader("{}"), &out); err != nil || strings.Contains(out.String(), `"deny"`) != closed {
			t.Fatalf("fallback %t: %v %s", closed, err, out.String())
		}
	}
	for _, h := range []*brokerHealth{nil, {Broker: "unavailable", PolicyStatus: "state_unavailable"}, {Broker: "responding", PolicyStatus: "verified_cache", Revision: 4, Queued: 256, Gaps: 1}} {
		beat := windowsBeat(h)
		if !beat.Valid() || (h == nil) != (beat.Adapter == "windows_inventory") {
			t.Fatalf("bad heartbeat %#v", beat)
		}
	}
}

func TestWindowsTaskGrantFrameUsesDeviceBindingAndActualHook(t *testing.T) {
	raw, err := os.ReadFile("../../../../sdks/fixtures/task-delegation.json")
	if err != nil {
		t.Fatal(err)
	}
	var grant struct {
		Verifier delegation.Verifier
		Token    string
		Issued   int64 `json:"issued_at"`
	}
	if err := json.Unmarshal(raw, &grant); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(grant.Issued, 0)
	binding := endpointprotocol.Binding{Organization: grant.Verifier.Organization, Workspace: grant.Verifier.Workspace, Environment: grant.Verifier.Environment}
	hook := json.RawMessage(`{"hook_event_name":"PreToolUse","session_id":"session","tool_use_id":"call","tool_name":"mcp__pilot__update_ticket","tool_input":{"destination":"internal"}}`)
	wrap := func(h json.RawMessage, token string) []byte {
		t.Helper()
		body, err := json.Marshal(delegatedHook{Hook: h, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(delegationFrame), body...)
	}
	for _, tc := range []struct {
		raw  []byte
		at   time.Time
		want bool
	}{
		{wrap(hook, grant.Token), now, true},
		{wrap(hook, ""), now, false},
		{hook, now, false},
		{wrap(bytes.ReplaceAll(hook, []byte("internal"), []byte("external")), grant.Token), now, false},
		{wrap(hook, grant.Token), now.Add(5 * time.Minute), false},
	} {
		if _, allowed := checkDelegatedHook(binding, &grant.Verifier, tc.raw, tc.at); allowed != tc.want {
			t.Fatalf("delegated frame allowed = %t, want %t", allowed, tc.want)
		}
	}
	binding.Environment = "elsewhere"
	if _, allowed := checkDelegatedHook(binding, &grant.Verifier, wrap(hook, grant.Token), now); allowed {
		t.Fatal("cross-environment frame admitted")
	}
	t.Setenv("ZASP_TASK_DELEGATION", "")
	var out bytes.Buffer
	if err := managedPipeHook(pipeName+"-unavailable", false, true, bytes.NewReader(hook), &out); err != nil || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatal("mandatory hook did not deny an unavailable grant")
	}
}

func fixtureEvent(tool string) []byte {
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "synthetic-session", "tool_use_id": "synthetic-call", "cwd": `C:\ZaspFixture`, "tool_name": tool, "tool_input": map[string]string{"note": "local-only-inert"}})
	return raw
}
func writeFixturePolicy(t *testing.T, root string, c windowsinventory.Config, issuer ed25519.PrivateKey, mode, failure string, expired bool) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	stop := now.Add(time.Hour)
	if expired {
		stop = now.Add(-time.Minute)
	}
	p := endpointprotocol.PolicyV2{Audience: endpointprotocol.PolicyAudienceV2, Binding: c.Binding, Revision: 2, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: stop, Mode: mode, FailureMode: failure, Rules: []endpointprotocol.PretoolRule{{ID: "synthetic.read", Type: "mcp_tool_policy", Match: "allowlist", Values: []string{"mcp__fixture__read"}}}}
	raw, _ := json.Marshal(p)
	envelope, _ := json.Marshal(endpointprotocol.Signed{Payload: raw, Signature: ed25519.Sign(issuer, raw)})
	if err := storeSecret(root, "pretool-policy.dpapi", envelope); err != nil {
		t.Fatal(err)
	}
}

func TestNativeManagedPretoolPipe(t *testing.T) {
	root := *nativePipeDir
	if root == "" {
		t.Skip("invoked by the native SYSTEM and employee fixture")
	}
	base := filepath.Base(root)
	if !strings.HasPrefix(base, "ZaspBrokerTest-") {
		t.Fatal("invalid fixture")
	}
	name := `\\.\pipe\` + base
	if *nativePipeRole == "employee" {
		if system() {
			t.Fatal("expected non-System employee token")
		}
		// Readiness marker is emitted by SYSTEM after preparing its keys. Retry
		// the first connection since pipe creation immediately follows the marker.
		until := time.Now().Add(15 * time.Second)
		var reply []byte
		var err error
		for time.Now().Before(until) {
			reply, err = exchangePipe(name, fixtureEvent("mcp__fixture__read"))
			if err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil || string(reply) != "{}" {
			t.Fatalf("assigned SID control: %s %v", reply, err)
		}
		reply, err = exchangePipe(name, fixtureEvent("mcp__fixture__write"))
		if err != nil || !bytes.Contains(reply, []byte(`"permissionDecision":"deny"`)) {
			t.Fatalf("assigned SID denied decision: %s %v", reply, err)
		}
		if _, err = exchangePipe(name, []byte(probeRequest)); err == nil {
			t.Fatal("employee obtained SYSTEM-only health attestation")
		}
		ptr, _ := windows.UTF16PtrFromString(name + "-unassigned")
		h, e := windows.CreateFile(ptr, pipeAccess, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if e == nil {
			windows.CloseHandle(h)
			t.Fatal("different SID connected")
		}
		if e != windows.ERROR_ACCESS_DENIED {
			t.Fatalf("expected DACL denial, got %v", e)
		}
		if err := os.WriteFile(filepath.Join(root, "employee.done"), []byte("done"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if *nativePipeRole != "system" || !system() {
		t.Fatal("expected LocalSystem")
	}
	// The parent script has restricted this ephemeral Program Files location.
	directory, err := checked(root, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	sid, err := read(filepath.Join(root, "employee.sid"), 512, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := windowsinventory.Config{Origin: "https://fixture.invalid", Binding: endpointprotocol.Binding{Organization: "org", Workspace: "workspace", Environment: "stage", Device: "device", Generation: 1}, AssignedSID: strings.TrimSpace(string(sid)), Scope: "managed"}
	issuerPub, issuer, _ := ed25519.GenerateKey(rand.Reader)
	devicePub, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg := pretoolConfig{Public: issuerPub, Home: `C:\ZaspHome`, Workspace: `C:\ZaspFixture`}
	writeCfg := func(pub []byte) {
		value := cfg
		value.Public = pub
		raw, _ := json.Marshal(value)
		if e := os.WriteFile(filepath.Join(root, "pretool.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeCfg(devicePub)
	if _, err := pretoolConfigAt(root, key); err == nil {
		t.Fatal("device key admitted as policy issuer")
	}
	writeCfg(issuerPub)
	if _, err := pretoolConfigAt(root, key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode, failure string
		expired, deny bool
	}{
		{"monitor", "closed", false, false}, {"enforce", "closed", true, true}, {"enforce", "open", true, false}, {"monitor", "closed", true, false},
	} {
		writeFixturePolicy(t, root, c, issuer, tc.mode, tc.failure, tc.expired)
		out, e := decidePretool(root, c, cfg, key, fixtureEvent("mcp__fixture__write"))
		if e != nil || bytes.Contains(out, []byte(`"permissionDecision":"deny"`)) != tc.deny {
			t.Fatalf("result for %#v: %v %s", tc, e, out)
		}
	}
	writeFixturePolicy(t, root, c, issuer, "enforce", "closed", false)
	other, _ := windows.StringToSid("S-1-5-21-1-2-3-9911")
	restricted, e := newPipe(name+"-unassigned", other)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(restricted)
	serverExited := make(chan error, 1)
	go func() { serverExited <- servePretool(root, c, cfg, key, name) }()
	failAt := time.Now().Add(55 * time.Second)
	for {
		select {
		case err := <-serverExited:
			t.Fatalf("SYSTEM broker stopped: %v", err)
		default:
		}
		data, e := os.ReadFile(filepath.Join(root, "employee.done"))
		if e == nil && string(data) == "done" {
			break
		}
		if time.Now().After(failAt) {
			t.Fatal("employee handshake timed out")
		}
		time.Sleep(50 * time.Millisecond)
	}
	probe, e := exchangePipe(name, []byte(probeRequest))
	if e != nil || !bytes.Equal(probe, brokerIdentity(c, cfg, key)) {
		t.Fatalf("SYSTEM health probe: %v", e)
	}
	entries, e := os.ReadDir(filepath.Join(root, "pretool-receipts"))
	if e != nil || len(entries) != 6 {
		t.Fatalf("want six durable receipts, got %d: %v", len(entries), e)
	}
	var ruleDenials, expiredClosed, expiredOpen bool
	for _, entry := range entries {
		raw, e := loadSecret(filepath.Join(root, "pretool-receipts"), entry.Name())
		if e != nil {
			t.Fatal(e)
		}
		var envelope endpointprotocol.Signed
		if !endpointprotocol.Strict(raw, &envelope) {
			t.Fatal("invalid envelope")
		}
		o, verified := envelope.ObservationV2For(devicePub, c.Binding, time.Now())
		if !verified || strings.Contains(string(envelope.Payload), "local-only-inert") || strings.Contains(string(envelope.Payload), "synthetic-session") {
			t.Fatal("invalid or unredacted receipt")
		}
		ruleDenials = ruleDenials || (o.Verdict == "deny" && o.Reason == "mcp_tool_restricted")
		expiredClosed = expiredClosed || (o.Verdict == "deny" && o.Reason == "policy_expired")
		expiredOpen = expiredOpen || (o.Verdict == "continue" && o.Reason == "policy_expired")
	}
	checkNativePolicySync(t, root, c, issuer, key)
	if !ruleDenials || !expiredClosed || !expiredOpen {
		t.Fatal("missing signed case")
	}
}

func TestNonSystemPipeOwnerRejected(t *testing.T) {
	if system() {
		t.Skip("requires a non-SYSTEM peer")
	}
	name := fmt.Sprintf(`\\.\pipe\zasp-untrusted-fixture-%d`, os.Getpid())
	ptr, _ := windows.UTF16PtrFromString(name)
	server, err := windows.CreateNamedPipe(ptr, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 250, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(server)
	client, err := windows.CreateFile(ptr, pipeAccess, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(client)
	if systemPipe(client) {
		t.Fatal("a pipe owned by a non-SYSTEM user was trusted")
	}
}

func checkNativePolicySync(t *testing.T, root string, c windowsinventory.Config, issuer, key ed25519.PrivateKey) {
	t.Helper()
	cached, e := loadSecret(root, "pretool-policy.dpapi")
	if e != nil {
		t.Fatal(e)
	}
	var cachedSigned endpointprotocol.Signed
	var p endpointprotocol.PolicyV2
	if !endpointprotocol.Strict(cached, &cachedSigned) || !endpointprotocol.Strict(cachedSigned.Payload, &p) {
		t.Fatal("invalid cached fixture")
	}
	sign := func(v endpointprotocol.PolicyV2, private ed25519.PrivateKey) endpointprotocol.Signed {
		raw, _ := json.Marshal(v)
		return endpointprotocol.Signed{Payload: raw, Signature: ed25519.Sign(private, raw)}
	}
	token := "synthetic-test-credential"
	var fetched atomic.Pointer[endpointprotocol.Signed]
	var acceptReceipt atomic.Bool
	var deliveries atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := map[string]string{"/api/v1/devices/device/policy-bundle": "fetchEndpointPolicy", "/api/v1/runtime/observations": "recordEndpointObservations"}[r.URL.Path]
		raw, _ := io.ReadAll(r.Body)
		parsed, proof, err := endpointprotocol.Parse(r.Header, c.Binding.Organization, c.Binding.Workspace, c.Binding.Environment, op, raw, time.Now())
		if err != nil || parsed.Binding != c.Binding || !endpointprotocol.Verify(r.Header, key.Public().(ed25519.PublicKey), proof) || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unverified request", 403)
			return
		}
		if op == "fetchEndpointPolicy" {
			_ = json.NewEncoder(w).Encode(map[string]any{"bundle": fetched.Load()})
			return
		}
		if !acceptReceipt.Load() {
			http.Error(w, "temporary unavailable", 503)
			return
		}
		var batch struct {
			Receipts []endpointprotocol.Signed `json:"receipts"`
		}
		if !endpointprotocol.Strict(raw, &batch) || len(batch.Receipts) != 1 {
			http.Error(w, "invalid batch", 400)
			return
		}
		if _, ok := batch.Receipts[0].ObservationV2For(key.Public().(ed25519.PublicKey), c.Binding, time.Now()); !ok {
			http.Error(w, "invalid receipt", 403)
			return
		}
		deliveries.Add(1)
		io.WriteString(w, `{"recorded":true}`)
	}))
	defer server.Close()
	c.Origin = server.URL
	sync := func() error { return syncPretool(context.Background(), server.Client(), root, c, key, token) }
	for _, candidate := range []struct {
		revision uint64
		mode     string
		signer   ed25519.PrivateKey
	}{{1, "monitor", issuer}, {2, "monitor", issuer}, {3, "monitor", key}} {
		next := p
		next.Revision = candidate.revision
		next.Mode = candidate.mode
		signed := sign(next, candidate.signer)
		fetched.Store(&signed)
		if sync() == nil {
			t.Fatal("invalid fetched policy accepted")
		}
		held, _ := loadSecret(root, "pretool-policy.dpapi")
		if !bytes.Equal(held, cached) {
			t.Fatal("invalid fetch changed trusted cache")
		}
	}
	p.Revision++
	next := sign(p, issuer)
	fetched.Store(&next)
	if sync() == nil {
		t.Fatal("unacknowledged receipts reported as delivered")
	}
	dir := filepath.Join(root, "pretool-receipts")
	names, e := os.ReadDir(dir)
	if e != nil || len(names) != 6 {
		t.Fatal("unacknowledged entries lost")
	}
	acceptReceipt.Store(true)
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	names, e = os.ReadDir(dir)
	if e != nil || len(names) != 0 || deliveries.Load() != 6 {
		t.Fatal("acknowledged evidence not drained")
	}
}
