//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestRemoteSyncAndInventory(t *testing.T) {
	f := newFixture(t)
	b := f.b
	b.inventoryEnabled = true
	logical := func(location string, complete bool) []byte {
		status := "partial"
		if complete {
			status = "complete"
		}
		bits, err := json.Marshal(map[string]any{"schema_version": "zaspctl.local.v1", "command": "inventory", "status": status, "coverage": map[string]any{"mode": "local_only", "roots": []map[string]any{{"scope": "project", "root": ".claude/skills", "status": status}}}, "items": []map[string]any{{"scope": "project", "path": ".claude/skills/" + location, "manifest_digest": "sha256:" + strings.Repeat("b", 64)}}})
		if err != nil {
			t.Fatal(err)
		}
		return bits
	}
	privateProject := "/private/work/first"
	if err := b.queueInventory(logical("internal-skill", true), privateProject); err != nil {
		t.Fatal(err)
	}
	if err := b.queueInventory(logical("changed-skill", false), privateProject); err != nil {
		t.Fatal(err)
	}
	if err := b.queueInventory(logical("same-relpath", true), "/private/work/second"); err != nil {
		t.Fatal(err)
	}
	if len(b.store.state.Inventory) != 2 {
		t.Fatal("mixed projects")
	}
	state, err := openStore(b.store.dir, b.key.Seed(), b.binding)
	if err != nil {
		t.Fatal(err)
	}
	b.store = state
	d, err := b.evaluate(event("local", "one", "external"))
	if err != nil || d.Verdict != "continue" {
		t.Fatal(d, err)
	}
	p := f.p
	p.Revision = 2
	p.Mode = "enforce"
	bundle, _ := sign(p, f.signer)
	var batches int
	var pending bool
	var ops []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		op := map[string]string{"/api/v1/device-enrollments/exchange": "exchangeEndpointEnrollment", "/api/v1/devices/test-device/policy-bundle": "fetchEndpointPolicy", "/api/v1/devices/test-device/heartbeat": "recordEndpointHeartbeat", "/api/v1/devices/test-device/inventory-snapshots": "recordEndpointInventory", "/api/v1/runtime/observations": "recordEndpointObservations"}[path]
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("private/work")) || bytes.Contains(body, []byte("internal-skill")) || bytes.Contains(body, []byte("changed-skill")) {
			t.Error("raw source names uploaded")
		}
		binding, proof, e := endpointprotocol.Parse(r.Header, b.binding.Organization, b.binding.Workspace, b.binding.Environment, op, body, time.Now())
		if r.Header.Get("Authorization") != "Bearer test-private-value" || e != nil || binding.Binding != endpointprotocol.Binding(b.binding) || !endpointprotocol.Verify(r.Header, b.key.Public().(ed25519.PublicKey), proof) {
			t.Error("unbound request")
			http.Error(w, "denied", 403)
			return
		}
		ops = append(ops, op)
		switch op {
		case "exchangeEndpointEnrollment":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_id": "test-device", "credential_generation": 1, "state": "active"})
		case "fetchEndpointPolicy":
			_ = json.NewEncoder(w).Encode(map[string]any{"bundle": bundle})
		case "recordEndpointObservations":
			if !pending {
				pending = true
				w.WriteHeader(503)
				return
			}
			var batch struct {
				Receipts []endpointprotocol.Signed `json:"receipts"`
			}
			json.Unmarshal(body, &batch)
			o, ok := batch.Receipts[0].ObservationFor(b.key.Public().(ed25519.PublicKey), binding.Binding, time.Now())
			if !ok || o.PolicyRevision != 1 || !o.WouldBlock {
				t.Error(o)
			}
			batches++
			io.WriteString(w, `{"recorded":true}`)
		case "recordEndpointInventory":
			var v endpointprotocol.Inventory
			if !endpointprotocol.Strict(body, &v) || !v.Valid() {
				t.Fatal("invalid inventory")
			}
			io.WriteString(w, `{"recorded":true}`)
		default:
			io.WriteString(w, `{"recorded":true}`)
		}
	}))
	defer server.Close()
	token := filepath.Join(b.store.dir, "token")
	if err = os.WriteFile(token, []byte("test-private-value"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := newRemote(remoteConfig{Origin: server.URL, TokenFile: token, Inventory: true}, b)
	if err != nil {
		t.Fatal(err)
	}
	a.client = server.Client()
	var mu sync.Mutex
	if s := a.syncOnce(context.Background(), &mu); s != "observations_pending" || len(b.store.state.Decisions) != 1 {
		t.Fatal("failed upload erased receipt", s)
	}
	if s := a.syncOnce(context.Background(), &mu); s != "connected" || len(b.store.state.Decisions) != 0 || len(b.store.state.Inventory) != 0 || batches != 1 {
		t.Fatal("did not sync", s)
	}
	if strings.Count(strings.Join(ops, " "), "recordEndpointInventory") != 3 {
		t.Fatal("partial observation erased earlier complete pending", ops)
	}
	denied, err := b.evaluate(event("local", "two", "external"))
	if err != nil || denied.Verdict != "deny" {
		t.Fatal("new policy failed", denied, err)
	}
}

func TestRemoteRejectsIdentityInURLAndPlaintext(t *testing.T) {
	f := newFixture(t)
	for _, u := range []string{"http://example.invalid", "https://viewer@example.invalid", "https://example.invalid/?token=private", "https://example.invalid/path", "https://example.invalid#route"} {
		if _, err := newRemote(remoteConfig{Origin: u, TokenFile: "/test"}, f.b); err == nil {
			t.Fatal("accepted unsafe control origin")
		}
	}
}
