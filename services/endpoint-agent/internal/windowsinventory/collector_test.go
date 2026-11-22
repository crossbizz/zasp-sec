package windowsinventory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestDeviceBoundInventoryOnlyLifecycle(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{Binding: endpointprotocol.Binding{Organization: "org", Workspace: "work", Environment: "dev", Device: "win", Generation: 1}, Scope: "personal", AssignedSID: "S-1-5-21-1-2-3-1001"}
	reject := false
	refused := false
	var delivered []endpointprotocol.Inventory
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := map[string]string{"/api/v1/device-enrollments/exchange": "exchangeEndpointEnrollment", "/api/v1/devices/win/heartbeat": "recordEndpointHeartbeat", "/api/v1/devices/win/inventory-snapshots": "recordEndpointInventory"}[r.URL.Path]
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "confidential") || strings.Contains(string(raw), ".agents") || strings.Contains(string(raw), c.AssignedSID) {
			t.Error("raw identity or path crossed boundary")
		}
		p, proof, err := endpointprotocol.Parse(r.Header, "org", "work", "dev", op, raw, time.Now())
		if err != nil || p.Binding != c.Binding || !endpointprotocol.Verify(r.Header, pub, proof) || r.Header.Get("Authorization") != "Bearer test-inventory-secret" {
			t.Error("bad device authorization")
			w.WriteHeader(403)
			return
		}
		if refused {
			w.WriteHeader(403)
			return
		}
		switch op {
		case "exchangeEndpointEnrollment":
			io.WriteString(w, `{"device_id":"win","credential_generation":1,"state":"active"}`)
		case "recordEndpointHeartbeat":
			var h endpointprotocol.Heartbeat
			if !endpointprotocol.Strict(raw, &h) || !h.Valid() || h.Adapter != "windows_inventory" || h.Revision != 0 || h.PolicyStatus != "policy_unavailable" {
				t.Error("inventory-only agent claimed policy coverage")
			}
			io.WriteString(w, `{"recorded":true}`)
		case "recordEndpointInventory":
			if reject {
				w.WriteHeader(503)
				return
			}
			var v endpointprotocol.Inventory
			if !endpointprotocol.Strict(raw, &v) || !v.Valid() {
				t.Error("bad inventory")
			}
			delivered = append(delivered, v)
			io.WriteString(w, `{"recorded":true}`)
		default:
			t.Errorf("unexpected operation %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer host.Close()
	c.Origin = host.URL
	report := func(state, path string) []byte {
		return []byte(fmt.Sprintf(`{"schema_version":"zaspctl.local.v1","command":"inventory","status":"%s","coverage":{"mode":"local_only","roots":[{"scope":"personal","root":".agents/skills","status":"%s"}]},"items":[{"scope":"personal","path":".agents/skills/%s","manifest_digest":"sha256:%s"}]}`, state, state, path, strings.Repeat("a", 64)))
	}
	s := State{}
	full := report("complete", "confidential")
	if err := s.Admit(c, key.Seed(), full); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit(c, key.Seed(), full); err != nil || s.Sequence != 1 {
		t.Fatal("duplicate handoff advanced generation")
	}
	if err := s.Admit(c, key.Seed(), report("partial", "confidential2")); err != nil || len(s.Pending) != 2 {
		t.Fatal("lost last complete report")
	}
	save := func(n State) error { raw, _ := json.Marshal(n); return json.Unmarshal(raw, &s) }
	reject = true
	if Sync(context.Background(), host.Client(), c, key, "test-inventory-secret", s, save) == nil || len(s.Pending) != 2 {
		t.Fatal("offline queue lost")
	}
	reject = false
	if err := Sync(context.Background(), host.Client(), c, key, "test-inventory-secret", s, save); err != nil || len(s.Pending) != 0 || len(delivered) != 2 || !*delivered[0].Complete || *delivered[1].Complete {
		t.Fatal("retry failed", err)
	}
	refused = true
	if Sync(context.Background(), host.Client(), c, key, "test-inventory-secret", s, save) == nil {
		t.Fatal("retired device admitted")
	}
	other := c
	other.AssignedSID = "S-1-5-21-1-2-3-1002"
	if err := s.Admit(other, key.Seed(), full); err == nil {
		t.Fatal("reassigned employee inherited same state")
	}
}
