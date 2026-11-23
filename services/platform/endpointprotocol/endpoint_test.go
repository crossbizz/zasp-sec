package endpointprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"
)

func TestProofCannotBeReusedAcrossOperationsOrPayloads(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{Organization: "org", Workspace: "workspace", Environment: "test", Device: "dev", Generation: 1}
	now := time.Now().UTC()
	body := []byte(`{"policy_revision":2}`)
	hdr := http.Header{}
	if err = Sign(hdr, b, "heartbeat", body, key, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		op, env string
		body    []byte
		clock   time.Time
		valid   bool
	}{
		{"heartbeat", "test", body, now, true}, {"exchange", "test", body, now, false}, {"heartbeat", "other", body, now, false}, {"heartbeat", "test", []byte("{}"), now, false}, {"heartbeat", "test", body, now.Add(121 * time.Second), false},
	} {
		_, msg, err := Parse(hdr, "org", "workspace", tc.env, tc.op, tc.body, tc.clock)
		valid := err == nil && Verify(hdr, pub, msg)
		if valid != tc.valid {
			t.Fatalf("operation %s, Environment %s: got %v", tc.op, tc.env, valid)
		}
	}
	hdr.Add("X-Zasp-Device-Proof", hdr.Get("X-Zasp-Device-Proof"))
	if _, _, err := Parse(hdr, "org", "workspace", "test", "heartbeat", body, now); err == nil {
		t.Fatal("accepted duplicate proof")
	}
}

func TestInventoryOnlyHeartbeatCannotClaimPolicyCoverage(t *testing.T) {
	h := Heartbeat{Adapter: "windows_inventory", PolicyStatus: "policy_unavailable"}
	if !h.Valid() {
		t.Fatal("inventory-only health rejected")
	}
	h.PolicyStatus = "verified_cache"
	h.Revision = 1
	if h.Valid() {
		t.Fatal("inventory agent acknowledged policy")
	}
	h.Adapter = "unknown-adapter"
	if h.Valid() {
		t.Fatal("unrecognized adapter")
	}
}
