package addonsandbox

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReceiptBindsReleaseScopeProfileAndIndicators(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	id := "pid_11111111-1111-4111-8111-111111111111"
	scope := [3]string{id, id, id}
	profile := "sha256:" + strings.Repeat("d", 64)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Receipt{Schema: "zasp-offline-addon-observation.v1", Organization: id, Workspace: id, Environment: id, Version: id, Manifest: profile, Evidence: id, Scanner: "gvisor_tetragon", ProfileDigest: profile, Isolation: "egress_denied", ObservedAt: now, ExpiresAt: now.Add(time.Hour), Indicators: []string{"honeytoken_egress_denied"}}
	check := func(r Receipt, target [3]string, pin string, clock time.Time, ok bool) {
		t.Helper()
		raw, _ := json.Marshal(r)
		sig := ed25519.Sign(private, append([]byte(SignatureContext), raw...))
		_, err := Verify(raw, sig, public, target, pin, clock)
		if (err == nil) != ok {
			t.Fatal("unexpected decision", err)
		}
		if ok {
			sig[0] ^= 1
			if _, err := Verify(raw, sig, public, target, pin, clock); err == nil {
				t.Fatal("tampered signature trusted")
			}
		}
	}
	check(r, scope, profile, now, true)
	check(r, [3]string{id, id, "other"}, profile, now, false)
	check(r, scope, "sha256:"+strings.Repeat("c", 64), now, false)
	check(r, scope, profile, now.Add(time.Hour), false)
	r.Isolation = "network_available"
	check(r, scope, profile, now, false)
	r.Isolation = "offline_static"
	r.Scanner = "cisco_skill_scanner"
	check(r, scope, profile, now, false)
	r.Indicators = []string{"network_reference"}
	check(r, scope, profile, now, true)
	r.Indicators = []string{"network_reference", "network_reference"}
	check(r, scope, profile, now, false)
}
