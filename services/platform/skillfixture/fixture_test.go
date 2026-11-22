package skillfixture

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/privatearchive"
)

func TestHandoffPinsOnlyCurrentRetainedSyntheticArchive(t *testing.T) {
	const scoped = "pid_00000000-0000-4000-8000-000000000001/pid_00000000-0000-4000-8000-000000000002/pid_00000000-0000-4000-8000-000000000003"
	const grant = "pid_00000000-0000-4000-8000-000000000004"
	now := time.Unix(1700000000, 0)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32))
	file, _ := Archive(Difference)
	r := privatearchive.Record{Binding: privatearchive.Binding{Scope: scoped, Grant: grant, Digest: identity(file), Size: int64(len(file)), Deadline: now.Add(time.Hour).Unix()}, State: "retained", Version: "immutable-A"}
	h, err := Sign(key, r, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(h)
	parse := func(raw []byte, scope string, at time.Time) (Claim, error) {
		return Verify(key.Public().(ed25519.PublicKey), scope, bytes.NewReader(raw), at)
	}
	c, err := parse(wire, scoped, now)
	if err != nil || c.Fixture != Difference || c.ExpiresAt != now.Add(MaxDuration).Unix() {
		t.Fatal("valid verified handoff missing")
	}
	if _, err = parse(wire, scoped, time.Unix(c.ExpiresAt, 0)); err == nil {
		t.Fatal("expired handoff accepted")
	}
	if _, err = parse(wire, scoped, now.Add(-time.Second)); err == nil {
		t.Fatal("future handoff accepted")
	}
	if _, err = parse(wire, "foreign", now); err == nil {
		t.Fatal("foreign scope accepted")
	}
	h.Payload[2] ^= 1
	bad, _ := json.Marshal(h)
	if _, err = parse(bad, scoped, now); err == nil {
		t.Fatal("tampered handoff accepted")
	}
	for _, op := range []func(*privatearchive.Record){
		func(r *privatearchive.Record) { r.State = "deleted" }, func(r *privatearchive.Record) { r.Deadline = now.Unix() },
		func(r *privatearchive.Record) { r.Digest = identity([]byte("customer source")) }, func(r *privatearchive.Record) { r.Size++ },
	} {
		x := r
		op(&x)
		if _, err := Sign(key, x, now); err == nil {
			t.Fatal("ineligible retained record admitted")
		}
	}
	if _, err := Archive("custom-script"); err == nil {
		t.Fatal("arbitrary fixture was accepted")
	}
	if out := result(c, []string{"process.exec"}, false, now); out.Status != "inconclusive" {
		t.Fatal("partial kernel observations produced a behavioral claim")
	}
}
