package gatewayinstallationwire

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func sampleObservation() Observation {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	return Observation{Schema: ObservationSchema, CredentialGeneration: 2, ContractVersion: 1, KeyID: "gateway_key", Algorithm: "Ed25519", Audience: "runtime-gateway-policy", Sequence: 10, PolicyVersion: 5, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), FailureMode: "closed", PayloadDigest: strings.Repeat("a", 64), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)), InstalledObservedAt: now}
}
func rawObservation(t *testing.T, o Observation) []byte {
	t.Helper()
	b, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func sampleBinding() Binding {
	return Binding{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", DeviceID: "pid_44444444-4444-4444-8444-444444444444", CredentialID: "pid_55555555-5555-4555-8555-555555555555"}
}
func sampleReceipt(o Observation, digest string) Receipt {
	b := sampleBinding()
	return Receipt{Schema: ReceiptSchema, RequestSHA256: digest, OrganizationID: b.OrganizationID, WorkspaceID: b.WorkspaceID, EnvironmentID: b.EnvironmentID, DeviceID: b.DeviceID, CredentialID: b.CredentialID, CredentialGeneration: o.CredentialGeneration, Disposition: "recorded", RepresentativeSHA256: digest, RepresentativeSequence: o.Sequence, RepresentativeInstalledObservedAt: o.InstalledObservedAt, RepresentativeRecordedAt: o.InstalledObservedAt.Add(time.Second)}
}
func TestInstallationObservationRoundTrip(t *testing.T) {
	o := sampleObservation()
	raw, e := MarshalObservation(o)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseObservation(raw)
	if e != nil || got != o {
		t.Fatalf("round trip: %v %#v", e, got)
	}
	if e = ValidateAt(got, o.InstalledObservedAt); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if Digest(raw) != hex.EncodeToString(sum[:]) {
		t.Fatal("exact raw digest")
	}
	whitespace := append([]byte(" "), raw...)
	if Digest(whitespace) == Digest(raw) {
		t.Fatal("digest normalized bytes")
	}
}
func TestInstallationObservationClosedSyntax(t *testing.T) {
	raw := string(rawObservation(t, sampleObservation()))
	cases := []string{strings.Replace(raw, `"schema":`, `"Schema":`, 1), strings.Replace(raw, `"schema":`, `"unknown":null,"schema":`, 1), strings.Replace(raw, `"sequence":10`, `"sequence":10,"sequence":11`, 1), strings.Replace(raw, `"sequence":10`, `"sequence":null`, 1), strings.Replace(raw, `"sequence":10`, `"sequence":1e1`, 1), strings.Replace(raw, `"sequence":10`, `"sequence":10.0`, 1), strings.Replace(raw, `"sequence":10`, `"sequence":9223372036854775808`, 1), strings.Replace(raw, `"key_id":"gateway_key"`, `"key_id":"\ud800"`, 1), raw + ` {}`, raw + strings.Repeat(" ", MaximumBytes), string([]byte{0xff})}
	for i, v := range cases {
		if _, e := ParseObservation([]byte(v)); e == nil {
			t.Fatalf("accepted closed-syntax case %d", i)
		}
	}
}
func TestInstallationObservationTimeAndIdentity(t *testing.T) {
	base := sampleObservation()
	mutations := []func(*Observation){func(o *Observation) { o.Sequence = 0 }, func(o *Observation) { o.PolicyVersion = math.MaxUint64 }, func(o *Observation) { o.CredentialGeneration = 0 }, func(o *Observation) { o.ContractVersion = 2 }, func(o *Observation) { o.Algorithm = "ed25519" }, func(o *Observation) { o.Audience = "runtime-gateway" }, func(o *Observation) { o.KeyID = "invalid" }, func(o *Observation) { o.Signature = "invalid" }, func(o *Observation) { o.PayloadDigest = strings.Repeat("A", 64) }, func(o *Observation) { o.FailureMode = "allow" }, func(o *Observation) { o.ExpiresAt = o.IssuedAt }, func(o *Observation) { o.InstalledObservedAt = o.ExpiresAt }, func(o *Observation) { o.IssuedAt = o.IssuedAt.Add(time.Nanosecond) }}
	for i, m := range mutations {
		o := base
		m(&o)
		if _, e := MarshalObservation(o); e == nil {
			t.Fatalf("accepted invalid observation %d", i)
		}
	}
	if e := ValidateAt(base, base.ExpiresAt); e == nil {
		t.Fatal("expired")
	}
	if e := ValidateAt(base, base.InstalledObservedAt.Add(-time.Minute)); e == nil {
		t.Fatal("future install")
	}
}
func TestInstallationReceiptRoundTripAndBinding(t *testing.T) {
	o := sampleObservation()
	digest := strings.Repeat("b", 64)
	r := sampleReceipt(o, digest)
	raw, e := MarshalReceipt(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseReceipt(raw)
	if e != nil || got != r {
		t.Fatalf("receipt roundtrip %v", e)
	}
	if !ReceiptMatches(got, o, digest, sampleBinding()) {
		t.Fatal("exact current scope receipt rejected")
	}
	b := sampleBinding()
	b.DeviceID = b.WorkspaceID
	if ReceiptMatches(got, o, digest, b) {
		t.Fatal("foreign device accepted")
	}
	r.RequestSHA256 = strings.Repeat("c", 64)
	if ReceiptMatches(r, o, digest, sampleBinding()) {
		t.Fatal("wrong request accepted")
	}
}
func TestInstallationReceiptCoalescedRank(t *testing.T) {
	o := sampleObservation()
	d := strings.Repeat("b", 64)
	r := sampleReceipt(o, d)
	r.Disposition = "coalesced"
	if ReceiptMatches(r, o, d, sampleBinding()) {
		t.Fatal("equal rank coalesced")
	}
	r.RepresentativeSequence++
	r.RepresentativeSHA256 = strings.Repeat("a", 64)
	if !ReceiptMatches(r, o, d, sampleBinding()) {
		t.Fatal("greater sequence coalesced refused")
	}
	r.RepresentativeSequence = o.Sequence
	r.RepresentativeInstalledObservedAt = r.RepresentativeInstalledObservedAt.Add(time.Second)
	if !ReceiptMatches(r, o, d, sampleBinding()) {
		t.Fatal("greater observation time refused")
	}
	r.RepresentativeInstalledObservedAt = o.InstalledObservedAt
	r.RepresentativeSHA256 = strings.Repeat("c", 64)
	if !ReceiptMatches(r, o, d, sampleBinding()) {
		t.Fatal("greater digest refused")
	}
	r.RepresentativeSHA256 = strings.Repeat("a", 64)
	if ReceiptMatches(r, o, d, sampleBinding()) {
		t.Fatal("older digest accepted")
	}
	if RankCompare(o.Sequence, o.InstalledObservedAt, d, o.Sequence, o.InstalledObservedAt, d) != 0 {
		t.Fatal("equal rank")
	}
}
func TestInstallationReceiptClosedSyntaxAndTimes(t *testing.T) {
	o := sampleObservation()
	r := sampleReceipt(o, strings.Repeat("b", 64))
	raw, _ := json.Marshal(r)
	cases := []string{strings.Replace(string(raw), `"schema":`, `"schema":null,"schema":`, 1), strings.Replace(string(raw), `"representative_recorded_at":`, `"Representative_recorded_at":`, 1), strings.Replace(string(raw), `12:00:01Z`, `12:00:01.0000001Z`, 1), strings.Replace(string(raw), `12:00:01Z`, `12:00:01+00:00`, 1), strings.Replace(string(raw), `"disposition":"recorded"`, `"disposition":"accepted"`, 1)}
	for i, v := range cases {
		if _, e := ParseReceipt([]byte(v)); e == nil {
			t.Fatalf("accepted invalid receipt %d", i)
		}
	}
	r.RepresentativeRecordedAt = r.RepresentativeRecordedAt.Add(123456 * time.Microsecond)
	if _, e := MarshalReceipt(r); e != nil {
		t.Fatal("canonical microsecond receipt refused", e)
	}
}
