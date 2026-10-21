package gatewayenrollmentwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testToken() TokenBundle {
	return TokenBundle{Schema: TokenSchema, OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", DeviceID: "pid_44444444-4444-4444-8444-444444444444", EnrollmentID: "pid_55555555-5555-4555-8555-555555555555", TokenGeneration: 2, CredentialGeneration: 3, EnrollmentExpiresAt: time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC), Locator: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), Secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))}
}
func testRequest() Request {
	b := testToken()
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	return Request{Schema: RequestSchema, OrganizationID: b.OrganizationID, WorkspaceID: b.WorkspaceID, EnvironmentID: b.EnvironmentID, DeviceID: b.DeviceID, EnrollmentID: b.EnrollmentID, TokenGeneration: b.TokenGeneration, CredentialID: "pid_66666666-6666-4666-8666-666666666666", CredentialGeneration: b.CredentialGeneration, KeyID: "gateway_key", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(p.Public().(ed25519.PublicKey)), ExpiresAt: b.EnrollmentExpiresAt.Add(time.Hour)}
}
func testReceipt(r Request, d string) Receipt {
	return Receipt{Schema: ReceiptSchema, RequestSHA256: d, OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, DeviceID: r.DeviceID, EnrollmentID: r.EnrollmentID, TokenGeneration: r.TokenGeneration, CredentialID: r.CredentialID, CredentialGeneration: r.CredentialGeneration, KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Audience: "runtime-gateway", IssuedAt: r.ExpiresAt.Add(-time.Hour).Add(123456 * time.Microsecond), ExpiresAt: r.ExpiresAt}
}
func TestGatewayEnrollmentTokenClosedRoundTrip(t *testing.T) {
	b := testToken()
	raw, e := MarshalTokenBundle(b)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseTokenBundle(raw)
	if e != nil || got != b {
		t.Fatal("token roundtrip", e)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		v := fmt.Sprintf(f, b)
		if strings.Contains(v, b.Secret) || strings.Contains(v, b.Locator) {
			t.Fatal("fmt secret exposure")
		}
	}
	bad := []string{strings.Replace(string(raw), `"locator":`, `"Locator":`, 1), strings.Replace(string(raw), `"token_generation":2`, `"token_generation":2,"token_generation":2`, 1), strings.Replace(string(raw), `"secret":"`+b.Secret+`"`, `"secret":null`, 1), strings.Replace(string(raw), `"token_generation":2`, `"token_generation":2e0`, 1)}
	for i, v := range bad {
		if _, e = ParseTokenBundle([]byte(v)); e == nil {
			t.Fatalf("accepted token %d", i)
		}
	}
}
func TestGatewayEnrollmentRequestExactIntent(t *testing.T) {
	r := testRequest()
	raw, e := MarshalRequest(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseRequest(raw)
	if e != nil || got != r || !RequestMatchesBundle(got, testToken()) {
		t.Fatal("request mismatch", e)
	}
	sum := sha256.Sum256(raw)
	if Digest(raw) != hex.EncodeToString(sum[:]) || Digest(raw) == Digest(append([]byte(" "), raw...)) {
		t.Fatal("normalized digest")
	}
	b := testToken()
	b.TokenGeneration++
	if RequestMatchesBundle(r, b) {
		t.Fatal("foreign token generation")
	}
	r.Algorithm = "RSA"
	if _, e = MarshalRequest(r); e == nil {
		t.Fatal("algorithm")
	}
}
func TestGatewayEnrollmentReceiptExactBinding(t *testing.T) {
	r := testRequest()
	raw, _ := json.Marshal(r)
	d := Digest(raw)
	v := testReceipt(r, d)
	encoded, e := MarshalReceipt(v)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseReceipt(encoded)
	if e != nil || got != v || !ReceiptMatches(got, r, d) {
		t.Fatal("receipt mismatch", e)
	}
	got.Replayed = true
	if !ReceiptMatches(got, r, d) {
		t.Fatal("retained replay")
	}
	for _, mutate := range []func(*Receipt){func(v *Receipt) { v.OrganizationID = v.WorkspaceID }, func(v *Receipt) { v.PublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)) }, func(v *Receipt) { v.TokenGeneration++ }, func(v *Receipt) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }, func(v *Receipt) { v.RequestSHA256 = strings.Repeat("a", 64) }} {
		bad := v
		mutate(&bad)
		if ReceiptMatches(bad, r, d) {
			t.Fatal("foreign receipt accepted")
		}
	}
}
func TestGatewayEnrollmentWireBoundaryRefusals(t *testing.T) {
	r := testRequest()
	raw, _ := json.Marshal(r)
	cases := []string{string(raw) + `{}`, string(raw) + strings.Repeat(" ", MaximumBytes), strings.Replace(string(raw), `"key_id":"gateway_key"`, `"key_id":"\ud800"`, 1), strings.Replace(string(raw), `"credential_generation":3`, `"credential_generation":9223372036854775808`, 1), strings.Replace(string(raw), `"expires_at":`, `"Expires_at":`, 1), strings.Replace(string(raw), `14:00:00Z`, `14:00:00+00:00`, 1), strings.Replace(string(raw), `"algorithm":"Ed25519"`, `"algorithm":null`, 1)}
	for i, v := range cases {
		if _, e := ParseRequest([]byte(v)); e == nil {
			t.Fatalf("accepted request %d", i)
		}
	}
	if _, e := ParseRequest([]byte{0xff}); e == nil {
		t.Fatal("invalid utf8")
	}
}
func TestGatewayEnrollmentSubmittedKeyProof(t *testing.T) {
	r := testRequest()
	raw, _ := json.Marshal(r)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	req, _ := http.NewRequest(http.MethodPost, "https://control.example"+EnrollmentPath, bytes.NewReader(raw))
	b := testToken()
	auth := AuthorizationScheme + " " + b.Locator + "." + b.Secret
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	if e := SignRequest(req, raw, func(message []byte) ([]byte, error) { return ed25519.Sign(key, message), nil }, now); e != nil {
		t.Fatal(e)
	}
	if req.Header.Get("Authorization") != auth {
		t.Fatal("bootstrap authorization replaced")
	}
	if e := VerifyRequest(req, raw, now); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*http.Request){func(q *http.Request) { q.Host = "foreign.example" }, func(q *http.Request) { q.URL.Path += "/" }, func(q *http.Request) { q.Header.Add("Authorization", auth) }, func(q *http.Request) { q.Header.Set("X-Zasp-Organization", r.OrganizationID) }} {
		q := req.Clone(req.Context())
		u := *req.URL
		q.URL = &u
		mutate(q)
		if VerifyRequest(q, raw, now) == nil {
			t.Fatal("mutated proof accepted")
		}
	}
	if VerifyRequest(req, raw, now.Add(31*time.Second)) == nil {
		t.Fatal("staleproof")
	}
}
