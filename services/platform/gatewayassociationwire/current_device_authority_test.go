package gatewayassociationwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func legacyAuthorityRequest(t *testing.T) *http.Request {
	t.Helper()
	r, e := http.NewRequest(http.MethodGet, "https://control.example/internal/v1/runtime-gateway/authority", nil)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func legacyAuthoritySigner() ([]byte, func([]byte) ([]byte, error)) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	return key.Public().(ed25519.PublicKey), func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }
}
func TestLegacyCurrentDeviceAuthorityExistingRequestABI(t *testing.T) {
	public, sign := legacyAuthoritySigner()
	request := legacyAuthorityRequest(t)
	id := "pid_77777777-7777-4777-8777-777777777777"
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if e := SignCurrentDeviceAuthorityRequest(request, id, "gateway_key", base64.RawURLEncoding.EncodeToString(public), sign, now); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(nil)
	digest := hex.EncodeToString(sum[:])
	canonical := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", "GET", "control.example", "/internal/v1/runtime-gateway/authority", id, now.Format(time.RFC3339), digest}, "\n"))
	signature, e := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Zasp-Gateway-Signature"))
	if e != nil || !ed25519.Verify(ed25519.PublicKey(public), canonical, signature) || request.Header.Get("Authorization") != "ZaspGatewayV1 "+id || request.Header.Get("X-Zasp-Content-SHA256") != digest || request.Header.Get("X-Zasp-Gateway-Timestamp") != now.Format(time.RFC3339) {
		t.Fatal("existing native request ABI changed")
	}
	if request.Header.Get("X-Zasp-Gateway-Key-ID") != "" {
		t.Fatal("invented unsigned key identity header")
	}
}
func TestLegacyCurrentDeviceAuthorityRejectsAliasAndBody(t *testing.T) {
	public, sign := legacyAuthoritySigner()
	encoded := base64.RawURLEncoding.EncodeToString(public)
	id := "pid_77777777-7777-4777-8777-777777777777"
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.URL.Scheme = "http" }, func(r *http.Request) { r.URL.RawQuery = "x=1" }, func(r *http.Request) { r.URL.ForceQuery = true }, func(r *http.Request) { r.URL.RawPath = r.URL.Path }, func(r *http.Request) { r.URL.Fragment = "fragment" }, func(r *http.Request) { r.Host = "foreign.example" }, func(r *http.Request) { r.Method = http.MethodPost }, func(r *http.Request) { r.Header.Set("X-Zasp-Environment-ID", id) }, func(r *http.Request) { r.Header.Set("X-Forwarded-Authorization", "other") }, func(r *http.Request) { r.ContentLength = -1 }, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }} {
		request := legacyAuthorityRequest(t)
		mutate(request)
		if SignCurrentDeviceAuthorityRequest(request, id, "gateway_key", encoded, sign, now) == nil {
			t.Fatal("aliased/caller-scoped Authority request signed")
		}
	}
	body, _ := http.NewRequest(http.MethodGet, "https://control.example/internal/v1/runtime-gateway/authority", strings.NewReader("body"))
	if SignCurrentDeviceAuthorityRequest(body, id, "gateway_key", encoded, sign, now) == nil {
		t.Fatal("nonempty GET signed")
	}
	valid := legacyAuthorityRequest(t)
	valid.Header = nil
	if e := SignCurrentDeviceAuthorityRequest(valid, id, "gateway_key", encoded, sign, now); e != nil {
		t.Fatal("valid empty GET with nil header", e)
	}
}
func TestLegacyCurrentDeviceAuthorityRetainedKeyProofRefusals(t *testing.T) {
	public, sign := legacyAuthoritySigner()
	encoded := base64.RawURLEncoding.EncodeToString(public)
	id := "pid_77777777-7777-4777-8777-777777777777"
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, input := range []struct {
		id, key, public string
		now             time.Time
		sign            func([]byte) ([]byte, error)
	}{{"not-a-product-id", "gateway_key", encoded, now, sign}, {id, "bad", encoded, now, sign}, {id, "gateway_key", encoded + "=", now, sign}, {id, "gateway_key", encoded, now.Add(time.Nanosecond), sign}, {id, "gateway_key", encoded, time.Time{}, sign}, {id, "gateway_key", encoded, now, nil}, {id, "gateway_key", encoded, now, func([]byte) ([]byte, error) { return nil, errors.New("must remain private") }}, {id, "gateway_key", encoded, now, func([]byte) ([]byte, error) { return make([]byte, 64), nil }}} {
		request := legacyAuthorityRequest(t)
		if SignCurrentDeviceAuthorityRequest(request, input.id, input.key, input.public, input.sign, input.now) == nil {
			t.Fatal("invalid retained key facts signed")
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("X-Zasp-Gateway-Signature") != "" {
			t.Fatal("failed signature published headers")
		}
	}
	request := legacyAuthorityRequest(t)
	if e := SignCurrentDeviceAuthorityRequest(request, id, "gateway_other_key", encoded, sign, now); e != nil {
		t.Fatal("keyID syntax local-only, native context deliberately unchanged", e)
	}
}
