package gatewayenrollmentwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func authorityFixture(r Request) CurrentAuthority {
	return CurrentAuthority{OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, DeviceID: r.DeviceID, DeviceVersion: 4, ReplayFloor: 0, CredentialID: r.CredentialID, CredentialGeneration: r.CredentialGeneration, KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Audience: "runtime-gateway", ExpiresAt: r.ExpiresAt}
}
func TestGatewayCurrentAuthorityClosedTupleAndFreshness(t *testing.T) {
	request := testRequest()
	value := authorityFixture(request)
	raw, e := MarshalCurrentAuthority(value)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := ParseCurrentAuthority(raw)
	now := request.ExpiresAt.Add(-time.Minute)
	if e != nil || parsed != value || !CurrentAuthorityMatchesRequest(parsed, request, now) {
		t.Fatal("actual authority tuple", e)
	}
	parsed.DeviceVersion++
	parsed.ReplayFloor = math.MaxInt64
	if !CurrentAuthorityMatchesRequest(parsed, request, now) {
		t.Fatal("advancing version/floor refused")
	}
	for _, mutate := range []func(*CurrentAuthority){func(a *CurrentAuthority) { a.CredentialID = a.DeviceID }, func(a *CurrentAuthority) {
		a.PublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	}, func(a *CurrentAuthority) { a.OrganizationID = a.WorkspaceID }, func(a *CurrentAuthority) { a.CredentialGeneration++ }, func(a *CurrentAuthority) { a.ExpiresAt = a.ExpiresAt.Add(time.Second) }} {
		bad := value
		mutate(&bad)
		if CurrentAuthorityMatchesRequest(bad, request, now) {
			t.Fatal("foreign authority tuple")
		}
	}
	if CurrentAuthorityMatchesRequest(value, request, value.ExpiresAt) {
		t.Fatal("expired authority")
	}
	if _, e := ParseCurrentAuthority(raw); e != nil {
		t.Fatal("structural parser must preserve historical authority", e)
	}
}
func TestGatewayCurrentAuthorityStrictOriginalThirteenFields(t *testing.T) {
	value := authorityFixture(testRequest())
	raw, _ := json.Marshal(value)
	cases := []string{strings.Replace(string(raw), `"replay_floor":0`, `"replay_floor":-1`, 1), strings.Replace(string(raw), `"replay_floor":0`, `"replay_floor":9223372036854775808`, 1), strings.Replace(string(raw), `"device_version":4`, `"device_version":0`, 1), strings.Replace(string(raw), `"replay_floor":0`, `"replay_floor":0e0`, 1), strings.Replace(string(raw), `"public_key":`, `"Public_key":`, 1), strings.Replace(string(raw), `"audience":"runtime-gateway"`, `"audience":null`, 1), strings.Replace(string(raw), `"key_id":"gateway_key"`, `"key_id":"\ud800"`, 1), strings.TrimSuffix(string(raw), "}") + `,"enrollment_id":"pid_55555555-5555-4555-8555-555555555555"}`, strings.TrimSuffix(string(raw), "}") + `,"device_version":4}`, string(raw) + `{}`, string(raw) + strings.Repeat(" ", MaximumBytes)}
	for i, s := range cases {
		if _, e := ParseCurrentAuthority([]byte(s)); e == nil {
			t.Fatalf("accepted authority syntax %d", i)
		}
	}
	value.ExpiresAt = value.ExpiresAt.Add(123456 * time.Microsecond)
	raw, e := MarshalCurrentAuthority(value)
	if e != nil {
		t.Fatal("canonical microsecond expiry", e)
	}
	if _, e = ParseCurrentAuthority(raw); e != nil {
		t.Fatal(e)
	}
}
func TestGatewayCurrentAuthorityExactRetainedKeyGetProof(t *testing.T) {
	value := testRequest()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	now := value.ExpiresAt.Add(-time.Minute)
	request, _ := http.NewRequest(http.MethodGet, "https://control.example/internal/v1/runtime-gateway/authority", nil)
	if e := SignAuthorityRequest(request, value, func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }, now); e != nil {
		t.Fatal(e)
	}
	digest := Digest(nil)
	canonical := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", "GET", "control.example", "/internal/v1/runtime-gateway/authority", value.CredentialID, now.Format(time.RFC3339), digest}, "\n"))
	signature, e := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Zasp-Gateway-Signature"))
	if e != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), canonical, signature) || request.Header.Get("Authorization") != "ZaspGatewayV1 "+value.CredentialID || request.Header.Get("X-Zasp-Content-SHA256") != digest {
		t.Fatal("existing signed Authority GET ABI")
	}
	for _, target := range []string{"http://control.example/internal/v1/runtime-gateway/authority", "https://control.example/internal/v1/runtime-gateway/authority?q=x", "https://control.example/internal/v1/runtime-gateway/authority/", "https://user@control.example/internal/v1/runtime-gateway/authority"} {
		bad, _ := http.NewRequest(http.MethodGet, target, nil)
		if SignAuthorityRequest(bad, value, func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }, now) == nil {
			t.Fatal("aliased target")
		}
	}
	body, _ := http.NewRequest(http.MethodGet, "https://control.example/internal/v1/runtime-gateway/authority", strings.NewReader("unexpected"))
	if SignAuthorityRequest(body, value, func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }, now) == nil {
		t.Fatal("nonempty authority body")
	}
}
