package gatewayassociationwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type answerFixture struct {
	Raw       string `json:"raw_utf8"`
	SHA       string `json:"sha256"`
	Envelope  string `json:"envelope_utf8"`
	Accept    string `json:"accept_utf8"`
	AcceptSHA string `json:"accept_sha256"`
	Response  string `json:"response_utf8"`
}

func answer(t *testing.T) answerFixture {
	t.Helper()
	raw, e := os.ReadFile("testdata/known-answer.json")
	if e != nil {
		t.Fatal(e)
	}
	var value answerFixture
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("known answer")
	}
	return value
}
func bindingFixture() DeviceBinding {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	return DeviceBinding{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", DeviceID: "pid_44444444-4444-4444-8444-444444444444", CredentialID: "pid_77777777-7777-4777-8777-777777777777", CredentialGeneration: 3, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), ExpiresAt: time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)}
}
func TestAgentDeviceAssociationNativeByteKnownAnswer(t *testing.T) {
	a := answer(t)
	sum := sha256.Sum256([]byte(a.Raw))
	if hex.EncodeToString(sum[:]) != a.SHA {
		t.Fatal("fixture identity")
	}
	challenge, e := ParseChallenge([]byte(a.Raw))
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := ParseChallengeEnvelope([]byte(a.Envelope))
	if e != nil {
		t.Fatal(e)
	}
	got, e := ChallengeFromEnvelope(envelope)
	if e != nil || got != challenge {
		t.Fatal("exact original challenge", e)
	}
	encoded, e := MarshalChallengeEnvelope(envelope)
	if e != nil || string(encoded) != a.Envelope {
		t.Fatal("envelope bytes", e)
	}
	accept, e := BuildAcceptRequest(envelope)
	if e != nil || string(accept) != a.Accept {
		t.Fatal("accept bytes", e)
	}
	response, e := ParseAcceptResponse([]byte(a.Response))
	now := time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC)
	if e != nil || !AcceptResponseMatches(response, accept, bindingFixture(), now) {
		t.Fatal("nested native acceptance", e)
	}
	encoded, e = MarshalAcceptResponse(response)
	if e != nil || string(encoded) != a.Response {
		t.Fatal("response bytes", e)
	}
}
func TestAgentDeviceAssociationClosedNestedContract(t *testing.T) {
	a := answer(t)
	for _, raw := range []string{" " + a.Raw, strings.Replace(a.Raw, `"expected_association_version":0`, `"expected_association_version":0e0`, 1), strings.Replace(a.Raw, `"nonce":`, `"Nonce":`, 1), strings.TrimSuffix(a.Raw, "}") + `,"nonce":null}`, strings.Replace(a.Raw, `"schema":"agent-device-intent-v1"`, `"schema":"\ud800"`, 1)} {
		if _, e := ParseChallenge([]byte(raw)); e == nil {
			t.Fatal("non-native inner bytes accepted")
		}
	}
	for _, raw := range []string{strings.Replace(a.Envelope, a.SHA, strings.Repeat("a", 64), 1), strings.TrimSuffix(a.Envelope, "}") + `,"schema":"agent-device-challenge-envelope-v1"}`, a.Envelope + "{}"} {
		if _, e := ParseChallengeEnvelope([]byte(raw)); e == nil {
			t.Fatal("bad envelope")
		}
	}
	response, e := ParseAcceptResponse([]byte(a.Response))
	if e != nil {
		t.Fatal(e)
	}
	binding := bindingFixture()
	now := time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC)
	for _, mutate := range []func(*AcceptResponse){func(r *AcceptResponse) { r.Acceptance.Credential.CredentialGeneration++ }, func(r *AcceptResponse) { r.Acceptance.RequestSHA256 = strings.Repeat("a", 64) }, func(r *AcceptResponse) { r.AssociationID = r.ChallengeID }, func(r *AcceptResponse) { r.Acceptance.ExpiresAt = r.Acceptance.ExpiresAt.Add(time.Second) }, func(r *AcceptResponse) { r.Acceptance.AcceptedAt = now.Add(31 * time.Second) }} {
		bad := response
		mutate(&bad)
		if AcceptResponseMatches(bad, []byte(a.Accept), binding, now) {
			t.Fatal("foreign/late acceptance")
		}
	}
	for _, raw := range []string{strings.Replace(a.Response, `"credential_generation":3`, `"credential_generation":null`, 1), strings.Replace(a.Response, `"replayed":false`, `"replayed":false,"replayed":true`, 1), strings.Replace(a.Response, `"accepted_at":`, `"Accepted_at":`, 1)} {
		if _, e := ParseAcceptResponse([]byte(raw)); e == nil {
			t.Fatal("bad nested receipt")
		}
	}
	if AcceptResponseMatches(response, []byte(a.Accept), binding, response.Acceptance.ExpiresAt) {
		t.Fatal("expired receipt")
	}
}
func TestAgentDeviceAssociationExistingDeviceProof(t *testing.T) {
	a := answer(t)
	binding := bindingFixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	now := time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC)
	request, _ := http.NewRequest(http.MethodPost, "https://control.example"+AcceptPath, strings.NewReader(a.Accept))
	request.Header.Set("Content-Type", "application/json")
	if e := SignAcceptRequest(request, []byte(a.Accept), binding, func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }, now); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(a.Accept))
	digest := hex.EncodeToString(sum[:])
	canonical := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", "POST", "control.example", AcceptPath, binding.CredentialID, now.Format(time.RFC3339), digest}, "\n"))
	sig, e := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Zasp-Gateway-Signature"))
	if e != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), canonical, sig) || request.Header.Get("Authorization") != "ZaspGatewayV1 "+binding.CredentialID {
		t.Fatal("original signed device ABI")
	}
	bad := binding
	bad.DeviceID = bad.WorkspaceID
	if SignAcceptRequest(request, []byte(a.Accept), bad, func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }, now) == nil {
		t.Fatal("foreign device")
	}
}
