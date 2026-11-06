package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	assoc "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	enrollment "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

// New legacy custody also enforces real wall-clock expiry. Anchor this
// component fixture to the executor clock while retaining deterministic steps.
func gatewayLegacyCLIClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	previous := gatewayEnrollmentNow
	gatewayEnrollmentNow = func() time.Time { return now }
	t.Cleanup(func() { gatewayEnrollmentNow = previous })
	return &now
}

type gatewayLegacyCLIFixture struct {
	source, state string
	original      []byte
	private       string
	binding       assoc.DeviceBinding
	authority     enrollment.CurrentAuthority
	challenge     assoc.Challenge
	envelope      assoc.ChallengeEnvelope
	input         []byte
}

func gatewayLegacyCLIFile(t *testing.T, now time.Time) *gatewayLegacyCLIFixture {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("key fixture")
	}
	source := filepath.Join(t.TempDir(), "runtime-credential.json")
	f := &gatewayLegacyCLIFixture{source: source, state: filepath.Join(t.TempDir(), "association-state.json"), private: base64.RawURLEncoding.EncodeToString(private)}
	q := struct {
		CredentialID string `json:"credential_id"`
		KeyID        string `json:"key_id"`
		PrivateKey   string `json:"private_key"`
	}{gatewayCLIID("7"), "gateway-legacy-key-1", f.private}
	f.original, _ = json.Marshal(q)
	if os.WriteFile(source, f.original, 0600) != nil {
		t.Fatal("legacy fixture file")
	}
	f.binding = assoc.DeviceBinding{OrganizationID: gatewayCLIID("1"), WorkspaceID: gatewayCLIID("2"), EnvironmentID: gatewayCLIID("3"), DeviceID: gatewayCLIID("4"), CredentialID: q.CredentialID, CredentialGeneration: 3, PublicKey: base64.RawURLEncoding.EncodeToString(public), ExpiresAt: now.Add(time.Hour)}
	b := f.binding
	f.authority = enrollment.CurrentAuthority{OrganizationID: b.OrganizationID, WorkspaceID: b.WorkspaceID, EnvironmentID: b.EnvironmentID, DeviceID: b.DeviceID, DeviceVersion: 5, ReplayFloor: 19, CredentialID: b.CredentialID, CredentialGeneration: b.CredentialGeneration, KeyID: q.KeyID, Algorithm: "Ed25519", PublicKey: b.PublicKey, Audience: "runtime-gateway", ExpiresAt: b.ExpiresAt}
	f.challenge = assoc.Challenge{Schema: assoc.ChallengeSchema, ChallengeID: gatewayCLIID("6"), AssociationID: gatewayCLIID("8"), OrganizationID: b.OrganizationID, WorkspaceID: b.WorkspaceID, EnvironmentID: b.EnvironmentID, AgentID: gatewayCLIID("9"), AgentSourceDigest: strings.Repeat("ac", 32), DeviceID: b.DeviceID, ExpectedAssociationVersion: 0, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32)), ExpiresAt: now.Add(4 * time.Minute)}
	f.refreshEnvelope()
	return f
}
func (f *gatewayLegacyCLIFixture) refreshEnvelope() {
	raw, _ := json.Marshal(f.challenge)
	sum := sha256.Sum256(raw)
	f.envelope = assoc.ChallengeEnvelope{Schema: assoc.EnvelopeSchema, ChallengeWire: base64.RawURLEncoding.EncodeToString(raw), ChallengeSHA256: hex.EncodeToString(sum[:])}
	f.input, _ = json.Marshal(f.envelope)
}
func gatewayLegacyCLIArgs(endpoint, ca string, f *gatewayLegacyCLIFixture) []string {
	return []string{"gateway", "accept-agent", "--credential-file", f.source, "--endpoint", endpoint, "--association-state-file", f.state, "--ca-bundle-file", ca, "--timeout", "10s"}
}
func gatewayLegacyCLIArtifact(f *gatewayLegacyCLIFixture, suffix string) string {
	sum := sha256.Sum256([]byte(filepath.Base(f.state)))
	return filepath.Join(filepath.Dir(f.state), ".zasp-gateway-device-associations-"+hex.EncodeToString(sum[:]), f.challenge.ChallengeID+"."+f.envelope.ChallengeSHA256+suffix)
}
func gatewayLegacyCLIVerify(t *testing.T, r *http.Request, body []byte, f *gatewayLegacyCLIFixture) {
	t.Helper()
	path := gatewayRecoveryAuthorityPath
	method := "GET"
	if r.Method == "POST" {
		path = assoc.AcceptPath
		method = "POST"
	}
	if r.Method != method || r.URL.Path != path || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "ZaspGatewayV1 "+f.binding.CredentialID {
		t.Error("legacy HTTP lost exact retained Device context")
	}
	if method == "GET" && len(body) != 0 {
		t.Error("Authority GET had body")
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	stamp := r.Header.Get("X-Zasp-Gateway-Timestamp")
	sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Zasp-Gateway-Signature"))
	public, _ := base64.RawURLEncoding.DecodeString(f.binding.PublicKey)
	message := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", method, r.Host, path, f.binding.CredentialID, stamp, digest}, "\n"))
	if r.Header.Get("X-Zasp-Content-SHA256") != digest || !ed25519.Verify(public, message, sig) {
		t.Error("legacy signature differs from original privatekey/publictuple")
	}
	if method == "POST" {
		raw, e := os.ReadFile(gatewayLegacyCLIArtifact(f, ".intent"))
		var intent struct {
			AcceptRequest json.RawMessage `json:"accept_request"`
		}
		if e != nil || json.Unmarshal(raw, &intent) != nil || !bytes.Equal(intent.AcceptRequest, body) {
			t.Error("mutating POST preceded durable exact legacy acceptance intent")
		}
		if bytes.Contains(raw, []byte(f.private)) {
			t.Error("legacy privatekey copied into association intent")
		}
		if bytes.Contains(raw, []byte("local_request_sha256")) {
			t.Error("legacy intent fabricated original enrollment lineage")
		}
	}
	raw, e := os.ReadFile(f.source)
	if e != nil || !bytes.Equal(raw, f.original) {
		t.Error("legacy adapter changed protected original credential")
	}
}
func gatewayLegacyCLIResponse(body []byte, f *gatewayLegacyCLIFixture, accepted time.Time, replayed bool) assoc.AcceptResponse {
	sum := sha256.Sum256(body)
	expiry := f.challenge.ExpiresAt
	if f.binding.ExpiresAt.Before(expiry) {
		expiry = f.binding.ExpiresAt
	}
	return assoc.AcceptResponse{ChallengeID: f.challenge.ChallengeID, ChallengeSHA256: f.envelope.ChallengeSHA256, AssociationID: f.challenge.AssociationID, Acceptance: assoc.Acceptance{RequestSHA256: hex.EncodeToString(sum[:]), Credential: assoc.DeviceCredential{CredentialID: f.binding.CredentialID, CredentialGeneration: f.binding.CredentialGeneration, ExpiresAt: f.binding.ExpiresAt}, AcceptedAt: accepted, ExpiresAt: expiry}, Replayed: replayed}
}
func gatewayLegacyCLINoSecrets(t *testing.T, raw []byte, f *gatewayLegacyCLIFixture) {
	t.Helper()
	for _, secret := range []string{f.private, f.envelope.ChallengeWire, f.challenge.Nonce} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("legacy protected key/challenge escaped output")
		}
	}
}
func gatewayLegacyCLIRetained(t *testing.T, f *gatewayLegacyCLIFixture) {
	t.Helper()
	raw, e := os.ReadFile(f.source)
	if e != nil || !bytes.Equal(raw, f.original) {
		t.Fatal("original runtime credential changed")
	}
	entries, e := os.ReadDir(filepath.Dir(f.source))
	if e != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(f.source) {
		t.Fatal("adapter wrote lock/custody/enrollment artifacts into readonly source directory")
	}
	raw, _ = os.ReadFile(f.state)
	if bytes.Contains(raw, []byte(f.private)) || bytes.Contains(raw, []byte("enrollment_id")) || bytes.Contains(raw, []byte("local_request_sha256")) {
		t.Fatal("legacy state copied key or fabricated enrollment provenance")
	}
}
func gatewayLegacyCLIJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func TestGatewayLegacyAgentAssociationCommandConnectedCurrentAuthority(t *testing.T) {
	now := gatewayLegacyCLIClock(t)
	f := gatewayLegacyCLIFile(t, *now)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, assoc.MaximumBytes+1))
		gatewayLegacyCLIVerify(t, r, body, f)
		if r.Method == "GET" {
			gatewayLegacyCLIJSON(w, f.authority)
			return
		}
		gatewayLegacyCLIJSON(w, gatewayLegacyCLIResponse(body, f, now.Add(100*time.Microsecond), false))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	if os.Chmod(filepath.Dir(f.source), 0500) != nil {
		t.Fatal("readonly-mode source fixture")
	}
	defer os.Chmod(filepath.Dir(f.source), 0700)
	var output bytes.Buffer
	if e := runCommand(&output, bytes.NewReader(f.input), gatewayLegacyCLIArgs(server.URL, ca, f), "test"); e != nil {
		t.Fatal("actual legacy existing-credential acceptance failed", e)
	}
	gatewayAssociationReport(t, output.Bytes(), f.challenge)
	gatewayLegacyCLINoSecrets(t, output.Bytes(), f)
	if calls.Load() != 2 {
		t.Fatal("legacy acceptance omitted live Authority or repeated mutation")
	}
	if _, e := os.Stat(gatewayLegacyCLIArtifact(f, ".receipt")); e != nil {
		t.Fatal("legacy Device acceptance receipt not durable")
	}
	gatewayLegacyCLIRetained(t, f)
}

func TestGatewayLegacyAgentAssociationCommandUnknownRetryRequiresFreshAuthority(t *testing.T) {
	now := gatewayLegacyCLIClock(t)
	f := gatewayLegacyCLIFile(t, *now)
	accepted := *now
	var mu sync.Mutex
	var bodies [][]byte
	var stamps []string
	var gets, posts atomic.Int32
	var rotated atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, assoc.MaximumBytes+1))
		gatewayLegacyCLIVerify(t, r, body, f)
		if r.Method == "GET" {
			n := gets.Add(1)
			a := f.authority
			a.DeviceVersion += uint64(n)
			a.ReplayFloor += uint64(n)
			if rotated.Load() {
				a.CredentialGeneration++
			}
			gatewayLegacyCLIJSON(w, a)
			return
		}
		n := posts.Add(1)
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		stamps = append(stamps, r.Header.Get("X-Zasp-Gateway-Timestamp"))
		mu.Unlock()
		if n == 1 {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		gatewayLegacyCLIJSON(w, gatewayLegacyCLIResponse(body, f, accepted, true))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	args := gatewayLegacyCLIArgs(server.URL, ca, f)
	var output bytes.Buffer
	if runCommand(&output, bytes.NewReader(f.input), args, "test") == nil {
		t.Fatal("lost legacy POST response claimed success")
	}
	gatewayCLIReport(t, output.Bytes(), "unresolved", "unknown")
	intent, _ := os.ReadFile(gatewayLegacyCLIArtifact(f, ".intent"))
	descriptor, _ := os.ReadFile(f.state)
	*now = now.Add(time.Second)
	output.Reset()
	if e := runCommand(&output, bytes.NewReader(f.input), args, "test"); e != nil {
		t.Fatal("legacy same-intent restart retry failed", e)
	}
	gatewayAssociationReport(t, output.Bytes(), f.challenge)
	history, _ := os.ReadFile(gatewayLegacyCLIArtifact(f, ".receipt"))
	*now = now.Add(time.Second)
	output.Reset()
	if e := runCommand(&output, bytes.NewReader(f.input), args, "test"); e != nil {
		t.Fatal("historical receipt blocked fresh legacy server check", e)
	}
	retained, _ := os.ReadFile(gatewayLegacyCLIArtifact(f, ".receipt"))
	intentAgain, _ := os.ReadFile(gatewayLegacyCLIArtifact(f, ".intent"))
	descriptorAgain, _ := os.ReadFile(f.state)
	mu.Lock()
	if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[1]) || !bytes.Equal(bodies[1], bodies[2]) || stamps[0] == stamps[1] {
		t.Error("legacy restart changed exact intent/key or reused proof timestamp")
	}
	mu.Unlock()
	if !bytes.Equal(intent, intentAgain) || !bytes.Equal(history, retained) || !bytes.Equal(descriptor, descriptorAgain) || gets.Load() != 3 {
		t.Fatal("legacy retry skipped fresh Authority or rewrote immutable evidence")
	}
	rotated.Store(true)
	*now = now.Add(time.Second)
	output.Reset()
	if runCommand(&output, bytes.NewReader(f.input), args, "test") == nil {
		t.Fatal("new current credential generation silently adopted")
	}
	gatewayCLIReport(t, output.Bytes(), "unresolved", "unknown")
	if gets.Load() != 4 || posts.Load() != 3 {
		t.Fatal("rotation not refused after fresh Authority before POST")
	}
	gatewayLegacyCLINoSecrets(t, output.Bytes(), f)
	gatewayLegacyCLIRetained(t, f)
}

func TestGatewayLegacyAgentAssociationCommandRefusesTrustAndAuthorityFailures(t *testing.T) {
	for _, kind := range []string{"mixed_source", "incomplete_legacy", "wrong_authority_key", "wrong_authority_scope", "zero_generation", "expired_authority", "revoked_post", "wrong_receipt_generation", "cacheable_authority", "redirect_authority", "expired_after_confirm_response", "shared_deadline"} {
		func() {
			now := gatewayLegacyCLIClock(t)
			f := gatewayLegacyCLIFile(t, *now)
			var gets, posts atomic.Int32
			var expired atomic.Bool
			previousClock := gatewayEnrollmentNow
			gatewayEnrollmentNow = func() time.Time {
				if expired.Load() {
					return f.challenge.ExpiresAt
				}
				return *now
			}
			defer func() { gatewayEnrollmentNow = previousClock }()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(io.LimitReader(r.Body, assoc.MaximumBytes+1))
				gatewayLegacyCLIVerify(t, r, body, f)
				if kind == "shared_deadline" {
					select {
					case <-time.After(600 * time.Millisecond):
					case <-r.Context().Done():
						return
					}
				}
				if r.Method == "GET" {
					gets.Add(1)
					a := f.authority
					switch kind {
					case "wrong_authority_key":
						a.KeyID = "other-key"
					case "wrong_authority_scope":
						a.WorkspaceID = gatewayCLIID("5")
					case "zero_generation":
						a.CredentialGeneration = 0
					case "expired_authority":
						a.ExpiresAt = *now
					case "redirect_authority":
						w.Header().Set("Location", "/elsewhere")
						w.WriteHeader(http.StatusTemporaryRedirect)
						return
					}
					if kind == "cacheable_authority" {
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Cache-Control", "public")
						_ = json.NewEncoder(w).Encode(a)
						return
					}
					gatewayLegacyCLIJSON(w, a)
					return
				}
				posts.Add(1)
				if kind == "revoked_post" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				response := gatewayLegacyCLIResponse(body, f, *now, false)
				if kind == "wrong_receipt_generation" {
					response.Acceptance.Credential.CredentialGeneration++
				}
				if kind == "expired_after_confirm_response" {
					expired.Store(true)
				}
				gatewayLegacyCLIJSON(w, response)
			}))
			defer server.Close()
			ca := gatewayCLICA(t, server)
			args := gatewayLegacyCLIArgs(server.URL, ca, f)
			var input io.Reader = bytes.NewReader(f.input)
			unread := &gatewayRecoveryUnreadable{}
			switch kind {
			case "mixed_source":
				args = append(args, "--custody-file", filepath.Join(t.TempDir(), "other.json"))
				input = unread
			case "incomplete_legacy":
				args = append(args[:6], args[8:]...)
				input = unread
			case "shared_deadline":
				args[len(args)-1] = "1s"
			}
			var output bytes.Buffer
			e := runCommand(&output, input, args, "test")
			if e == nil {
				t.Fatalf("%s accepted invalid existingcredential authority/transport", kind)
			}
			gatewayLegacyCLINoSecrets(t, append(output.Bytes(), []byte(e.Error())...), f)
			if kind == "mixed_source" || kind == "incomplete_legacy" {
				if unread.reads != 0 || gets.Load() != 0 || posts.Load() != 0 {
					t.Fatalf("%s consumed stdin or reached network", kind)
				}
			} else {
				if gets.Load() != 1 {
					t.Fatalf("%s failed to reach actual Authority TLS boundary", kind)
				}
				if kind == "wrong_authority_key" || kind == "wrong_authority_scope" || kind == "zero_generation" || kind == "expired_authority" || kind == "cacheable_authority" || kind == "redirect_authority" {
					if posts.Load() != 0 {
						t.Fatalf("%s mutated after invalid Authority", kind)
					}
				}
				gatewayCLIReport(t, output.Bytes(), "unresolved", "unknown")
			}
			if _, e := os.Stat(gatewayLegacyCLIArtifact(f, ".receipt")); !os.IsNotExist(e) {
				t.Fatalf("%s persisted invalid acceptance receipt", kind)
			}
			gatewayLegacyCLIRetained(t, f)
		}()
	}
}
