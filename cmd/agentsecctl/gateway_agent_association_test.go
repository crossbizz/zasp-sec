package main

import (
	"bytes"
	"crypto/ed25519"
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
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

func gatewayAssociationArgs(ca, path string) []string {
	return []string{"gateway", "accept-agent", "--custody-file", path, "--ca-bundle-file", ca, "--timeout", "10s"}
}
func gatewayAssociationChallenge(t *testing.T, q wire.Request, now time.Time, n string) (assoc.Challenge, assoc.ChallengeEnvelope, []byte) {
	t.Helper()
	challenge := assoc.Challenge{Schema: "agent-device-intent-v1", ChallengeID: gatewayCLIID(n), AssociationID: gatewayCLIID("8"), OrganizationID: q.OrganizationID, WorkspaceID: q.WorkspaceID, EnvironmentID: q.EnvironmentID, AgentID: gatewayCLIID("9"), AgentSourceDigest: strings.Repeat("ab", 32), DeviceID: q.DeviceID, ExpectedAssociationVersion: 0, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)), ExpiresAt: now.Add(4 * time.Minute)}
	raw, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal("challenge fixture")
	}
	sum := sha256.Sum256(raw)
	envelope := assoc.ChallengeEnvelope{Schema: "agent-device-challenge-envelope-v1", ChallengeWire: base64.RawURLEncoding.EncodeToString(raw), ChallengeSHA256: hex.EncodeToString(sum[:])}
	input, _ := json.Marshal(envelope)
	return challenge, envelope, input
}
func gatewayAssociationDirectory(path string) string {
	sum := sha256.Sum256([]byte(filepath.Base(path)))
	return filepath.Join(filepath.Dir(path), ".zasp-gateway-associations-"+hex.EncodeToString(sum[:]))
}
func gatewayAssociationArtifact(path string, c assoc.Challenge, e assoc.ChallengeEnvelope, suffix string) string {
	return filepath.Join(gatewayAssociationDirectory(path), c.ChallengeID+"."+e.ChallengeSHA256+suffix)
}
func gatewayAssociationVerify(t *testing.T, r *http.Request, body []byte, path string, q wire.Request, c assoc.Challenge, e assoc.ChallengeEnvelope) string {
	t.Helper()
	if r.Method != "POST" || r.URL.Path != assoc.AcceptPath || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "ZaspGatewayV1 "+q.CredentialID || r.Header.Get("Content-Type") != "application/json" {
		t.Error("acceptance changed fixed retained credential HTTP context")
	}
	var outer struct {
		Schema          string `json:"schema"`
		ChallengeWire   string `json:"challenge_wire"`
		ChallengeSHA256 string `json:"challenge_sha256"`
	}
	if json.Unmarshal(body, &outer) != nil || outer.Schema != "agent-device-accept-v1" || outer.ChallengeWire != e.ChallengeWire || outer.ChallengeSHA256 != e.ChallengeSHA256 {
		t.Error("POST did not preserve exact native challenge")
	}
	canonical, _ := json.Marshal(outer)
	if !bytes.Equal(body, canonical) {
		t.Error("POST body not frozen canonical outer3")
	}
	raw, err := os.ReadFile(gatewayAssociationArtifact(path, c, e, ".intent"))
	var intent struct {
		AcceptRequest        json.RawMessage `json:"accept_request"`
		CredentialID         string          `json:"credential_id"`
		CredentialGeneration uint64          `json:"credential_generation"`
	}
	if err != nil || json.Unmarshal(raw, &intent) != nil || !bytes.Equal(intent.AcceptRequest, body) || intent.CredentialID != q.CredentialID || intent.CredentialGeneration != q.CredentialGeneration {
		t.Error("HTTP preceded durable exact selected intent")
	}
	dirInfo, err := os.Stat(gatewayAssociationDirectory(path))
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0700 {
		t.Error("association namespace not protected0700")
	}
	info, err := os.Stat(gatewayAssociationArtifact(path, c, e, ".intent"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Error("intent not protected0600")
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	stamp := r.Header.Get("X-Zasp-Gateway-Timestamp")
	sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Zasp-Gateway-Signature"))
	public, _ := base64.RawURLEncoding.DecodeString(q.PublicKey)
	message := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", "POST", r.Host, assoc.AcceptPath, q.CredentialID, stamp, digest}, "\n"))
	if r.Header.Get("X-Zasp-Content-SHA256") != digest || !ed25519.Verify(public, message, sig) {
		t.Error("acceptance signature does not bind actual submitted retained-key context")
	}
	stored, _ := os.ReadFile(path)
	var key struct {
		PrivateKey string `json:"private_key"`
	}
	_ = json.Unmarshal(stored, &key)
	return key.PrivateKey
}
func gatewayAssociationResponse(body []byte, q wire.Request, c assoc.Challenge, e assoc.ChallengeEnvelope, accepted time.Time, replayed bool) assoc.AcceptResponse {
	sum := sha256.Sum256(body)
	expiry := c.ExpiresAt
	if q.ExpiresAt.Before(expiry) {
		expiry = q.ExpiresAt
	}
	return assoc.AcceptResponse{ChallengeID: c.ChallengeID, ChallengeSHA256: e.ChallengeSHA256, AssociationID: c.AssociationID, Acceptance: assoc.Acceptance{RequestSHA256: hex.EncodeToString(sum[:]), Credential: assoc.DeviceCredential{CredentialID: q.CredentialID, CredentialGeneration: q.CredentialGeneration, ExpiresAt: q.ExpiresAt}, AcceptedAt: accepted, ExpiresAt: expiry}, Replayed: replayed}
}
func gatewayAssociationReport(t *testing.T, raw []byte, c assoc.Challenge) {
	t.Helper()
	gatewayCLIReport(t, raw, "device_accepted_pending_human", "confirmed_device_acceptance")
	var report map[string]any
	if json.Unmarshal(raw, &report) != nil || len(report) != 6 || report["association_id"] != c.AssociationID || report["challenge_id"] != c.ChallengeID || report["agent_id"] != c.AgentID || report["device_id"] != c.DeviceID {
		t.Fatal("report omitted exact phase2-only identity or added claims")
	}
}
func gatewayAssociationNoSecrets(t *testing.T, raw []byte, b wire.TokenBundle, c assoc.Challenge, e assoc.ChallengeEnvelope, private string) {
	t.Helper()
	gatewayCLINoSecrets(t, raw, b, private)
	for _, secret := range []string{c.Nonce, e.ChallengeWire} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("raw challenge material escaped output")
		}
	}
}

func TestGatewayAgentAssociationCommandConnectedTLSPhaseTwoOnly(t *testing.T) {
	now := gatewayCLIClock(t)
	path := filepath.Join(t.TempDir(), "device.json")
	var q wire.Request
	var c assoc.Challenge
	var e assoc.ChallengeEnvelope
	var calls atomic.Int32
	privateSeen := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, assoc.MaximumBytes+1))
		privateSeen <- gatewayAssociationVerify(t, r, body, path, q, c, e)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(gatewayAssociationResponse(body, q, c, e, now.Add(100*time.Microsecond), false))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	bundle, request := gatewayRecoveryPending(t, path, server.URL, *now)
	q = request
	var input []byte
	c, e, input = gatewayAssociationChallenge(t, q, *now, "6")
	original, _ := os.ReadFile(path)
	var output bytes.Buffer
	if err := runCommand(&output, bytes.NewReader(input), gatewayAssociationArgs(ca, path), "test"); err != nil {
		t.Fatal("actual Device acceptance command failed", err)
	}
	private := <-privateSeen
	gatewayAssociationReport(t, output.Bytes(), c)
	gatewayAssociationNoSecrets(t, output.Bytes(), bundle, c, e, private)
	if calls.Load() != 1 {
		t.Fatal("acceptance did not perform exactly one signed POST")
	}
	if _, err := os.Stat(gatewayAssociationArtifact(path, c, e, ".receipt")); err != nil {
		t.Fatal("confirmed Device acceptance not durable")
	}
	gatewayRecoveryRetained(t, path, original)
}

func TestGatewayAgentAssociationCommandUnknownRetryAndIndependentHistory(t *testing.T) {
	now := gatewayCLIClock(t)
	path := filepath.Join(t.TempDir(), "device.json")
	var q wire.Request
	var c assoc.Challenge
	var e assoc.ChallengeEnvelope
	var mu sync.Mutex
	var bodies [][]byte
	var stamps []string
	accepted := *now
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, assoc.MaximumBytes+1))
		gatewayAssociationVerify(t, r, body, path, q, c, e)
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		stamps = append(stamps, r.Header.Get("X-Zasp-Gateway-Timestamp"))
		n := len(bodies)
		mu.Unlock()
		if n == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(gatewayAssociationResponse(body, q, c, e, accepted, n < 4))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	bundle, request := gatewayRecoveryPending(t, path, server.URL, *now)
	q = request
	var input []byte
	c, e, input = gatewayAssociationChallenge(t, q, *now, "6")
	original, _ := os.ReadFile(path)
	var output bytes.Buffer
	args := gatewayAssociationArgs(ca, path)
	if runCommand(&output, bytes.NewReader(input), args, "test") == nil {
		t.Fatal("lost acceptance response claimed success")
	}
	gatewayCLIReport(t, output.Bytes(), "unresolved", "unknown")
	intent, _ := os.ReadFile(gatewayAssociationArtifact(path, c, e, ".intent"))
	*now = now.Add(time.Second)
	output.Reset()
	if err := runCommand(&output, bytes.NewReader(input), args, "test"); err != nil {
		t.Fatal("exact acceptance retry failed", err)
	}
	gatewayAssociationReport(t, output.Bytes(), c)
	history, _ := os.ReadFile(gatewayAssociationArtifact(path, c, e, ".receipt"))
	*now = now.Add(time.Second)
	output.Reset()
	if err := runCommand(&output, bytes.NewReader(input), args, "test"); err != nil {
		t.Fatal("saved receipt bypassed or blocked fresh live replay", err)
	}
	retained, _ := os.ReadFile(gatewayAssociationArtifact(path, c, e, ".receipt"))
	intentAgain, _ := os.ReadFile(gatewayAssociationArtifact(path, c, e, ".intent"))
	if !bytes.Equal(history, retained) || !bytes.Equal(intent, intentAgain) {
		t.Fatal("retry rewrote immutable intent/receipt")
	}
	mu.Lock()
	if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[1]) || !bytes.Equal(bodies[1], bodies[2]) || stamps[0] == stamps[1] {
		t.Error("retry reused historical authority or changed exact body")
	}
	mu.Unlock()
	oldReceipt := gatewayAssociationArtifact(path, c, e, ".receipt")
	c, e, input = gatewayAssociationChallenge(t, q, *now, "7")
	c.AgentID = gatewayCLIID("5")
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	e.ChallengeWire = base64.RawURLEncoding.EncodeToString(raw)
	e.ChallengeSHA256 = hex.EncodeToString(sum[:])
	input, _ = json.Marshal(e)
	accepted = *now
	output.Reset()
	if err := runCommand(&output, bytes.NewReader(input), args, "test"); err != nil {
		t.Fatal("independent Agent challenge blocked by first history", err)
	}
	retained, _ = os.ReadFile(oldReceipt)
	if !bytes.Equal(history, retained) {
		t.Fatal("new Agent challenge replaced prior history")
	}
	gatewayAssociationNoSecrets(t, output.Bytes(), bundle, c, e, "")
	gatewayRecoveryRetained(t, path, original)
}

func TestGatewayAgentAssociationCommandRefusesInvalidChallengeAndEvidence(t *testing.T) {
	for _, kind := range []string{"wrong_scope", "hash_mismatch", "duplicate_input", "wrong_generation", "wrong_request_hash", "expired_after_response", "revoked", "cacheable", "redirect", "nested_extra", "endpoint_override"} {
		func() {
			now := gatewayCLIClock(t)
			path := filepath.Join(t.TempDir(), "device.json")
			var q wire.Request
			var c assoc.Challenge
			var e assoc.ChallengeEnvelope
			var calls atomic.Int32
			var expired atomic.Bool
			priorClock := gatewayEnrollmentNow
			gatewayEnrollmentNow = func() time.Time {
				if expired.Load() {
					return c.ExpiresAt
				}
				return *now
			}
			defer func() { gatewayEnrollmentNow = priorClock }()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(io.LimitReader(r.Body, assoc.MaximumBytes+1))
				gatewayAssociationVerify(t, r, body, path, q, c, e)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				response := gatewayAssociationResponse(body, q, c, e, *now, false)
				switch kind {
				case "wrong_generation":
					response.Acceptance.Credential.CredentialGeneration++
				case "wrong_request_hash":
					response.Acceptance.RequestSHA256 = strings.Repeat("0", 64)
				case "expired_after_response":
					expired.Store(true)
				case "revoked":
					w.WriteHeader(http.StatusUnauthorized)
					return
				case "cacheable":
					w.Header().Set("Cache-Control", "public")
				case "redirect":
					w.Header().Set("Location", "/other")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				case "nested_extra":
					raw, _ := json.Marshal(response)
					raw = bytes.Replace(raw, []byte(`"acceptance":{`), []byte(`"acceptance":{"extra":true,`), 1)
					_, _ = w.Write(raw)
					return
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			ca := gatewayCLICA(t, server)
			bundle, request := gatewayRecoveryPending(t, path, server.URL, *now)
			q = request
			var input []byte
			c, e, input = gatewayAssociationChallenge(t, q, *now, "6")
			original, _ := os.ReadFile(path)
			args := gatewayAssociationArgs(ca, path)
			switch kind {
			case "wrong_scope":
				c.WorkspaceID = gatewayCLIID("7")
				raw, _ := json.Marshal(c)
				sum := sha256.Sum256(raw)
				e.ChallengeWire = base64.RawURLEncoding.EncodeToString(raw)
				e.ChallengeSHA256 = hex.EncodeToString(sum[:])
				input, _ = json.Marshal(e)
			case "hash_mismatch":
				e.ChallengeSHA256 = strings.Repeat("0", 64)
				input, _ = json.Marshal(e)
			case "duplicate_input":
				input = append([]byte(`{"schema":"agent-device-challenge-envelope-v1",`), input[1:]...)
			case "endpoint_override":
				args = append(args, "--endpoint", server.URL)
			}
			var output bytes.Buffer
			err := runCommand(&output, bytes.NewReader(input), args, "test")
			if err == nil {
				t.Fatalf("%s accepted invalid phase2 evidence", kind)
			}
			gatewayAssociationNoSecrets(t, append(output.Bytes(), []byte(err.Error())...), bundle, c, e, "")
			local := kind == "wrong_scope" || kind == "hash_mismatch" || kind == "duplicate_input" || kind == "endpoint_override"
			if local {
				if calls.Load() != 0 {
					t.Fatalf("%s reached HTTP before local validation", kind)
				}
			} else {
				if calls.Load() != 1 {
					t.Fatalf("%s did not exercise actual TLS response", kind)
				}
				gatewayCLIReport(t, output.Bytes(), "unresolved", "unknown")
			}
			if _, err := os.Stat(gatewayAssociationArtifact(path, c, e, ".receipt")); !os.IsNotExist(err) {
				t.Fatalf("%s saved invalid acceptance receipt", kind)
			}
			gatewayRecoveryRetained(t, path, original)
		}()
	}
}
