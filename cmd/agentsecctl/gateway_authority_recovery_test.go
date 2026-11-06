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
	"sync/atomic"
	"testing"
	"time"

	custody "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentcustody"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

const gatewayRecoveryAuthorityPath = "/internal/v1/runtime-gateway/authority"

type gatewayRecoveryUnreadable struct{ reads int }

func (r *gatewayRecoveryUnreadable) Read([]byte) (int, error) {
	r.reads++
	return 0, io.ErrUnexpectedEOF
}
func gatewayRecoveryArgs(ca, path, output string) []string {
	args := []string{"gateway", "recover", "--custody-file", path, "--ca-bundle-file", ca, "--timeout", "10s"}
	if output != "" {
		args = append(args, "--credential-output", output)
	}
	return args
}
func gatewayRecoveryAuthority(q wire.Request, version, floor int64) map[string]any {
	return map[string]any{"organization_id": q.OrganizationID, "workspace_id": q.WorkspaceID, "environment_id": q.EnvironmentID, "device_id": q.DeviceID, "device_version": version, "replay_floor": floor, "credential_id": q.CredentialID, "credential_generation": q.CredentialGeneration, "key_id": q.KeyID, "algorithm": q.Algorithm, "public_key": q.PublicKey, "audience": "runtime-gateway", "expires_at": q.ExpiresAt}
}
func gatewayRecoveryVerify(t *testing.T, r *http.Request, q wire.Request) {
	t.Helper()
	raw, _ := io.ReadAll(r.Body)
	if r.Method != "GET" || r.URL.Path != gatewayRecoveryAuthorityPath || r.URL.RawQuery != "" || len(raw) != 0 || r.Header.Get("Authorization") != "ZaspGatewayV1 "+q.CredentialID {
		t.Error("authority request changed fixed original credential context")
	}
	sum := sha256.Sum256(nil)
	digest := hex.EncodeToString(sum[:])
	stamp := r.Header.Get("X-Zasp-Gateway-Timestamp")
	public, _ := base64.RawURLEncoding.DecodeString(q.PublicKey)
	sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Zasp-Gateway-Signature"))
	message := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", "GET", r.Host, gatewayRecoveryAuthorityPath, q.CredentialID, stamp, digest}, "\n"))
	if _, err := time.Parse(time.RFC3339, stamp); err != nil || r.Header.Get("X-Zasp-Content-SHA256") != digest || !ed25519.Verify(public, message, sig) {
		t.Error("retained-key signature does not bind actual authority GET")
	}
}
func gatewayRecoveryArtifact(path, suffix string) string {
	sum := sha256.Sum256([]byte(filepath.Base(path)))
	return filepath.Join(filepath.Dir(path), ".zasp-gateway-enrollment-"+hex.EncodeToString(sum[:])+suffix)
}
func gatewayRecoveryPending(t *testing.T, path, endpoint string, now time.Time) (wire.TokenBundle, wire.Request) {
	t.Helper()
	bundle := gatewayCLIBundle(now)
	store, err := custody.Open(path)
	if err != nil {
		t.Fatal("fixture custody open", err)
	}
	snapshot, err := store.Prepare(bundle, endpoint, 24*time.Hour, now)
	if err != nil {
		t.Fatal("fixture custody prepare", err)
	}
	if store.Close() != nil {
		t.Fatal("fixture custody close")
	}
	return bundle, snapshot.Request
}
func gatewayRecoveryReport(t *testing.T, raw []byte, state string, now time.Time) {
	t.Helper()
	gatewayCLIReport(t, raw, state, "unknown")
	var report map[string]any
	if json.Unmarshal(raw, &report) != nil || report["source"] != "current_authority" || report["observed_at"] != now.Format(time.RFC3339) {
		t.Fatal("missing explicit live authority evidence source/time")
	}
}
func gatewayRecoveryRetained(t *testing.T, path string, original []byte) {
	t.Helper()
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, original) {
		t.Fatal("recovery changed original key/intent")
	}
	if _, err := os.Stat(gatewayRecoveryArtifact(path, ".receipt")); !os.IsNotExist(err) {
		t.Fatal("recovery fabricated original enrollment receipt")
	}
	store, err := custody.Open(path)
	if err != nil {
		t.Fatal("reopen original custody", err)
	}
	defer store.Close()
	snapshot, err := store.Snapshot()
	if err != nil || snapshot.State != custody.StatePending {
		t.Fatal("historical authority changed original enrollment outcome")
	}
}

func TestGatewayAuthorityRecoveryCommandLostEnrollmentAndExpiredToken(t *testing.T) {
	now := gatewayCLIClock(t)
	bundle := gatewayCLIBundle(*now)
	path := filepath.Join(t.TempDir(), "pending.json")
	outputPath := filepath.Join(t.TempDir(), "credential.json")
	var request wire.Request
	var calls atomic.Int32
	var private string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == "POST" {
			raw, _ := io.ReadAll(r.Body)
			private = gatewayCLIVerifyRequest(t, r, raw, path, bundle)
			_ = json.Unmarshal(raw, &request)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		gatewayRecoveryVerify(t, r, request)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(gatewayRecoveryAuthority(request, 3, 7))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	var output bytes.Buffer
	if runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), gatewayCLIArgs(server.URL, ca, path), "test") == nil {
		t.Fatal("lost enrollment response must remain unknown")
	}
	original, _ := os.ReadFile(path)
	*now = now.Add(2 * time.Hour)
	output.Reset()
	input := &gatewayRecoveryUnreadable{}
	if err := runCommand(&output, input, gatewayRecoveryArgs(ca, path, outputPath), "test"); err != nil {
		t.Fatal("actual expired-token authority recovery failed", err)
	}
	if input.reads != 0 {
		t.Fatal("recovery consumed token stdin")
	}
	gatewayRecoveryReport(t, output.Bytes(), "credential_exported_from_current_authority", *now)
	gatewayCLINoSecrets(t, output.Bytes(), bundle, private)
	raw, err := os.ReadFile(outputPath)
	var credential struct {
		CredentialID string `json:"credential_id"`
		KeyID        string `json:"key_id"`
		PrivateKey   string `json:"private_key"`
	}
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.PrivateKey != private || credential.CredentialID != request.CredentialID || credential.KeyID != request.KeyID {
		t.Fatal("recovery export did not retain original exact credential")
	}
	info, _ := os.Stat(outputPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("export permissions")
	}
	if calls.Load() != 2 {
		t.Fatal("recovery reenrolled or omitted live authority check")
	}
	gatewayRecoveryRetained(t, path, original)
}

func TestGatewayAuthorityRecoveryCommandFreshRetryPreservesHistory(t *testing.T) {
	now := gatewayCLIClock(t)
	path := filepath.Join(t.TempDir(), "pending.json")
	var request wire.Request
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		gatewayRecoveryVerify(t, r, request)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(gatewayRecoveryAuthority(request, int64(n)+1, int64(n)*10))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	bundle, q := gatewayRecoveryPending(t, path, server.URL, *now)
	request = q
	original, _ := os.ReadFile(path)
	*now = now.Add(2 * time.Hour)
	var output bytes.Buffer
	if err := runCommand(&output, &gatewayRecoveryUnreadable{}, gatewayRecoveryArgs(ca, path, ""), "test"); err != nil {
		t.Fatal("first live recovery failed", err)
	}
	gatewayRecoveryReport(t, output.Bytes(), "current_authority_observed", *now)
	history, err := os.ReadFile(gatewayRecoveryArtifact(path, ".authority"))
	if err != nil {
		t.Fatal("missing historical authority artifact")
	}
	output.Reset()
	offline := filepath.Join(t.TempDir(), "offline.json")
	if runCommand(&output, strings.NewReader(""), []string{"gateway", "export", "--custody-file", path, "--credential-output", offline}, "test") == nil {
		t.Fatal("historical artifact authorized offline receipt export")
	}
	*now = now.Add(time.Minute)
	output.Reset()
	fresh := filepath.Join(t.TempDir(), "fresh.json")
	if err := runCommand(&output, &gatewayRecoveryUnreadable{}, gatewayRecoveryArgs(ca, path, fresh), "test"); err != nil {
		t.Fatal("live retry with advanced version/floor failed", err)
	}
	gatewayRecoveryReport(t, output.Bytes(), "credential_exported_from_current_authority", *now)
	retained, _ := os.ReadFile(gatewayRecoveryArtifact(path, ".authority"))
	if !bytes.Equal(history, retained) || calls.Load() != 2 {
		t.Fatal("retry rewrote history or reused historical proof")
	}
	gatewayCLINoSecrets(t, output.Bytes(), bundle, "")
	gatewayRecoveryRetained(t, path, original)
}

func TestGatewayAuthorityRecoveryCommandRefusesInvalidEvidenceAndInputs(t *testing.T) {
	for _, kind := range []string{"wrong_tuple", "expired_after_response", "revoked", "cacheable", "redirect", "duplicate_json", "endpoint_override", "unbounded_timeout"} {
		func() {
			now := gatewayCLIClock(t)
			path := filepath.Join(t.TempDir(), "pending.json")
			var request wire.Request
			var calls atomic.Int32
			var expired atomic.Bool
			priorClock := gatewayEnrollmentNow
			gatewayEnrollmentNow = func() time.Time {
				if expired.Load() {
					return request.ExpiresAt
				}
				return *now
			}
			defer func() { gatewayEnrollmentNow = priorClock }()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				gatewayRecoveryVerify(t, r, request)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				v := gatewayRecoveryAuthority(request, 2, 5)
				switch kind {
				case "wrong_tuple":
					v["device_id"] = gatewayCLIID("9")
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
				case "duplicate_json":
					raw, _ := json.Marshal(v)
					_, _ = w.Write(append([]byte(`{"device_id":"`+request.DeviceID+`",`), raw[1:]...))
					return
				}
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			ca := gatewayCLICA(t, server)
			bundle, q := gatewayRecoveryPending(t, path, server.URL, *now)
			request = q
			original, _ := os.ReadFile(path)
			*now = now.Add(2 * time.Hour)
			destination := filepath.Join(t.TempDir(), "refused.json")
			args := gatewayRecoveryArgs(ca, path, destination)
			if kind == "endpoint_override" {
				args = append(args, "--endpoint", server.URL)
			}
			if kind == "unbounded_timeout" {
				args[len(args)-3] = "31s"
			}
			var output bytes.Buffer
			input := &gatewayRecoveryUnreadable{}
			err := runCommand(&output, input, args, "test")
			if err == nil {
				t.Fatal("invalid authority/input accepted")
			}
			gatewayCLINoSecrets(t, append(output.Bytes(), []byte(err.Error())...), bundle, "")
			if input.reads != 0 {
				t.Fatal("refusal consumed stdin")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("refused evidence exported credential")
			}
			if kind == "endpoint_override" || kind == "unbounded_timeout" {
				if calls.Load() != 0 {
					t.Fatal("invalid command reached network")
				}
			} else if calls.Load() != 1 {
				t.Fatal("refusal was not one live request")
			}
			gatewayRecoveryRetained(t, path, original)
		}()
	}
}
