package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
)

func gatewayCLIID(n string) string { return "pid_a000000" + n + "-0000-4000-8000-00000000000" + n }
func gatewayCLIClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)
	previous := gatewayEnrollmentNow
	gatewayEnrollmentNow = func() time.Time { return now }
	t.Cleanup(func() { gatewayEnrollmentNow = previous })
	return &now
}
func gatewayCLIBundle(now time.Time) wire.TokenBundle {
	return wire.TokenBundle{Schema: wire.TokenSchema, OrganizationID: gatewayCLIID("1"), WorkspaceID: gatewayCLIID("2"), EnvironmentID: gatewayCLIID("3"), DeviceID: gatewayCLIID("4"), EnrollmentID: gatewayCLIID("5"), TokenGeneration: 2, CredentialGeneration: 1, EnrollmentExpiresAt: now.Add(time.Hour), Locator: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x34}, 16)), Secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x56}, 32))}
}
func gatewayCLIInput(t *testing.T, bundle wire.TokenBundle) []byte {
	t.Helper()
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal("fixture encoding")
	}
	return raw
}
func gatewayCLICA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0644); err != nil {
		t.Fatal("CA fixture")
	}
	return path
}
func gatewayCLIArgs(endpoint, ca, custody string) []string {
	return []string{"gateway", "enroll", "--endpoint", endpoint, "--ca-bundle-file", ca, "--custody-file", custody, "--credential-ttl", "24h", "--timeout", "10s"}
}
func gatewayCLIReceipt(raw []byte, replayed bool, issued time.Time) wire.Receipt {
	var request wire.Request
	_ = json.Unmarshal(raw, &request)
	sum := sha256.Sum256(raw)
	return wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: hex.EncodeToString(sum[:]), OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, DeviceID: request.DeviceID, EnrollmentID: request.EnrollmentID, TokenGeneration: request.TokenGeneration, CredentialID: request.CredentialID, CredentialGeneration: request.CredentialGeneration, KeyID: request.KeyID, Algorithm: request.Algorithm, PublicKey: request.PublicKey, Audience: "runtime-gateway", IssuedAt: issued, ExpiresAt: request.ExpiresAt, Replayed: replayed}
}
func gatewayCLIRespond(w http.ResponseWriter, receipt wire.Receipt) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(receipt)
}
func gatewayCLIReport(t *testing.T, raw []byte, state, outcome string) {
	t.Helper()
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("missing bounded JSON report")
	}
	var gotState, gotOutcome string
	_ = json.Unmarshal(value["state"], &gotState)
	_ = json.Unmarshal(value["outcome"], &gotOutcome)
	if gotState != state || gotOutcome != outcome {
		t.Fatalf("unexpected state/outcome: %q/%q", gotState, gotOutcome)
	}
}
func gatewayCLINoSecrets(t *testing.T, output []byte, bundle wire.TokenBundle, private string) {
	t.Helper()
	for _, secret := range []string{bundle.Locator, bundle.Secret, private} {
		if secret != "" && bytes.Contains(output, []byte(secret)) {
			t.Fatal("secret material escaped command output")
		}
	}
}
func gatewayCLIVerifyRequest(t *testing.T, r *http.Request, body []byte, custody string, bundle wire.TokenBundle) string {
	t.Helper()
	if r.Method != "POST" || r.URL.Path != wire.EnrollmentPath || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != wire.AuthorizationScheme+" "+bundle.Locator+"."+bundle.Secret {
		t.Error("wrong fixed enrollment request context")
	}
	info, err := os.Stat(custody)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Error("HTTP preceded durable private custody")
		return ""
	}
	raw, err := os.ReadFile(custody)
	if err != nil {
		t.Error("custody readback missing")
		return ""
	}
	var disk struct {
		PrivateKey string          `json:"private_key"`
		Request    json.RawMessage `json:"request"`
	}
	if json.Unmarshal(raw, &disk) != nil || !bytes.Equal(disk.Request, body) {
		t.Error("durable original request differs from sent bytes")
		return ""
	}
	private, err := base64.RawURLEncoding.DecodeString(disk.PrivateKey)
	if err != nil || len(private) != 64 {
		t.Error("missing original durable key")
		return ""
	}
	var request wire.Request
	if json.Unmarshal(body, &request) != nil {
		t.Error("request decode")
		return ""
	}
	public, err := base64.RawURLEncoding.DecodeString(request.PublicKey)
	if err != nil || len(public) != 32 || !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		t.Error("submitted key differs from retained private key")
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	stamp := r.Header.Get("X-Zasp-Gateway-Timestamp")
	sig, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Zasp-Gateway-Signature"))
	message := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", "POST", r.Host, wire.EnrollmentPath, request.CredentialID, stamp, digest}, "\n"))
	if r.Header.Get("X-Zasp-Content-SHA256") != digest || err != nil || !ed25519.Verify(public, message, sig) {
		t.Error("actual submitted-key signature does not bind fixed HTTP context")
	}
	return disk.PrivateKey
}

func TestGatewayEnrollmentCommandConnectedTLSAndCredentialExport(t *testing.T) {
	now := gatewayCLIClock(t)
	bundle := gatewayCLIBundle(*now)
	custody := filepath.Join(t.TempDir(), "gateway-custody.json")
	outputPath := filepath.Join(t.TempDir(), "runtime-credential.json")
	privateSeen := make(chan string, 1)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		privateSeen <- gatewayCLIVerifyRequest(t, r, body, custody, bundle)
		gatewayCLIRespond(w, gatewayCLIReceipt(body, false, *now))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	var output bytes.Buffer
	if err := runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), gatewayCLIArgs(server.URL, ca, custody), "test"); err != nil {
		t.Fatal("actual gateway enroll command did not complete", err)
	}
	private := <-privateSeen
	gatewayCLIReport(t, output.Bytes(), "accepted", "confirmed")
	gatewayCLINoSecrets(t, output.Bytes(), bundle, private)
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatal("enroll exported credentials before explicit export")
	}
	output.Reset()
	if err := runCommand(&output, strings.NewReader(""), []string{"gateway", "export", "--custody-file", custody, "--credential-output", outputPath}, "test"); err != nil {
		t.Fatal("explicit credential export failed", err)
	}
	gatewayCLIReport(t, output.Bytes(), "exported", "confirmed")
	gatewayCLINoSecrets(t, output.Bytes(), bundle, private)
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal("runtime credential not durable")
	}
	var credential struct {
		CredentialID string `json:"credential_id"`
		KeyID        string `json:"key_id"`
		PrivateKey   string `json:"private_key"`
	}
	if json.Unmarshal(raw, &credential) != nil || credential.PrivateKey != private || credential.CredentialID == "" || credential.KeyID == "" {
		t.Fatal("export differs from original runtime credential")
	}
	canonical, _ := json.Marshal(credential)
	info, _ := os.Stat(outputPath)
	if !bytes.Equal(raw, canonical) || info.Mode().Perm() != 0600 {
		t.Fatal("runtime credential not canonical0600")
	}
	if calls.Load() != 1 {
		t.Fatal("export repeated enrollment HTTP")
	}
	// Late command-boundary controls: retained acceptance is not a license to
	// replace an operator file or report a conflicting new input as accepted.
	if err := runCommand(shortWriter{}, strings.NewReader(""), []string{"gateway", "status", "--custody-file", custody}, "test"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short status writer failure lost", err)
	}
	existing := filepath.Join(t.TempDir(), "operator-credential.json")
	original := []byte("existing-operator-owned-data")
	if os.WriteFile(existing, original, 0600) != nil {
		t.Fatal("existing output fixture")
	}
	output.Reset()
	if runCommand(&output, strings.NewReader(""), []string{"gateway", "export", "--custody-file", custody, "--credential-output", existing}, "test") == nil {
		t.Fatal("differing existing output replaced")
	}
	retained, _ := os.ReadFile(existing)
	if !bytes.Equal(retained, original) {
		t.Fatal("operator output changed")
	}
	changed := bundle
	changed.DeviceID = gatewayCLIID("8")
	output.Reset()
	if runCommand(&output, bytes.NewReader(gatewayCLIInput(t, changed)), gatewayCLIArgs(server.URL, ca, custody), "test") == nil {
		t.Fatal("conflicting token metadata accepted")
	}
	gatewayCLIReport(t, output.Bytes(), "unresolved", "unknown")
	if calls.Load() != 1 {
		t.Fatal("conflicting accepted custody reached network")
	}
}

func TestGatewayEnrollmentCommandUnknownRetryRetainsExactIntent(t *testing.T) {
	now := gatewayCLIClock(t)
	bundle := gatewayCLIBundle(*now)
	custody := filepath.Join(t.TempDir(), "pending.json")
	var mu sync.Mutex
	var bodies [][]byte
	var private string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		retained := gatewayCLIVerifyRequest(t, r, body, custody, bundle)
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		attempt := len(bodies)
		if private == "" {
			private = retained
		} else if private != retained {
			t.Error("unknown outcome regenerated key")
		}
		mu.Unlock()
		if attempt == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				connection.Close()
			}
			return
		}
		gatewayCLIRespond(w, gatewayCLIReceipt(body, true, now.Add(-time.Minute)))
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	args := gatewayCLIArgs(server.URL, ca, custody)
	var output bytes.Buffer
	if err := runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), args, "test"); err == nil {
		t.Fatal("unknown connection outcome reported enrolled")
	}
	gatewayCLIReport(t, output.Bytes(), "pending", "unknown")
	mu.Lock()
	retainedPrivate := private
	mu.Unlock()
	gatewayCLINoSecrets(t, output.Bytes(), bundle, retainedPrivate)
	*now = now.Add(time.Minute)
	output.Reset()
	if err := runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), args, "test"); err != nil {
		t.Fatal("same original enrollment retry failed", err)
	}
	gatewayCLIReport(t, output.Bytes(), "accepted", "confirmed")
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("retry altered original body, identity, key or expiry")
	}
}

func TestGatewayEnrollmentCommandLocalStatusAndExpiredUnknown(t *testing.T) {
	now := gatewayCLIClock(t)
	bundle := gatewayCLIBundle(*now)
	custody := filepath.Join(t.TempDir(), "unresolved.json")
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		gatewayCLIVerifyRequest(t, r, body, custody, bundle)
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "private upstream failure "+bundle.Secret)
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	args := gatewayCLIArgs(server.URL, ca, custody)
	var output bytes.Buffer
	if runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), args, "test") == nil {
		t.Fatal("failed enrollment accepted")
	}
	before, err := os.ReadFile(custody)
	if err != nil {
		t.Fatal("unknown key not retained")
	}
	*now = bundle.EnrollmentExpiresAt.Add(time.Second)
	output.Reset()
	if err := runCommand(&output, strings.NewReader(""), []string{"gateway", "status", "--custody-file", custody}, "test"); err != nil {
		t.Fatal("local status failed", err)
	}
	gatewayCLIReport(t, output.Bytes(), "pending", "unknown")
	gatewayCLINoSecrets(t, output.Bytes(), bundle, "")
	output.Reset()
	if runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), args, "test") == nil {
		t.Fatal("expired unknown outcome reported resolved")
	}
	gatewayCLINoSecrets(t, output.Bytes(), bundle, "")
	if calls.Load() != 1 {
		t.Fatal("expired local pending attempted enrollment or status network")
	}
	after, _ := os.ReadFile(custody)
	if !bytes.Equal(before, after) {
		t.Fatal("expiry changed original custody")
	}
	output.Reset()
	path := filepath.Join(t.TempDir(), "unconfirmed.json")
	if runCommand(&output, strings.NewReader(""), []string{"gateway", "export", "--custody-file", custody, "--credential-output", path}, "test") == nil {
		t.Fatal("unconfirmed credentials exported")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pending key published to runtime output")
	}
}

func TestGatewayEnrollmentCommandRefusesUntrustedInputsAndReceipts(t *testing.T) {
	now := gatewayCLIClock(t)
	bundle := gatewayCLIBundle(*now)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		receipt := gatewayCLIReceipt(body, false, *now)
		receipt.DeviceID = gatewayCLIID("9")
		gatewayCLIRespond(w, receipt)
	}))
	defer server.Close()
	ca := gatewayCLICA(t, server)
	for _, item := range []struct {
		name   string
		mutate func([]string) []string
		input  []byte
	}{
		{"cleartext origin", func(a []string) []string { a[3] = strings.Replace(a[3], "https:", "http:", 1); return a }, gatewayCLIInput(t, bundle)},
		{"secret flag", func(a []string) []string { return append(a, "--enrollment-secret", bundle.Secret) }, gatewayCLIInput(t, bundle)},
		{"duplicate input", func(a []string) []string { return a }, append([]byte(`{"schema":"gateway-enrollment-token-v1",`), gatewayCLIInput(t, bundle)[1:]...)},
		{"oversized input", func(a []string) []string { return a }, bytes.Repeat([]byte("x"), 4097)},
	} {
		t.Run(item.name, func(t *testing.T) {
			custody := filepath.Join(t.TempDir(), "invalid.json")
			args := item.mutate(gatewayCLIArgs(server.URL, ca, custody))
			var output bytes.Buffer
			if runCommand(&output, bytes.NewReader(item.input), args, "test") == nil {
				t.Fatal("untrusted command accepted")
			}
			gatewayCLINoSecrets(t, output.Bytes(), bundle, "")
			if _, err := os.Stat(custody); !os.IsNotExist(err) {
				t.Fatal("invalid input created identity custody")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached network")
	}
	custody := filepath.Join(t.TempDir(), "foreign-receipt.json")
	var output bytes.Buffer
	if runCommand(&output, bytes.NewReader(gatewayCLIInput(t, bundle)), gatewayCLIArgs(server.URL, ca, custody), "test") == nil {
		t.Fatal("foreign receipt accepted")
	}
	gatewayCLIReport(t, output.Bytes(), "pending", "unknown")
	gatewayCLINoSecrets(t, output.Bytes(), bundle, "")
	if calls.Load() != 1 {
		t.Fatal("real TLS foreign receipt case was not executed")
	}
}
