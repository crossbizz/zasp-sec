package gatewayenrollmentcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tokenFixture() wire.TokenBundle {
	return wire.TokenBundle{Schema: wire.TokenSchema, OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", DeviceID: "pid_44444444-4444-4444-8444-444444444444", EnrollmentID: "pid_55555555-5555-4555-8555-555555555555", TokenGeneration: 1, CredentialGeneration: 1, EnrollmentExpiresAt: time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC), Locator: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), Secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))}
}
func custodyNow() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) }
func openPrepared(t *testing.T, path string) (*Store, Snapshot) {
	t.Helper()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	snap, e := s.Prepare(tokenFixture(), "https://control.example", 24*time.Hour, custodyNow())
	if e != nil {
		s.Close()
		t.Fatal(e)
	}
	return s, snap
}
func TestGatewayEnrollmentCustodyDurableReplay(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	path := filepath.Join(t.TempDir(), "custody.json")
	s, first := openPrepared(t, path)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 || bytes.Contains(raw, []byte(tokenFixture().Secret)) || bytes.Contains(raw, []byte(tokenFixture().Locator)) {
		t.Fatal("unsafe custody/token persistence")
	}
	var bundle struct {
		PrivateKey string          `json:"private_key"`
		Request    json.RawMessage `json:"request"`
	}
	if json.Unmarshal(raw, &bundle) != nil || !bytes.Equal(bundle.Request, first.RequestRaw) {
		t.Fatal("exact intent not durable")
	}
	key, e := base64.RawURLEncoding.DecodeString(bundle.PrivateKey)
	if e != nil || len(key) != 64 || base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) != first.Request.PublicKey {
		t.Fatal("key/request binding")
	}
	msg := []byte("owned-message")
	sig, e := s.Sign(msg)
	if e != nil || !ed25519.Verify(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("retained signer")
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	second, e := s.Prepare(tokenFixture(), "https://control.example", 24*time.Hour, custodyNow().Add(time.Minute))
	if e != nil || !bytes.Equal(first.RequestRaw, second.RequestRaw) || second.Request != first.Request {
		t.Fatal("replay regenerated intent", e)
	}
	second.RequestRaw[0] = 'x'
	current, e := s.Snapshot()
	if e != nil || !bytes.Equal(current.RequestRaw, first.RequestRaw) {
		t.Fatal("snapshot aliases custody")
	}
}
func TestGatewayEnrollmentCustodyExclusiveConflict(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	path := filepath.Join(t.TempDir(), "custody.json")
	s, first := openPrepared(t, path)
	defer s.Close()
	if other, e := Open(path); e == nil {
		other.Close()
		t.Fatal("second owner")
	}
	changed := tokenFixture()
	changed.DeviceID = changed.WorkspaceID
	if _, e := s.Prepare(changed, "https://control.example", 24*time.Hour, custodyNow()); e == nil {
		t.Fatal("changed identity")
	}
	if _, e := s.Prepare(tokenFixture(), "https://foreign.example", 24*time.Hour, custodyNow()); e == nil {
		t.Fatal("changedendpoint")
	}
	after, e := s.Snapshot()
	if e != nil || !bytes.Equal(first.RequestRaw, after.RequestRaw) {
		t.Fatal("conflict replaced key/intent")
	}
}
func stageName(name string) string {
	d := sha256.Sum256([]byte(name))
	return ".zasp-publish-" + hex.EncodeToString(d[:]) + ".prepare"
}
func TestGatewayEnrollmentCustodyStageRecovery(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "custody.json")
	s, first := openPrepared(t, path)
	s.Close()
	stage := filepath.Join(dir, stageName("custody.json"))
	if e := os.Rename(path, stage); e != nil {
		t.Fatal(e)
	}
	s, second := openPrepared(t, path)
	if !bytes.Equal(first.RequestRaw, second.RequestRaw) {
		t.Fatal("orphan stage regenerated")
	}
	s.Close()
	if _, e := os.Stat(stage); !os.IsNotExist(e) {
		t.Fatal("owned stage not cleaned")
	}
	if e := os.Link(path, stage); e != nil {
		t.Fatal(e)
	}
	s, third := openPrepared(t, path)
	if !bytes.Equal(first.RequestRaw, third.RequestRaw) {
		t.Fatal("linked pair changed")
	}
	s.Close()
	dir2 := t.TempDir()
	bad := filepath.Join(dir2, "custody.json")
	partial := []byte(`{"private_key":"incomplete`)
	if e := os.WriteFile(filepath.Join(dir2, stageName("custody.json")), partial, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := Open(bad)
	if e == nil {
		_, e = s.Prepare(tokenFixture(), "https://control.example", 24*time.Hour, custodyNow())
		s.Close()
	}
	if e == nil {
		t.Fatal("partial stage accepted")
	}
	got, _ := os.ReadFile(filepath.Join(dir2, stageName("custody.json")))
	if !bytes.Equal(got, partial) {
		t.Fatal("partial key overwritten")
	}
}
func TestGatewayEnrollmentCustodyReceiptExport(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	s, snap := openPrepared(t, filepath.Join(dir, "custody.json"))
	defer s.Close()
	out := filepath.Join(dir, "credential.json")
	if s.ExportCredential(out) == nil {
		t.Fatal("export before accepted")
	}
	r := snap.Request
	receipt := wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: wire.Digest(snap.RequestRaw), OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, DeviceID: r.DeviceID, EnrollmentID: r.EnrollmentID, TokenGeneration: r.TokenGeneration, CredentialID: r.CredentialID, CredentialGeneration: r.CredentialGeneration, KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Audience: "runtime-gateway", IssuedAt: custodyNow(), ExpiresAt: r.ExpiresAt}
	bad := receipt
	bad.PublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if s.Accept(bad) == nil {
		t.Fatal("foreignkey receipt")
	}
	if e := s.Accept(receipt); e != nil {
		t.Fatal(e)
	}
	if e := s.ExportCredential(out); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(out)
	var config map[string]string
	if json.Unmarshal(raw, &config) != nil || len(config) != 3 || config["credential_id"] != r.CredentialID || config["key_id"] != r.KeyID || config["private_key"] == "" {
		t.Fatal("runtime credential shape")
	}
	if e := s.ExportCredential(out); e != nil {
		t.Fatal("exact export retry", e)
	}
	if e := os.WriteFile(out, []byte(`{"unrelated":"keep"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if s.ExportCredential(out) == nil {
		t.Fatal("overwrote existing unrelated credential")
	}
	current, _ := os.ReadFile(out)
	if !strings.Contains(string(current), "keep") {
		t.Fatal("lost unrelated credential")
	}
}
