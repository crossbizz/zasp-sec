package gatewayenrollmentcustody

import (
	"bytes"
	"encoding/json"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func currentAuthorityFor(snapshot Snapshot) wire.CurrentAuthority {
	r := snapshot.Request
	return wire.CurrentAuthority{OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, DeviceID: r.DeviceID, DeviceVersion: 4, ReplayFloor: 7, CredentialID: r.CredentialID, CredentialGeneration: r.CredentialGeneration, KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Audience: "runtime-gateway", ExpiresAt: r.ExpiresAt}
}
func observeRecovery(t *testing.T, s *Store, snapshot Snapshot) (*Recovery, time.Time) {
	t.Helper()
	recovery, e := s.BeginRecovery()
	if e != nil {
		t.Fatal(e)
	}
	endpoint, source, e := recovery.Source()
	if e != nil || endpoint != "https://control.example" || !bytes.Equal(source.RequestRaw, snapshot.RequestRaw) {
		t.Fatal("original recovery source", e)
	}
	raw, _ := json.Marshal(currentAuthorityFor(snapshot))
	now := custodyNow().Add(2 * time.Hour)
	if e = recovery.Observe(raw, now.Add(-time.Second), now); e != nil {
		t.Fatal(e)
	}
	return recovery, now
}
func TestGatewayAuthorityRecoveryLiveCapabilityPreservesUnknownEnrollment(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	s, snapshot := openPrepared(t, filepath.Join(dir, "custody.json"))
	defer s.Close()
	recovery, now := observeRecovery(t, s, snapshot)
	defer recovery.Close()
	if e := s.ExportCredential(filepath.Join(dir, "forbidden-offline.json")); e == nil {
		t.Fatal("authority history became enrollment receipt")
	}
	state, e := s.Snapshot()
	if e != nil || state.State != StatePending {
		t.Fatal("unknown enrollment promoted")
	}
	out := filepath.Join(dir, "credential.json")
	if e = recovery.ExportCredential(out, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var credential map[string]string
	if json.Unmarshal(raw, &credential) != nil || len(credential) != 3 || credential["credential_id"] != snapshot.Request.CredentialID || credential["private_key"] == "" {
		t.Fatal("runtime export shape")
	}
	if recovery.ExportCredential(out, now.Add(2*time.Second)) == nil {
		t.Fatal("consumed recovery export reused")
	}
}
func TestGatewayAuthorityRecoveryRestartHistoryIsNeverLive(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "custody.json")
	s, snapshot := openPrepared(t, path)
	recovery, now := observeRecovery(t, s, snapshot)
	recovery.Close()
	artifact := filepath.Join(dir, ".zasp-gateway-enrollment-"+wire.Digest([]byte("custody.json"))+".authority")
	first, e := os.ReadFile(artifact)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.ExportCredential(filepath.Join(dir, "offline.json")) == nil {
		t.Fatal("restart accepted historical authority")
	}
	next, e := s.BeginRecovery()
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if next.ExportCredential(filepath.Join(dir, "never-observed.json"), now) == nil {
		t.Fatal("artifact recreated capability")
	}
	again, e := s.BeginRecovery()
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	updated := currentAuthorityFor(snapshot)
	updated.DeviceVersion++
	updated.ReplayFloor++
	body, _ := json.Marshal(updated)
	later := now.Add(time.Minute)
	if e = again.Observe(body, later.Add(-time.Second), later); e != nil {
		t.Fatal(e)
	}
	second, _ := os.ReadFile(artifact)
	if !bytes.Equal(first, second) {
		t.Fatal("first immutable observation overwritten")
	}
	conflict := filepath.Join(dir, "conflict.json")
	if e = os.WriteFile(conflict, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if again.ExportCredential(conflict, later) == nil {
		t.Fatal("existing export overwritten")
	}
	if again.Observe(body, later, later) == nil || again.ExportCredential(filepath.Join(dir, "retry-after-consumed.json"), later) == nil {
		t.Fatal("failed export capability reset")
	}
}
func TestGatewayAuthorityRecoveryOrphansAliasesAndClosedHandles(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	name := "custody.json"
	authorityName := ".zasp-gateway-enrollment-" + wire.Digest([]byte(name)) + ".authority"
	orphan := filepath.Join(dir, authorityName)
	if e := os.WriteFile(orphan, []byte(`{"orphan":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e := Open(filepath.Join(dir, name)); e == nil {
		s.Close()
		t.Fatal("orphan authority adopted without keybundle")
	}
	dir = t.TempDir()
	s, snapshot := openPrepared(t, filepath.Join(dir, name))
	recovery, now := observeRecovery(t, s, snapshot)
	artifact := filepath.Join(dir, authorityName)
	if recovery.ExportCredential(artifact, now) == nil {
		t.Fatal("authority artifact export alias")
	}
	next, e := s.BeginRecovery()
	if e != nil {
		t.Fatal(e)
	}
	if next.Close() != nil || next.Observe(nil, now, now) == nil || next.ExportCredential(filepath.Join(dir, "closed.json"), now) == nil {
		t.Fatal("closed capability usable")
	}
	last, e := s.BeginRecovery()
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if _, _, e = last.Source(); e == nil {
		t.Fatal("closed store retained recovery authority")
	}
	last.Close()
	recovery.Close()
}
