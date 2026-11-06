package gatewayenrollmentcustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	associationwire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func associationEnvelope(snapshot Snapshot, id string) associationwire.ChallengeEnvelope {
	r := snapshot.Request
	challenge := associationwire.Challenge{Schema: associationwire.ChallengeSchema, ChallengeID: id, AssociationID: "pid_f3f29485-8121-4d74-80ac-797261970ce8", OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, AgentID: "pid_55555555-5555-4555-8555-555555555555", AgentSourceDigest: strings.Repeat("a", 64), DeviceID: r.DeviceID, ExpectedAssociationVersion: 0, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), ExpiresAt: custodyNow().Add(5 * time.Minute)}
	raw, _ := json.Marshal(challenge)
	sum := sha256.Sum256(raw)
	return associationwire.ChallengeEnvelope{Schema: associationwire.EnvelopeSchema, ChallengeWire: base64.RawURLEncoding.EncodeToString(raw), ChallengeSHA256: hex.EncodeToString(sum[:])}
}
func associationReceipt(snapshot AssociationSnapshot) associationwire.AcceptResponse {
	challenge, binding := snapshot.Challenge, snapshot.Binding
	return associationwire.AcceptResponse{ChallengeID: challenge.ChallengeID, ChallengeSHA256: snapshot.Envelope.ChallengeSHA256, AssociationID: challenge.AssociationID, Acceptance: associationwire.Acceptance{RequestSHA256: wire.Digest(snapshot.RequestRaw), Credential: associationwire.DeviceCredential{CredentialID: binding.CredentialID, CredentialGeneration: binding.CredentialGeneration, ExpiresAt: binding.ExpiresAt}, AcceptedAt: custodyNow().Add(123456 * time.Microsecond), ExpiresAt: challenge.ExpiresAt}}
}
func beginAssociation(t *testing.T, s *Store, snapshot Snapshot, id string) (*Association, AssociationSnapshot) {
	t.Helper()
	a, e := s.BeginAssociation(associationEnvelope(snapshot, id), custodyNow())
	if e != nil {
		t.Fatal(e)
	}
	endpoint, state, e := a.Source()
	if e != nil || endpoint != "https://control.example" || state.Binding.CredentialID != snapshot.Request.CredentialID {
		t.Fatal("original bound source", e)
	}
	return a, state
}
func TestAgentDeviceAssociationCustodyMultipleExactIntents(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "custody.json")
	s, snapshot := openPrepared(t, path)
	id := "pid_66666666-6666-4666-8666-666666666666"
	first, state := beginAssociation(t, s, snapshot, id)
	body := append([]byte(nil), state.RequestRaw...)
	namespace := filepath.Join(dir, ".zasp-gateway-associations-"+wire.Digest([]byte("custody.json")))
	info, e := os.Stat(namespace)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("protected namespace", e)
	}
	artifact := filepath.Join(namespace, id+"."+state.Envelope.ChallengeSHA256+".intent")
	raw, e := os.ReadFile(artifact)
	if e != nil || !bytes.Contains(raw, []byte(`"accept_request":`+string(body))) {
		t.Fatal("exact acceptance intent absent before network", e)
	}
	second, other := beginAssociation(t, s, snapshot, "pid_88888888-8888-4888-8888-888888888888")
	if bytes.Equal(other.RequestRaw, body) {
		t.Fatal("second intent reused first slot")
	}
	second.Close()
	first.Close()
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, restored := beginAssociation(t, s, snapshot, id)
	defer again.Close()
	if !bytes.Equal(restored.RequestRaw, body) {
		t.Fatal("restart changed exact intent")
	}
	receipt := associationReceipt(restored)
	if e = again.Confirm(receipt, custodyNow()); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(filepath.Join(namespace, id+"."+restored.Envelope.ChallengeSHA256+".receipt"))
	if e != nil {
		t.Fatal(e)
	}
	receipt.Replayed = true
	if e = again.Confirm(receipt, custodyNow()); e != nil {
		t.Fatal(e)
	}
	retained, _ := os.ReadFile(filepath.Join(namespace, id+"."+restored.Envelope.ChallengeSHA256+".receipt"))
	if !bytes.Equal(original, retained) {
		t.Fatal("receipt overwritten on replay")
	}
	local, e := s.Snapshot()
	if e != nil || local.State != StatePending {
		t.Fatal("association promoted enrollment proof")
	}
}
func TestAgentDeviceAssociationCustodyStageAndOrphanBoundaries(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	namespace := filepath.Join(dir, ".zasp-gateway-associations-"+wire.Digest([]byte("custody.json")))
	if e := os.Mkdir(namespace, 0700); e != nil {
		t.Fatal(e)
	}
	if s, e := Open(filepath.Join(dir, "custody.json")); e == nil {
		s.Close()
		t.Fatal("orphan namespace accepted")
	}
	dir = t.TempDir()
	path := filepath.Join(dir, "custody.json")
	s, snapshot := openPrepared(t, path)
	id := "pid_66666666-6666-4666-8666-666666666666"
	a, state := beginAssociation(t, s, snapshot, id)
	a.Close()
	s.Close()
	namespace = filepath.Join(dir, ".zasp-gateway-associations-"+wire.Digest([]byte("custody.json")))
	name := id + "." + state.Envelope.ChallengeSHA256 + ".intent"
	original, _ := os.ReadFile(filepath.Join(namespace, name))
	if e := os.Rename(filepath.Join(namespace, name), filepath.Join(namespace, stageName(name))); e != nil {
		t.Fatal(e)
	}
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	a, restored := beginAssociation(t, s, snapshot, id)
	if !bytes.Equal(restored.RequestRaw, state.RequestRaw) {
		t.Fatal("stage changed intent")
	}
	a.Close()
	s.Close()
	got, _ := os.ReadFile(filepath.Join(namespace, name))
	if !bytes.Equal(got, original) {
		t.Fatal("stage changed artifact")
	}
	if e = os.WriteFile(filepath.Join(namespace, stageName(name)), []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal("Open must not scan unrelated histories", e)
	}
	defer s.Close()
	if a, e = s.BeginAssociation(state.Envelope, custodyNow()); e == nil {
		a.Close()
		t.Fatal("conflicting selected stage accepted")
	}
	partial, _ := os.ReadFile(filepath.Join(namespace, stageName(name)))
	if string(partial) != "partial" {
		t.Fatal("partial evidence deleted")
	}
}
func TestAgentDeviceAssociationCustodyBothExportPathsReserveNamespace(t *testing.T) {
	if !Supported() {
		t.Skip("Linux custody")
	}
	dir := t.TempDir()
	s, snapshot := openPrepared(t, filepath.Join(dir, "custody.json"))
	defer s.Close()
	a, _ := beginAssociation(t, s, snapshot, "pid_66666666-6666-4666-8666-666666666666")
	defer a.Close()
	r := snapshot.Request
	receipt := wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: wire.Digest(snapshot.RequestRaw), OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, DeviceID: r.DeviceID, EnrollmentID: r.EnrollmentID, TokenGeneration: r.TokenGeneration, CredentialID: r.CredentialID, CredentialGeneration: r.CredentialGeneration, KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Audience: "runtime-gateway", IssuedAt: custodyNow(), ExpiresAt: r.ExpiresAt}
	if e := s.Accept(receipt); e != nil {
		t.Fatal(e)
	}
	namespace := filepath.Join(dir, ".zasp-gateway-associations-"+wire.Digest([]byte("custody.json")))
	nested := filepath.Join(namespace, "nested")
	if e := os.Mkdir(nested, 0700); e != nil {
		t.Fatal(e)
	}
	for _, output := range []string{filepath.Join(namespace, "credential.json"), filepath.Join(nested, "credential.json")} {
		if s.ExportCredential(output) == nil {
			t.Fatal("normal export entered association namespace")
		}
		recovery, now := observeRecovery(t, s, snapshot)
		if recovery.ExportCredential(output, now) == nil {
			recovery.Close()
			t.Fatal("recovery export entered namespace")
		}
		recovery.Close()
	}
	if e := s.ExportCredential(filepath.Join(dir, "allowed.json")); e != nil {
		t.Fatal("ordinary export regressed", e)
	}
}
