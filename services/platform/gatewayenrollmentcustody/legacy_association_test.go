package gatewayenrollmentcustody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	associationwire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type legacyCustodyFixture struct {
	source, state string
	raw           []byte
	key           ed25519.PrivateKey
	authority     wire.CurrentAuthority
	envelope      associationwire.ChallengeEnvelope
	now           time.Time
}

func legacyCustodyFiles(t *testing.T) legacyCustodyFixture {
	t.Helper()
	if !Supported() {
		t.Skip("Linux custody")
	}
	sourceDir, stateDir := t.TempDir(), t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32))
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	now := time.Now().UTC().Truncate(time.Second)
	f := legacyCustodyFixture{source: filepath.Join(sourceDir, "device.json"), state: filepath.Join(stateDir, "association-state.json"), key: key, now: now}
	f.authority = wire.CurrentAuthority{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", DeviceID: "pid_44444444-4444-4444-8444-444444444444", CredentialID: "pid_77777777-7777-4777-8777-777777777777", CredentialGeneration: 1, DeviceVersion: 1, ReplayFloor: 0, KeyID: "gateway_01234567", Algorithm: "Ed25519", PublicKey: public, Audience: "runtime-gateway", ExpiresAt: now.Add(time.Hour)}
	f.raw = []byte("{\n \"private_key\":\"" + base64.RawURLEncoding.EncodeToString(key) + "\",\n \"key_id\":\"" + f.authority.KeyID + "\",\n \"credential_id\":\"" + f.authority.CredentialID + "\"\n}\n")
	if e := os.WriteFile(f.source, f.raw, 0600); e != nil {
		t.Fatal(e)
	}
	c := associationwire.Challenge{Schema: associationwire.ChallengeSchema, ChallengeID: "pid_66666666-6666-4666-8666-666666666666", AssociationID: "pid_f3f29485-8121-4d74-80ac-797261970ce8", OrganizationID: f.authority.OrganizationID, WorkspaceID: f.authority.WorkspaceID, EnvironmentID: f.authority.EnvironmentID, AgentID: "pid_55555555-5555-4555-8555-555555555555", AgentSourceDigest: strings.Repeat("a", 64), DeviceID: f.authority.DeviceID, ExpectedAssociationVersion: 0, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), ExpiresAt: now.Add(5 * time.Minute)}
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	f.envelope = associationwire.ChallengeEnvelope{Schema: associationwire.EnvelopeSchema, ChallengeWire: base64.RawURLEncoding.EncodeToString(raw), ChallengeSHA256: wire.Digest(raw)}
	return f
}
func legacyCustodyOpen(t *testing.T, f legacyCustodyFixture) *LegacyDeviceStore {
	t.Helper()
	s, e := OpenLegacyDevice(f.source, "https://control.example", f.state)
	if e != nil {
		t.Fatal("real legacy readonly custody capability absent", e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func legacyCustodyObserve(t *testing.T, s *LegacyDeviceStore, f legacyCustodyFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://control.example/internal/v1/runtime-gateway/authority", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SignAuthorityRequest(req, f.now); e != nil {
		t.Fatal("current-source Authority signing unavailable", e)
	}
	if req.Header.Get("Authorization") != "ZaspGatewayV1 "+f.authority.CredentialID {
		t.Fatal("Authority signing lost original credential")
	}
}
func legacyCustodyBegin(t *testing.T, s *LegacyDeviceStore, f legacyCustodyFixture) (*LegacyAssociation, AssociationSnapshot) {
	t.Helper()
	a, e := s.BeginAssociation(f.envelope, f.authority, f.now)
	if e != nil {
		t.Fatal("actual bound durable association intent unavailable", e)
	}
	t.Cleanup(func() { a.Close() })
	endpoint, snap, e := a.Source()
	if e != nil || endpoint != "https://control.example" || snap.Binding.CredentialGeneration != f.authority.CredentialGeneration {
		t.Fatal("legacy current binding unavailable", e)
	}
	return a, snap
}
func legacyCustodyReceipt(s AssociationSnapshot, now time.Time) associationwire.AcceptResponse {
	return associationwire.AcceptResponse{ChallengeID: s.Challenge.ChallengeID, ChallengeSHA256: s.Envelope.ChallengeSHA256, AssociationID: s.Challenge.AssociationID, Acceptance: associationwire.Acceptance{RequestSHA256: wire.Digest(s.RequestRaw), Credential: associationwire.DeviceCredential{CredentialID: s.Binding.CredentialID, CredentialGeneration: s.Binding.CredentialGeneration, ExpiresAt: s.Binding.ExpiresAt}, AcceptedAt: now, ExpiresAt: s.Challenge.ExpiresAt}}
}
func legacyNamespace(f legacyCustodyFixture) string {
	return filepath.Join(filepath.Dir(f.state), ".zasp-gateway-device-associations-"+wire.Digest([]byte(filepath.Base(f.state))))
}

// Grouped stdlib custody boundaries; CurrentAuthority DTO is a test input, not
// HTTP/native attestation. CLI separately proves real in-invocation GET ordering.
func TestLegacyDeviceAssociationReadonlyCurrentAuthority(t *testing.T) {
	for _, mode := range []string{"actual_three_fields_and_durable_intent", "no_offline_or_repeat_capability", "source_swap_invalidates_signing"} {
		t.Run(mode, func(t *testing.T) {
			f := legacyCustodyFiles(t)
			s := legacyCustodyOpen(t, f)
			if mode == "no_offline_or_repeat_capability" {
				if a, e := s.BeginAssociation(f.envelope, f.authority, f.now); e == nil {
					a.Close()
					t.Fatal("saved/input DTO authorized without this invocation GET signature")
				}
				s.Close()
				s = legacyCustodyOpen(t, f)
			}
			legacyCustodyObserve(t, s, f)
			a, snap := legacyCustodyBegin(t, s, f)
			if mode == "source_swap_invalidates_signing" {
				replacement := f.source + ".replacement"
				if e := os.WriteFile(replacement, f.raw, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(replacement, f.source); e != nil {
					t.Fatal(e)
				}
				if _, e := a.Sign([]byte("message")); e == nil {
					t.Fatal("replaced readonly source remained signer")
				}
				return
			}
			if mode == "no_offline_or_repeat_capability" {
				if other, e := s.BeginAssociation(f.envelope, f.authority, f.now); e == nil {
					other.Close()
					t.Fatal("one store minted second Begin capability")
				}
				return
			}
			body := snap.RequestRaw
			artifact := filepath.Join(legacyNamespace(f), snap.Challenge.ChallengeID+"."+snap.Envelope.ChallengeSHA256+".intent")
			intent, e := os.ReadFile(artifact)
			if e != nil || !bytes.Contains(intent, []byte(`"accept_request":`+string(body))) {
				t.Fatal("exact intent missing before POST", e)
			}
			if bytes.Contains(intent, []byte("local_request_sha256")) || bytes.Contains(intent, []byte("enrollment_id")) || bytes.Contains(intent, []byte(base64.RawURLEncoding.EncodeToString(f.key))) {
				t.Fatal("fabricated enrollment lineage or secret persistence")
			}
			signature, e := a.Sign([]byte("actual-local-key"))
			if e != nil || !ed25519.Verify(f.key.Public().(ed25519.PublicKey), []byte("actual-local-key"), signature) {
				t.Fatal("legacy source key unavailable", e)
			}
			if e = a.Confirm(legacyCustodyReceipt(snap, f.now), f.now); e != nil {
				t.Fatal(e)
			}
			original, _ := os.ReadFile(f.source)
			entries, _ := os.ReadDir(filepath.Dir(f.source))
			if !bytes.Equal(original, f.raw) || len(entries) != 1 {
				t.Fatal("readonly source or its directory mutated")
			}
			if strings.Contains(fmt.Sprintf("%v %#v", s, a), base64.RawURLEncoding.EncodeToString(f.key)) {
				t.Fatal("opaque handles exposed key")
			}
		})
	}
}
func TestLegacyDeviceAssociationDurableRecovery(t *testing.T) {
	for _, mode := range []string{"exact_restart_and_immutable_receipt", "partial_intent_stage_refused", "orphan_namespace_refused"} {
		t.Run(mode, func(t *testing.T) {
			f := legacyCustodyFiles(t)
			if mode == "orphan_namespace_refused" {
				if e := os.Mkdir(legacyNamespace(f), 0700); e != nil {
					t.Fatal(e)
				}
				if s, e := OpenLegacyDevice(f.source, "https://control.example", f.state); e == nil {
					s.Close()
					t.Fatal("orphan empty namespace adopted")
				}
				return
			}
			s := legacyCustodyOpen(t, f)
			legacyCustodyObserve(t, s, f)
			a, snap := legacyCustodyBegin(t, s, f)
			receipt := legacyCustodyReceipt(snap, f.now)
			if e := a.Confirm(receipt, f.now); e != nil {
				t.Fatal(e)
			}
			name := snap.Challenge.ChallengeID + "." + snap.Envelope.ChallengeSHA256
			receiptPath := filepath.Join(legacyNamespace(f), name+".receipt")
			original, _ := os.ReadFile(receiptPath)
			a.Close()
			s.Close()
			if mode == "partial_intent_stage_refused" {
				if e := os.WriteFile(filepath.Join(legacyNamespace(f), publicationStage(name+".intent")), []byte("partial"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			s = legacyCustodyOpen(t, f)
			legacyCustodyObserve(t, s, f)
			if mode == "partial_intent_stage_refused" {
				if a, e := s.BeginAssociation(f.envelope, f.authority, f.now); e == nil {
					a.Close()
					t.Fatal("partial stage adopted")
				}
				return
			}
			again, restored := legacyCustodyBegin(t, s, f)
			if !bytes.Equal(snap.RequestRaw, restored.RequestRaw) || restored.Receipt == nil {
				t.Fatal("history/body lost on restart")
			}
			receipt.Replayed = true
			if e := again.Confirm(receipt, f.now); e != nil {
				t.Fatal(e)
			}
			retained, _ := os.ReadFile(receiptPath)
			if !bytes.Equal(original, retained) {
				t.Fatal("immutable first receipt overwritten")
			}
		})
	}
}
func TestLegacyDeviceAssociationSourceAndNamespaceBoundaries(t *testing.T) {
	for _, mode := range []string{"guard_and_key_consistency", "binding_rotation_refused", "cross_store_export_ancestors"} {
		t.Run(mode, func(t *testing.T) {
			f := legacyCustodyFiles(t)
			s := legacyCustodyOpen(t, f)
			if mode == "guard_and_key_consistency" {
				if other, e := OpenLegacyDevice(f.source, "https://control.example", f.state); e == nil {
					other.Close()
					t.Fatal("state guard not exclusive")
				}
				s.Close()
				bad := append(ed25519.PrivateKey(nil), f.key...)
				bad[63] ^= 1
				raw := []byte(`{"credential_id":"` + f.authority.CredentialID + `","key_id":"` + f.authority.KeyID + `","private_key":"` + base64.RawURLEncoding.EncodeToString(bad) + `"}`)
				if e := os.WriteFile(f.source, raw, 0600); e != nil {
					t.Fatal(e)
				}
				if badStore, e := OpenLegacyDevice(f.source, "https://control.example", f.state); e == nil {
					badStore.Close()
					t.Fatal("private seed/public half inconsistency accepted")
				}
				// Late review regression within the existing consistency group: all
				// source facts are valid; only the raw spelling of one member differs.
				alias := bytes.Replace(f.raw, []byte("\"credential_id\""), []byte("\"\\u0063redential_id\""), 1)
				if bytes.Equal(alias, f.raw) {
					t.Fatal("escaped-key regression fixture unchanged")
				}
				if e := os.WriteFile(f.source, alias, 0600); e != nil {
					t.Fatal(e)
				}
				if badStore, e := OpenLegacyDevice(f.source, "https://control.example", f.state); e == nil {
					badStore.Close()
					t.Fatal("escaped source member-name alias accepted")
				}
				return
			}
			legacyCustodyObserve(t, s, f)
			a, _ := legacyCustodyBegin(t, s, f)
			a.Close()
			s.Close()
			if mode == "binding_rotation_refused" {
				s = legacyCustodyOpen(t, f)
				legacyCustodyObserve(t, s, f)
				changed := f.authority
				changed.CredentialGeneration++
				if a, e := s.BeginAssociation(f.envelope, changed, f.now); e == nil {
					a.Close()
					t.Fatal("new generation silently rebound old state")
				}
				return
			}
			enrollment, _ := openPrepared(t, filepath.Join(t.TempDir(), "enrollment.json"))
			defer enrollment.Close()
			for _, prefix := range []string{".zasp-gateway-device-associations-", ".zasp-gateway-associations-"} {
				reserved := filepath.Join(t.TempDir(), prefix+strings.Repeat("a", 64))
				if e := os.Mkdir(reserved, 0700); e != nil {
					t.Fatal(e)
				}
				nested := filepath.Join(reserved, "nested")
				if e := os.Mkdir(nested, 0700); e != nil {
					t.Fatal(e)
				}
				if root, _, e := enrollment.pinExportParent(filepath.Join(nested, "credential.json")); e == nil {
					root.Close()
					t.Fatal("export into protected namespace ancestor accepted")
				}
			}
		})
	}
}
