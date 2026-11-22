package redteam

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func signedTicket(t *testing.T) (TicketProofBundle, TicketTrust, time.Time) {
	t.Helper()
	f := ticketProof()
	b := TicketProofBundle{Scenario: f.s, Adapter: f.a, Recorder: f.r}
	trust := TicketTrust{}
	issue := f.s.WindowEnd
	sign := func(role, id string, source any) TicketAttestation {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyID := role + "-key"
		trust.Keys = append(trust.Keys, TicketVerificationKey{KeyID: keyID, AuthorityID: role + "-authority", Role: role, Scope: f.s.Scope, TargetID: f.s.TargetID, SourceID: id, PublicKey: base64.StdEncoding.EncodeToString(pub), ValidFrom: f.s.WindowStart.Add(-time.Hour), ValidUntil: f.now.Add(time.Hour)})
		a, err := SignTicketSource(f.s, role, keyID, issue, source, private)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	b.Attestations = &TicketAttestations{Adapter: sign("adapter", f.s.AdapterID, f.a), Recorder: sign("recorder", f.s.RecorderID, f.r)}
	return b, trust, f.now
}
func TestIndependentlyAuthenticatedTicketSources(t *testing.T) {
	b, trust, now := signedTicket(t)
	if got := QualifyTicketProof(b, now, trust); got != "verified_prevention" {
		t.Fatal(got)
	}
	for _, c := range []struct {
		name string
		edit func(*TicketProofBundle, *TicketTrust)
	}{
		{"key removed", func(_ *TicketProofBundle, keys *TicketTrust) { keys.Keys = keys.Keys[1:] }},
		{"late key activation", func(b *TicketProofBundle, keys *TicketTrust) { keys.Keys[0].ValidFrom = b.Scenario.WindowEnd }},
		{"expired key", func(b *TicketProofBundle, keys *TicketTrust) { keys.Keys[0].ValidUntil = b.Scenario.WindowEnd }},
		{"same organization of signers", func(_ *TicketProofBundle, keys *TicketTrust) { keys.Keys[1].AuthorityID = keys.Keys[0].AuthorityID }},
		{"same key across roles", func(_ *TicketProofBundle, keys *TicketTrust) { keys.Keys[1].PublicKey = keys.Keys[0].PublicKey }},
		{"stolen scope", func(_ *TicketProofBundle, keys *TicketTrust) {
			keys.Keys[0].Scope.WorkspaceID = "pid_11111111-1111-4111-8111-111111111111"
		}},
		{"unregistered target", func(_ *TicketProofBundle, keys *TicketTrust) { keys.Keys[0].TargetID = "different" }},
		{"swapped roles", func(b *TicketProofBundle, _ *TicketTrust) {
			b.Attestations.Adapter, b.Attestations.Recorder = b.Attestations.Recorder, b.Attestations.Adapter
		}},
		{"revised policy", func(b *TicketProofBundle, _ *TicketTrust) {
			b.Scenario.PolicyRevision = "new"
			b.Adapter.PolicyRevision = "new"
		}},
		{"reused run", func(b *TicketProofBundle, _ *TicketTrust) {
			b.Scenario.RunID = "new"
			b.Adapter.RunID = "new"
			b.Recorder.RunID = "new"
		}},
		{"substituted receipt", func(b *TicketProofBundle, _ *TicketTrust) { b.Recorder.Writes[0].ReceiptID = "other" }},
		{"missing independent control", func(b *TicketProofBundle, _ *TicketTrust) { b.Recorder.Writes = []TicketWriteReceipt{} }},
		{"unhealthy target", func(b *TicketProofBundle, _ *TicketTrust) { b.Recorder.Healthy = false }},
		{"late signing time", func(b *TicketProofBundle, _ *TicketTrust) {
			b.Attestations.Recorder.SignedAt = b.Scenario.WindowEnd.Add(25 * time.Hour)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, trust, now := signedTicket(t)
			c.edit(&b, &trust)
			if got := QualifyTicketProof(b, now, trust); got != "unknown" {
				t.Fatalf("qualified invalid proof as %s", got)
			}
		})
	}
	if got := QualifyTicketProof(b, now.Add(25*time.Hour), trust); got != "unknown" {
		t.Fatal(got)
	}
	b.Attestations = nil
	if got := QualifyTicketProof(b, now, trust); got != "tested_control" {
		t.Fatal(got)
	}
	b.Recorder.Healthy = false
	if got := QualifyTicketProof(b, now, trust); got != "unknown" {
		t.Fatal(got)
	}
}
