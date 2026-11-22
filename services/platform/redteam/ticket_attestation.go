package redteam

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Each source signs the same complete scenario and only its own evidence.
type TicketAttestation struct {
	KeyID     string    `json:"key_id"`
	SignedAt  time.Time `json:"signed_at"`
	Signature string    `json:"signature"`
}
type TicketAttestations struct {
	Adapter  TicketAttestation `json:"adapter"`
	Recorder TicketAttestation `json:"recorder"`
}

type TicketVerificationKey struct {
	KeyID       string      `json:"key_id"`
	AuthorityID string      `json:"authority_id"`
	Role        string      `json:"role"`
	Scope       TicketScope `json:"scope"`
	TargetID    string      `json:"target_id"`
	SourceID    string      `json:"source_id"`
	PublicKey   string      `json:"public_key"`
	ValidFrom   time.Time   `json:"valid_from"`
	ValidUntil  time.Time   `json:"valid_until"`
}

type TicketTrust struct {
	Keys []TicketVerificationKey `json:"keys"`
}

func decodeBase64(value string, size int) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	return b, err == nil && len(b) == size && base64.StdEncoding.EncodeToString(b) == value
}
func (a TicketAttestation) wellFormed() bool {
	_, ok := decodeBase64(a.Signature, ed25519.SignatureSize)
	return ok && ticketOpaqueID.MatchString(a.KeyID) && !a.SignedAt.IsZero()
}

func (trust TicketTrust) valid() bool {
	if len(trust.Keys) == 0 || len(trust.Keys) > 128 {
		return false
	}
	seenID := map[string]bool{}
	owners := map[string]string{}
	keys := map[string]string{}
	for _, key := range trust.Keys {
		_, ok := decodeBase64(key.PublicKey, ed25519.PublicKeySize)
		if !ok || !ticketOpaqueID.MatchString(key.KeyID) || !ticketOpaqueID.MatchString(key.AuthorityID) || !key.Scope.valid() || !ticketOpaqueID.MatchString(key.TargetID) || !ticketOpaqueID.MatchString(key.SourceID) || key.ValidFrom.IsZero() || !key.ValidUntil.After(key.ValidFrom) || (key.Role != "adapter" && key.Role != "recorder") || seenID[key.KeyID] {
			return false
		}
		if ownerRole := owners[key.AuthorityID]; ownerRole != "" && ownerRole != key.Role {
			return false
		}
		if keyRole := keys[key.PublicKey]; keyRole != "" && keyRole != key.Role {
			return false
		}
		seenID[key.KeyID] = true
		owners[key.AuthorityID] = key.Role
		keys[key.PublicKey] = key.Role
	}
	return true
}

// A stable array gives the signature a versioned domain, authenticated role,
// key ID, issue time, full scope and the typed, metadata-only source export.
// JSON object order and whitespace in transit cannot affect verification.
func ticketSignedBytes(s TicketScenario, role, keyID string, issued time.Time, source any) ([]byte, error) {
	if s.validate() != nil || s.Environment != "staging" || !ticketOpaqueID.MatchString(keyID) || issued.Before(s.WindowEnd) || issued.After(s.WindowEnd.Add(24*time.Hour)) {
		return nil, ErrRejected
	}
	switch evidence := source.(type) {
	case TicketAdapterEvidence:
		if role != "adapter" || evidence.Version != s.Version || evidence.TicketRunBinding != s.TicketRunBinding || evidence.TicketPolicyBinding != s.TicketPolicyBinding || len(evidence.Decisions) > 64 {
			return nil, ErrRejected
		}
		for _, decision := range evidence.Decisions {
			if decision.DecidedAt.After(issued) {
				return nil, ErrRejected
			}
		}
	case TicketRecorderEvidence:
		if role != "recorder" || evidence.Version != s.Version || evidence.TicketRunBinding != s.TicketRunBinding || evidence.RecorderID != s.RecorderID || len(evidence.Writes) > 64 {
			return nil, ErrRejected
		}
		if evidence.CompleteThrough.After(issued) {
			return nil, ErrRejected
		}
		for _, write := range evidence.Writes {
			if write.RecordedAt.After(issued) {
				return nil, ErrRejected
			}
		}
	default:
		return nil, ErrRejected
	}
	return json.Marshal([]any{"zasp.staging-ticket-source.v1", role, keyID, issued.UTC(), s, source})
}

// SignTicketSource is run at the source with its independently administered
// key and local authenticated evidence. It cannot issue a combined verdict.
func SignTicketSource(s TicketScenario, role, keyID string, issued time.Time, source any, key ed25519.PrivateKey) (TicketAttestation, error) {
	if len(key) != ed25519.PrivateKeySize {
		return TicketAttestation{}, ErrRejected
	}
	data, err := ticketSignedBytes(s, role, keyID, issued, source)
	if err != nil {
		return TicketAttestation{}, err
	}
	return TicketAttestation{KeyID: keyID, SignedAt: issued.UTC(), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))}, nil
}

func (trust TicketTrust) sourceKey(s TicketScenario, role, sourceID string, a TicketAttestation, submitted time.Time, source any) (TicketVerificationKey, bool) {
	if !a.wellFormed() || a.SignedAt.After(submitted) {
		return TicketVerificationKey{}, false
	}
	data, err := ticketSignedBytes(s, role, a.KeyID, a.SignedAt, source)
	if err != nil {
		return TicketVerificationKey{}, false
	}
	for _, key := range trust.Keys {
		if key.KeyID != a.KeyID || key.Role != role || key.Scope != s.Scope || key.TargetID != s.TargetID || key.SourceID != sourceID || s.WindowStart.Before(key.ValidFrom) || !submitted.Before(key.ValidUntil) {
			continue
		}
		pub, _ := decodeBase64(key.PublicKey, ed25519.PublicKeySize)
		sig, _ := decodeBase64(a.Signature, ed25519.SignatureSize)
		return key, ed25519.Verify(pub, data, sig)
	}
	return TicketVerificationKey{}, false
}

// QualifyTicketProof classifies the evidence as of the immutable server
// submission time. Removing a trusted key invalidates live re-evaluation.
// Public trust material is deployment-owned and separate from the import.
func QualifyTicketProof(b TicketProofBundle, submitted time.Time, trust TicketTrust) string {
	if submitted.IsZero() || !b.Archivable() {
		return "unknown"
	}
	result, err := VerifyTicketProof(b.Scenario, b.Adapter, b.Recorder, submitted)
	if err != nil || (result.Verdict != "passed" && result.Verdict != "unexpected_effect") {
		return "unknown"
	}
	if b.Attestations == nil {
		return "tested_control"
	}
	s := b.Scenario
	if !trust.valid() || s.Environment != "staging" || submitted.Sub(s.WindowEnd) > 24*time.Hour || submitted.Before(s.WindowEnd) {
		return "unknown"
	}
	adapter, ok := trust.sourceKey(s, "adapter", s.AdapterID, b.Attestations.Adapter, submitted, b.Adapter)
	recorder, ok2 := trust.sourceKey(s, "recorder", s.RecorderID, b.Attestations.Recorder, submitted, b.Recorder)
	if !ok || !ok2 || adapter.AuthorityID == recorder.AuthorityID || adapter.PublicKey == recorder.PublicKey {
		return "unknown"
	}
	if result.Verdict == "passed" {
		return "verified_prevention"
	}
	return "tested_control"
}
