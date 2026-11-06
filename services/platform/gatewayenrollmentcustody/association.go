package gatewayenrollmentcustody

import (
	"bytes"
	"encoding/json"
	"fmt"
	associationwire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"io"
	"os"
	"sync"
	"time"
)

type AssociationSnapshot struct {
	Challenge  associationwire.Challenge
	Envelope   associationwire.ChallengeEnvelope
	RequestRaw []byte
	Binding    associationwire.DeviceBinding
	Receipt    *associationwire.AcceptResponse
}

// Association preserves one administrative Device acceptance intent. It never
// establishes a live Agent association or authorizes credential export.
type Association struct {
	mu          sync.Mutex
	store       *Store
	closed      bool
	snapshot    AssociationSnapshot
	intentName  string
	receiptName string
	intentRaw   []byte
}
type associationIntent struct {
	Schema               string                            `json:"schema"`
	LocalRequestSHA256   string                            `json:"local_request_sha256"`
	Endpoint             string                            `json:"endpoint"`
	CredentialID         string                            `json:"credential_id"`
	CredentialGeneration uint64                            `json:"credential_generation"`
	Challenge            associationwire.ChallengeEnvelope `json:"challenge"`
	AcceptRequest        json.RawMessage                   `json:"accept_request"`
}
type associationReceiptRecord struct {
	Schema       string                         `json:"schema"`
	IntentSHA256 string                         `json:"intent_sha256"`
	Response     associationwire.AcceptResponse `json:"response"`
}

func (*Association) String() string                 { return "[REDACTED]" }
func (*Association) GoString() string               { return "[REDACTED]" }
func (*Association) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "[REDACTED]") }
func (s *Store) associationDirectoryName() string {
	return ".zasp-gateway-associations-" + wire.Digest([]byte(s.name))
}
func (s *Store) associationBinding() associationwire.DeviceBinding {
	return associationwire.DeviceBinding{OrganizationID: s.request.OrganizationID, WorkspaceID: s.request.WorkspaceID, EnvironmentID: s.request.EnvironmentID, DeviceID: s.request.DeviceID, CredentialID: s.request.CredentialID, CredentialGeneration: s.request.CredentialGeneration, PublicKey: s.request.PublicKey, ExpiresAt: s.request.ExpiresAt}
}
func (s *Store) BeginAssociation(envelope associationwire.ChallengeEnvelope, now time.Time) (*Association, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil || !whole(now) {
		return nil, ErrUnavailable
	}
	challenge, e := associationwire.ChallengeFromEnvelope(envelope)
	if e != nil {
		return nil, ErrUnavailable
	}
	binding := s.associationBinding()
	if challenge.OrganizationID != binding.OrganizationID || challenge.WorkspaceID != binding.WorkspaceID || challenge.EnvironmentID != binding.EnvironmentID || challenge.DeviceID != binding.DeviceID || !challenge.ExpiresAt.After(now) || !binding.ExpiresAt.After(now) {
		return nil, ErrUnavailable
	}
	raw, e := associationwire.BuildAcceptRequest(envelope)
	if e != nil {
		return nil, ErrUnavailable
	}
	if s.ensureAssociationNamespace() != nil {
		s.failed = true
		return nil, ErrUnavailable
	}
	intent := associationIntent{Schema: "gateway-agent-device-acceptance-intent-v1", LocalRequestSHA256: wire.Digest(s.bundle.Request), Endpoint: s.bundle.Endpoint, CredentialID: binding.CredentialID, CredentialGeneration: binding.CredentialGeneration, Challenge: envelope, AcceptRequest: append([]byte(nil), raw...)}
	encoded, e := json.Marshal(intent)
	if e != nil {
		return nil, ErrUnavailable
	}
	prefix := challenge.ChallengeID + "." + envelope.ChallengeSHA256
	handle := &Association{store: s, intentName: prefix + ".intent", receiptName: prefix + ".receipt", intentRaw: append([]byte(nil), encoded...), snapshot: AssociationSnapshot{Challenge: challenge, Envelope: envelope, RequestRaw: append([]byte(nil), raw...), Binding: binding}}
	// An orphan receipt is not authority to create a missing immutable intent.
	_, present, e := readRecoverable(s.associationRoot, handle.intentName)
	if e != nil {
		return nil, ErrUnavailable
	}
	if !present {
		if _, receiptPresent, e := readRecoverable(s.associationRoot, handle.receiptName); e != nil || receiptPresent {
			return nil, ErrUnavailable
		}
	}
	if publish(s.associationRoot, handle.intentName, encoded) != nil || !s.associationNamespaceValid() {
		s.failed = true
		return nil, ErrUnavailable
	}
	receiptRaw, present, e := readRecoverable(s.associationRoot, handle.receiptName)
	if e != nil {
		return nil, ErrUnavailable
	}
	if present {
		response, e := handle.decodeReceipt(receiptRaw)
		if e != nil {
			return nil, ErrUnavailable
		}
		if publish(s.associationRoot, handle.receiptName, receiptRaw) != nil {
			s.failed = true
			return nil, ErrUnavailable
		}
		handle.snapshot.Receipt = &response
	}
	return handle, nil
}
func (a *Association) Source() (string, AssociationSnapshot, error) {
	if a == nil {
		return "", AssociationSnapshot{}, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.store == nil {
		return "", AssociationSnapshot{}, ErrUnavailable
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !a.validLocked() {
		return "", AssociationSnapshot{}, ErrUnavailable
	}
	return s.bundle.Endpoint, copyAssociationSnapshot(a.snapshot), nil
}
func (a *Association) Sign(message []byte) ([]byte, error) {
	if a == nil {
		return nil, ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.store == nil {
		return nil, ErrUnavailable
	}
	s := a.store
	s.mu.Lock()
	valid := a.validLocked()
	s.mu.Unlock()
	if !valid {
		return nil, ErrUnavailable
	}
	return s.Sign(message)
}
func (a *Association) Confirm(response associationwire.AcceptResponse, now time.Time) error {
	if a == nil {
		return ErrUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.store == nil {
		return ErrUnavailable
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !a.validLocked() || !associationwire.AcceptResponseMatches(response, a.snapshot.RequestRaw, a.snapshot.Binding, now) {
		return ErrUnavailable
	}
	// Another handle may have already retained this challenge's same immutable
	// receipt. Re-read that selected path under the shared Store lock and keep
	// its original replay presentation rather than overwriting history.
	if a.snapshot.Receipt == nil {
		existing, present, err := readRecoverable(s.associationRoot, a.receiptName)
		if err != nil {
			return ErrUnavailable
		}
		if present {
			retained, err := a.decodeReceipt(existing)
			if err != nil {
				return ErrUnavailable
			}
			if publish(s.associationRoot, a.receiptName, existing) != nil {
				s.failed = true
				return ErrUnavailable
			}
			a.snapshot.Receipt = &retained
		}
	}
	if a.snapshot.Receipt != nil {
		old, next := *a.snapshot.Receipt, response
		old.Replayed = false
		next.Replayed = false
		if old != next {
			return ErrUnavailable
		}
		return nil
	}
	receipt := associationReceiptRecord{Schema: "gateway-agent-device-acceptance-receipt-v1", IntentSHA256: wire.Digest(a.intentRaw), Response: response}
	raw, e := json.Marshal(receipt)
	if e != nil || publish(s.associationRoot, a.receiptName, raw) != nil || !s.guard.Valid() || !s.associationNamespaceValid() {
		s.failed = true
		return ErrUnavailable
	}
	a.snapshot.Receipt = &response
	return nil
}
func (a *Association) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.store = nil
	return nil
}
func copyAssociationSnapshot(value AssociationSnapshot) AssociationSnapshot {
	value.RequestRaw = append([]byte(nil), value.RequestRaw...)
	if value.Receipt != nil {
		copy := *value.Receipt
		value.Receipt = &copy
	}
	return value
}
func (a *Association) decodeReceipt(raw []byte) (associationwire.AcceptResponse, error) {
	var receipt associationReceiptRecord
	if len(raw) == 0 || len(raw) > 16384 || json.Unmarshal(raw, &receipt) != nil {
		return associationwire.AcceptResponse{}, ErrUnavailable
	}
	canonical, e := json.Marshal(receipt)
	if e != nil || !bytes.Equal(raw, canonical) || receipt.Schema != "gateway-agent-device-acceptance-receipt-v1" || receipt.IntentSHA256 != wire.Digest(a.intentRaw) {
		return associationwire.AcceptResponse{}, ErrUnavailable
	}
	responseRaw, e := associationwire.MarshalAcceptResponse(receipt.Response)
	if e != nil {
		return associationwire.AcceptResponse{}, ErrUnavailable
	}
	response, e := associationwire.ParseAcceptResponse(responseRaw)
	if e != nil || !associationwire.AcceptResponseMatches(response, a.snapshot.RequestRaw, a.snapshot.Binding, response.Acceptance.AcceptedAt.UTC().Truncate(time.Second)) {
		return associationwire.AcceptResponse{}, ErrUnavailable
	}
	return response, nil
}
func (a *Association) validLocked() bool {
	if a.closed || a.store == nil || !a.store.validLocked() || a.store.associationRoot == nil {
		return false
	}
	raw, e := readExactFile(a.store.associationRoot, a.intentName, 1)
	if e != nil || !bytes.Equal(raw, a.intentRaw) {
		return false
	}
	if a.snapshot.Receipt != nil {
		raw, e = readExactFile(a.store.associationRoot, a.receiptName, 1)
		if e != nil {
			return false
		}
		response, e := a.decodeReceipt(raw)
		if e != nil || response != *a.snapshot.Receipt {
			return false
		}
	}
	return true
}

// Namespace checks examine the pinned directory only. Selected histories are
// inspected explicitly by BeginAssociation; unrelated history is never scanned.
func (s *Store) openAssociationNamespace() error {
	info, e := s.root.Lstat(s.associationDirectoryName())
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || !safeAssociationDirectory(info) {
		return ErrUnavailable
	}
	root, e := s.root.OpenRoot(s.associationDirectoryName())
	if e != nil {
		return ErrUnavailable
	}
	opened, oe := root.Stat(".")
	after, ae := s.root.Lstat(s.associationDirectoryName())
	if oe != nil || ae != nil || !safeAssociationDirectory(opened) || !safeAssociationDirectory(after) || !os.SameFile(info, opened) || !os.SameFile(opened, after) {
		root.Close()
		return ErrUnavailable
	}
	s.associationRoot = root
	return nil
}
func (s *Store) ensureAssociationNamespace() error {
	if s.associationRoot == nil {
		if s.root.Mkdir(s.associationDirectoryName(), 0700) != nil {
			return ErrUnavailable
		}
		if s.openAssociationNamespace() != nil || s.associationRoot == nil {
			return ErrUnavailable
		}
	}
	// A visible recovered directory may follow an earlier uncertain parent fsync.
	// Re-establish both directory durabilities before exposing any sendable intent.
	if !s.associationNamespaceValid() || syncDirectory(s.associationRoot) != nil || syncDirectory(s.root) != nil || s.guard == nil || !s.guard.Valid() || !s.associationNamespaceValid() {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) associationNamespaceValid() bool {
	if s.root == nil {
		return false
	}
	info, e := s.root.Lstat(s.associationDirectoryName())
	if s.associationRoot == nil {
		return os.IsNotExist(e)
	}
	opened, oe := s.associationRoot.Stat(".")
	return e == nil && oe == nil && safeAssociationDirectory(info) && safeAssociationDirectory(opened) && os.SameFile(info, opened)
}
