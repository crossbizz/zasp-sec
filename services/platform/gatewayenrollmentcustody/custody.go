// Package gatewayenrollmentcustody retains immutable device bootstrap keys and
// intent. It coordinates cooperating Linux processes under trusted directories;
// it does not isolate malicious parents, same-UID actors, or older binaries.
package gatewayenrollmentcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/cacheownership"
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("gateway enrollment custody unavailable")

type State string

const (
	StateAbsent   State = "absent"
	StatePending  State = "pending"
	StateAccepted State = "accepted"
)

type Snapshot struct {
	State      State
	RequestRaw []byte
	Request    wire.Request
}
type tokenMetadata struct {
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	EnrollmentID         string    `json:"enrollment_id"`
	TokenGeneration      uint64    `json:"token_generation"`
	CredentialGeneration uint64    `json:"credential_generation"`
	EnrollmentExpiresAt  time.Time `json:"enrollment_expires_at"`
}
type custodyBundle struct {
	Schema               string          `json:"schema"`
	Endpoint             string          `json:"endpoint"`
	TokenMetadata        tokenMetadata   `json:"token_metadata"`
	LocatorSHA256        string          `json:"locator_sha256"`
	CredentialTTLSeconds int64           `json:"credential_ttl_seconds"`
	PrivateKey           string          `json:"private_key"`
	Request              json.RawMessage `json:"request"`
	PublicKey            string          `json:"public_key"`
}
type Store struct {
	mu              sync.Mutex
	root            *os.Root
	associationRoot *os.Root
	name            string
	receiptName     string
	guard           *cacheownership.Guard
	bundle          *custodyBundle
	bundleRaw       []byte
	request         wire.Request
	key             ed25519.PrivateKey
	receipt         *wire.Receipt
	closed          bool
	failed          bool
}

// Formatting a Store must never print its retained private key.
func (*Store) String() string                 { return "[REDACTED]" }
func (*Store) GoString() string               { return "[REDACTED]" }
func (*Store) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "[REDACTED]") }

func Supported() bool { return cacheownership.Supported() }
func Open(path string) (*Store, error) {
	if !Supported() {
		return nil, ErrUnavailable
	}
	root, name, e := pinParent(path)
	if e != nil {
		return nil, ErrUnavailable
	}
	guard, e := cacheownership.Acquire(root, name)
	if e != nil {
		root.Close()
		return nil, ErrUnavailable
	}
	s := &Store{root: root, name: name, receiptName: ".zasp-gateway-enrollment-" + wire.Digest([]byte(name)) + ".receipt", guard: guard}
	fail := func() (*Store, error) { s.Close(); return nil, ErrUnavailable }
	raw, present, e := readRecoverable(root, name)
	if e != nil {
		return fail()
	}
	if !present {
		for _, artifact := range []string{s.receiptName, publicationStage(s.receiptName), s.authorityName(), publicationStage(s.authorityName()), s.associationDirectoryName()} {
			if _, e := root.Lstat(artifact); !errors.Is(e, os.ErrNotExist) {
				return fail()
			}
		}
		return s, nil
	}
	bundle, request, key, e := decodeBundle(raw)
	if e != nil {
		return fail()
	}
	if publish(root, name, raw) != nil {
		clear(key)
		return fail()
	}
	s.bundle, s.bundleRaw, s.request, s.key = &bundle, append([]byte(nil), raw...), request, key
	receiptRaw, present, e := readRecoverable(root, s.receiptName)
	if e != nil {
		return fail()
	}
	if present {
		receipt, e := wire.ParseReceipt(receiptRaw)
		if e != nil || !wire.ReceiptMatches(receipt, request, wire.Digest(bundle.Request)) {
			return fail()
		}
		canonical, e := wire.MarshalReceipt(receipt)
		if e != nil || !bytes.Equal(canonical, receiptRaw) || publish(root, s.receiptName, receiptRaw) != nil {
			return fail()
		}
		s.receipt = &receipt
	}
	if s.recoverAuthorityHistory() != nil {
		return fail()
	}
	if s.openAssociationNamespace() != nil {
		return fail()
	}
	return s, nil
}
func (s *Store) Prepare(token wire.TokenBundle, endpoint string, ttl time.Duration, now time.Time) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || !validEndpoint(endpoint) || ttl < time.Minute || ttl > 90*24*time.Hour || ttl%time.Second != 0 || !whole(now) {
		return Snapshot{}, ErrUnavailable
	}
	if _, e := wire.MarshalTokenBundle(token); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	metadata := metadataFor(token)
	locator, e := base64.RawURLEncoding.DecodeString(token.Locator)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	locatorDigest := wire.Digest(locator)
	clear(locator)
	if s.bundle != nil {
		if s.bundle.Endpoint != endpoint || s.bundle.TokenMetadata != metadata || s.bundle.LocatorSHA256 != locatorDigest || s.bundle.CredentialTTLSeconds != int64(ttl/time.Second) {
			return Snapshot{}, ErrUnavailable
		}
		return s.snapshotLocked(), nil
	}
	if !token.EnrollmentExpiresAt.After(now) {
		return Snapshot{}, ErrUnavailable
	}
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	defer clear(key)
	idBytes := make([]byte, 16)
	if _, e = rand.Read(idBytes); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	idBytes[6] = (idBytes[6] & 0x0f) | 0x40
	idBytes[8] = (idBytes[8] & 0x3f) | 0x80
	idHex := hex.EncodeToString(idBytes)
	credentialID := "pid_" + idHex[:8] + "-" + idHex[8:12] + "-" + idHex[12:16] + "-" + idHex[16:20] + "-" + idHex[20:]
	keyBytes := make([]byte, 8)
	if _, e = rand.Read(keyBytes); e != nil {
		return Snapshot{}, ErrUnavailable
	}
	request := wire.Request{Schema: wire.RequestSchema, OrganizationID: token.OrganizationID, WorkspaceID: token.WorkspaceID, EnvironmentID: token.EnvironmentID, DeviceID: token.DeviceID, EnrollmentID: token.EnrollmentID, TokenGeneration: token.TokenGeneration, CredentialID: credentialID, CredentialGeneration: token.CredentialGeneration, KeyID: "gateway_" + hex.EncodeToString(keyBytes), Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(public), ExpiresAt: now.Add(ttl)}
	raw, e := wire.MarshalRequest(request)
	if e != nil {
		return Snapshot{}, ErrUnavailable
	}
	bundle := custodyBundle{Schema: "gateway-enrollment-custody-v1", Endpoint: endpoint, TokenMetadata: metadata, LocatorSHA256: locatorDigest, CredentialTTLSeconds: int64(ttl / time.Second), PrivateKey: base64.RawURLEncoding.EncodeToString(key), Request: append([]byte(nil), raw...), PublicKey: request.PublicKey}
	encoded, e := json.Marshal(bundle)
	if e != nil || len(encoded) > 16384 {
		return Snapshot{}, ErrUnavailable
	}
	if publish(s.root, s.name, encoded) != nil || !s.guard.Valid() {
		s.failed = true
		return Snapshot{}, ErrUnavailable
	}
	s.bundle = &bundle
	s.bundleRaw = append([]byte(nil), encoded...)
	s.request = request
	s.key = append(ed25519.PrivateKey(nil), key...)
	return s.snapshotLocked(), nil
}
func (s *Store) Snapshot() (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() {
		return Snapshot{}, ErrUnavailable
	}
	return s.snapshotLocked(), nil
}
func (s *Store) snapshotLocked() Snapshot {
	if s.bundle == nil {
		return Snapshot{State: StateAbsent}
	}
	state := StatePending
	if s.receipt != nil {
		state = StateAccepted
	}
	return Snapshot{State: state, RequestRaw: append([]byte(nil), s.bundle.Request...), Request: s.request}
}
func (s *Store) Sign(message []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil || len(s.key) != ed25519.PrivateKeySize || len(message) == 0 || len(message) > 16384 {
		return nil, ErrUnavailable
	}
	return ed25519.Sign(s.key, message), nil
}
func (s *Store) Accept(receipt wire.Receipt) error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil || !wire.ReceiptMatches(receipt, s.request, wire.Digest(s.bundle.Request)) {
		return ErrUnavailable
	}
	if s.receipt != nil {
		old, next := *s.receipt, receipt
		old.Replayed = false
		next.Replayed = false
		if old != next {
			return ErrUnavailable
		}
		return nil
	}
	raw, e := wire.MarshalReceipt(receipt)
	if e != nil || publish(s.root, s.receiptName, raw) != nil || !s.guard.Valid() {
		s.failed = true
		return ErrUnavailable
	}
	s.receipt = &receipt
	return nil
}
func (s *Store) ExportCredential(path string) error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil || s.receipt == nil {
		return ErrUnavailable
	}
	return s.exportCredentialLocked(path)
}

func (s *Store) exportCredentialLocked(path string) error {
	if !s.validLocked() || s.bundle == nil {
		return ErrUnavailable
	}
	root, name, e := s.pinExportParent(path)
	if e != nil {
		return ErrUnavailable
	}
	defer root.Close()
	parent, e := root.Stat(".")
	sourceParent, sourceErr := s.root.Stat(".")
	if e != nil || sourceErr != nil {
		return ErrUnavailable
	}
	if os.SameFile(parent, sourceParent) {
		for _, reserved := range []string{s.name, s.receiptName, s.authorityName(), publicationStage(s.name), publicationStage(s.receiptName), publicationStage(s.authorityName()), ".zasp-cache-ownership-" + wire.Digest([]byte(s.name)) + ".lock"} {
			if name == reserved || publicationStage(name) == reserved {
				return ErrUnavailable
			}
		}
	}
	guard, e := cacheownership.Acquire(root, name)
	if e != nil {
		return ErrUnavailable
	}
	defer guard.Close()
	for _, candidate := range []string{name, publicationStage(name)} {
		info, e := root.Lstat(candidate)
		if e == nil {
			for _, source := range []string{s.name, s.receiptName, s.authorityName()} {
				sourceInfo, se := s.root.Lstat(source)
				if se == nil && os.SameFile(info, sourceInfo) {
					return ErrUnavailable
				}
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return ErrUnavailable
		}
	}
	config := struct {
		CredentialID string `json:"credential_id"`
		KeyID        string `json:"key_id"`
		PrivateKey   string `json:"private_key"`
	}{s.request.CredentialID, s.request.KeyID, s.bundle.PrivateKey}
	raw, e := json.Marshal(config)
	if e != nil || publish(root, name, raw) != nil || !guard.Valid() {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	clear(s.key)
	s.key = nil
	s.bundle = nil
	clear(s.bundleRaw)
	s.bundleRaw = nil
	var result error
	if s.associationRoot != nil {
		if s.associationRoot.Close() != nil {
			result = ErrUnavailable
		}
		s.associationRoot = nil
	}
	if s.guard != nil {
		if s.guard.Close() != nil {
			result = ErrUnavailable
		}
		s.guard = nil
	}
	if s.root != nil {
		if s.root.Close() != nil {
			result = ErrUnavailable
		}
		s.root = nil
	}
	return result
}
func (s *Store) validLocked() bool {
	if s.closed || s.failed || s.root == nil || s.guard == nil || !s.guard.Valid() {
		return false
	}
	if !s.associationNamespaceValid() {
		return false
	}
	if s.bundle == nil {
		return true
	}
	raw, e := readExactFile(s.root, s.name, 1)
	if e != nil || !bytes.Equal(raw, s.bundleRaw) {
		return false
	}
	if s.receipt != nil {
		raw, e = readExactFile(s.root, s.receiptName, 1)
		if e != nil {
			return false
		}
		receipt, e := wire.ParseReceipt(raw)
		if e != nil || receipt != *s.receipt {
			return false
		}
	}
	return s.checkAuthorityHistory()
}
func metadataFor(b wire.TokenBundle) tokenMetadata {
	return tokenMetadata{b.OrganizationID, b.WorkspaceID, b.EnvironmentID, b.DeviceID, b.EnrollmentID, b.TokenGeneration, b.CredentialGeneration, b.EnrollmentExpiresAt}
}
func decodeBundle(raw []byte) (custodyBundle, wire.Request, ed25519.PrivateKey, error) {
	var b custodyBundle
	fail := func() (custodyBundle, wire.Request, ed25519.PrivateKey, error) {
		return custodyBundle{}, wire.Request{}, nil, ErrUnavailable
	}
	if len(raw) == 0 || len(raw) > 16384 || json.Unmarshal(raw, &b) != nil {
		return fail()
	}
	canonical, e := json.Marshal(b)
	if e != nil || !bytes.Equal(raw, canonical) || b.Schema != "gateway-enrollment-custody-v1" || !validEndpoint(b.Endpoint) || b.CredentialTTLSeconds < 60 || b.CredentialTTLSeconds > 90*86400 {
		return fail()
	}
	digest, e := hex.DecodeString(b.LocatorSHA256)
	if e != nil || len(digest) != 32 || hex.EncodeToString(digest) != b.LocatorSHA256 {
		return fail()
	}
	request, e := wire.ParseRequest(b.Request)
	if e != nil {
		return fail()
	}
	requestRaw, e := wire.MarshalRequest(request)
	if e != nil || !bytes.Equal(requestRaw, b.Request) || b.PublicKey != request.PublicKey {
		return fail()
	}
	metadata := b.TokenMetadata
	dummy := wire.TokenBundle{Schema: wire.TokenSchema, OrganizationID: metadata.OrganizationID, WorkspaceID: metadata.WorkspaceID, EnvironmentID: metadata.EnvironmentID, DeviceID: metadata.DeviceID, EnrollmentID: metadata.EnrollmentID, TokenGeneration: metadata.TokenGeneration, CredentialGeneration: metadata.CredentialGeneration, EnrollmentExpiresAt: metadata.EnrollmentExpiresAt, Locator: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), Secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}
	if !wire.RequestMatchesBundle(request, dummy) {
		return fail()
	}
	key, e := base64.RawURLEncoding.DecodeString(b.PrivateKey)
	if e != nil || len(key) != 64 || base64.RawURLEncoding.EncodeToString(key) != b.PrivateKey {
		clear(key)
		return fail()
	}
	expected := ed25519.NewKeyFromSeed(key[:32])
	if !bytes.Equal(expected, key) || base64.RawURLEncoding.EncodeToString(expected.Public().(ed25519.PublicKey)) != b.PublicKey {
		clear(key)
		clear(expected)
		return fail()
	}
	clear(expected)
	return b, request, ed25519.PrivateKey(key), nil
}
func whole(v time.Time) bool {
	return !v.IsZero() && v.Location() == time.UTC && v.Nanosecond() == 0 && v.Year() >= 1 && v.Year() <= 9999
}
func validEndpoint(value string) bool {
	u, e := url.Parse(value)
	return e == nil && u.String() == value && u.Scheme == "https" && u.User == nil && u.Hostname() != "" && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}
func publicationStage(name string) string {
	return ".zasp-publish-" + wire.Digest([]byte(name)) + ".prepare"
}
