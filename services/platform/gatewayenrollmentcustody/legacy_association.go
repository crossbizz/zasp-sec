package gatewayenrollmentcustody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	associationwire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/cacheownership"
)

// LegacyDeviceStore consumes an existing key without copying it into enrollment
// custody or claiming enrollment lineage. Its writable state is public metadata.
type LegacyDeviceStore struct {
	mu                                       sync.Mutex
	sourceRoot                               *os.Root
	sourceFile                               *os.File
	sourceName                               string
	sourcePath                               string
	sourceInfo                               os.FileInfo
	sourceRaw                                []byte
	key                                      ed25519.PrivateKey
	credentialID, keyID, publicKey, endpoint string
	root, associationRoot                    *os.Root
	name                                     string
	guard                                    *cacheownership.Guard
	descriptor                               *legacyDeviceDescriptor
	descriptorRaw                            []byte
	signed, signedOK, begun, closed, failed  bool
	started, signedAt, deadline              time.Time
	ctx                                      context.Context
}
type LegacyAssociation struct {
	mu                      sync.Mutex
	store                   *LegacyDeviceStore
	closed                  bool
	snapshot                AssociationSnapshot
	intentName, receiptName string
	intentRaw               []byte
}
type legacyDeviceBinding struct {
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	PublicKey            string    `json:"public_key"`
	ExpiresAt            time.Time `json:"expires_at"`
}
type legacyDeviceDescriptor struct {
	Schema         string                `json:"schema"`
	IdentitySource string                `json:"identity_source"`
	Endpoint       string                `json:"endpoint"`
	CredentialID   string                `json:"credential_id"`
	KeyID          string                `json:"key_id"`
	PublicKey      string                `json:"public_key"`
	Binding        legacyDeviceBinding   `json:"device_binding"`
	FirstAuthority wire.CurrentAuthority `json:"first_authority"`
	ObservedAt     time.Time             `json:"observed_at"`
}
type legacyPublicCredential struct {
	CredentialID string `json:"credential_id"`
	KeyID        string `json:"key_id"`
	PublicKey    string `json:"public_key"`
}
type legacyAssociationIntent struct {
	Schema         string                            `json:"schema"`
	IdentitySource string                            `json:"identity_source"`
	Endpoint       string                            `json:"endpoint"`
	Credential     legacyPublicCredential            `json:"public_credential"`
	Binding        legacyDeviceBinding               `json:"device_binding"`
	Challenge      associationwire.ChallengeEnvelope `json:"challenge"`
	AcceptRequest  json.RawMessage                   `json:"accept_request"`
}
type legacyAssociationReceipt struct {
	Schema       string                         `json:"schema"`
	IntentSHA256 string                         `json:"intent_sha256"`
	Response     associationwire.AcceptResponse `json:"response"`
}

var legacyDeviceIDPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var legacyDeviceKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)

func (*LegacyDeviceStore) String() string             { return "[REDACTED]" }
func (*LegacyDeviceStore) GoString() string           { return "[REDACTED]" }
func (*LegacyDeviceStore) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[REDACTED]") }
func (*LegacyAssociation) String() string             { return "[REDACTED]" }
func (*LegacyAssociation) GoString() string           { return "[REDACTED]" }
func (*LegacyAssociation) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[REDACTED]") }

func legacyProtectedPath(path string) bool {
	for _, part := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if strings.HasPrefix(part, ".zasp-gateway-device-associations-") || strings.HasPrefix(part, ".zasp-gateway-associations-") {
			return true
		}
	}
	return false
}
func decodeLegacySource(raw []byte) (string, string, ed25519.PrivateKey, error) {
	fail := func() (string, string, ed25519.PrivateKey, error) { return "", "", nil, ErrUnavailable }
	if len(raw) < 1 || len(raw) > 4096 || !utf8.Valid(raw) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return fail()
	}
	fields := map[string]string{}
	for d.More() {
		before := d.InputOffset()
		token, e := d.Token()
		after := d.InputOffset()
		name, ok := token.(string)
		if e != nil || !ok || name != "credential_id" && name != "key_id" && name != "private_key" {
			return fail()
		}
		// Token decodes escaped member names. The original key file allows
		// whitespace and order changes, but not a second spelling of a closed key.
		lexeme := bytes.TrimSpace(raw[before:after])
		if len(lexeme) > 0 && lexeme[0] == ',' {
			lexeme = bytes.TrimSpace(lexeme[1:])
		}
		if !bytes.Equal(lexeme, []byte("\""+name+"\"")) {
			return fail()
		}
		if _, present := fields[name]; present {
			return fail()
		}
		var value string
		if d.Decode(&value) != nil {
			return fail()
		}
		fields[name] = value
	}
	if last, e := d.Token(); e != nil || last != json.Delim('}') {
		return fail()
	}
	if _, e := d.Token(); e != io.EOF || len(fields) != 3 || !legacyDeviceIDPattern.MatchString(fields["credential_id"]) || !legacyDeviceKeyPattern.MatchString(fields["key_id"]) {
		return fail()
	}
	key, e := base64.RawURLEncoding.DecodeString(fields["private_key"])
	if e != nil || len(key) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(key) != fields["private_key"] {
		clear(key)
		return fail()
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(key, derived) {
		clear(key)
		return fail()
	}
	return fields["credential_id"], fields["key_id"], ed25519.PrivateKey(key), nil
}
func OpenLegacyDevice(credentialFile, endpoint, stateFile string) (*LegacyDeviceStore, error) {
	if !Supported() || !validEndpoint(endpoint) || legacyProtectedPath(credentialFile) || legacyProtectedPath(stateFile) {
		return nil, ErrUnavailable
	}
	sourceRoot, sourceName, e := pinParent(credentialFile)
	if e != nil {
		return nil, ErrUnavailable
	}
	s := &LegacyDeviceStore{sourceRoot: sourceRoot, sourceName: sourceName, sourcePath: credentialFile, endpoint: endpoint}
	fail := func() (*LegacyDeviceStore, error) { s.Close(); return nil, ErrUnavailable }
	raw, e := readExactFile(sourceRoot, sourceName, 1)
	if e != nil || len(raw) > 4096 {
		clear(raw)
		return fail()
	}
	s.sourceRaw = raw
	s.credentialID, s.keyID, s.key, e = decodeLegacySource(raw)
	if e != nil {
		return fail()
	}
	s.publicKey = base64.RawURLEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
	s.sourceFile, e = sourceRoot.OpenFile(sourceName, os.O_RDONLY|noFollowFlags(), 0)
	if e != nil {
		return fail()
	}
	s.sourceInfo, e = s.sourceFile.Stat()
	if e != nil || !s.sourceValidLocked() {
		return fail()
	}
	s.root, s.name, e = pinParent(stateFile)
	if e != nil {
		return fail()
	}
	sourceParent, se := sourceRoot.Stat(".")
	stateParent, pe := s.root.Stat(".")
	if se != nil || pe != nil || os.SameFile(sourceParent, stateParent) && sourceName == s.name {
		return fail()
	}
	// The source's nlink1 and reserved basename checks rule out source aliases to
	// state/guard/stage names before the only writable logical-name guard opens.
	s.guard, e = cacheownership.Acquire(s.root, s.name)
	if e != nil {
		return fail()
	}
	stateRaw, present, e := readRecoverable(s.root, s.name)
	if e != nil {
		return fail()
	}
	if present {
		descriptor, e := s.decodeDescriptor(stateRaw)
		if e != nil || publish(s.root, s.name, stateRaw) != nil {
			return fail()
		}
		s.descriptor = &descriptor
		s.descriptorRaw = append([]byte(nil), stateRaw...)
	} else {
		if _, e := s.root.Lstat(s.directoryName()); !errors.Is(e, os.ErrNotExist) {
			return fail()
		}
	}
	if s.openNamespace() != nil || !s.validLocked() {
		return fail()
	}
	return s, nil
}
func (s *LegacyDeviceStore) sourceValidLocked() bool {
	if s.sourceRoot == nil || s.sourceFile == nil || s.sourceInfo == nil || len(s.sourceRaw) == 0 {
		return false
	}
	fresh, name, e := pinParent(s.sourcePath)
	if e != nil {
		return false
	}
	defer fresh.Close()
	currentParent, ce := fresh.Stat(".")
	pinnedParent, pe := s.sourceRoot.Stat(".")
	if ce != nil || pe != nil || name != s.sourceName || !os.SameFile(currentParent, pinnedParent) {
		return false
	}
	path, e := fresh.Lstat(s.sourceName)
	fd, fe := s.sourceFile.Stat()
	if e != nil || fe != nil || !safeInfo(path, 1) || !safeInfo(fd, 1) || !os.SameFile(s.sourceInfo, path) || !os.SameFile(s.sourceInfo, fd) || fd.Size() != s.sourceInfo.Size() || !legacySourceMetadataEqual(s.sourceInfo, fd) || !legacySourceMetadataEqual(s.sourceInfo, path) || int64(len(s.sourceRaw)) != fd.Size() {
		return false
	}
	raw, e := readExactFile(fresh, s.sourceName, 1)
	if e != nil {
		return false
	}
	defer clear(raw)
	pinned := make([]byte, len(s.sourceRaw))
	defer clear(pinned)
	n, e := s.sourceFile.ReadAt(pinned, 0)
	return (e == nil || e == io.EOF) && n == len(pinned) && bytes.Equal(raw, s.sourceRaw) && bytes.Equal(pinned, s.sourceRaw)
}
func (s *LegacyDeviceStore) directoryName() string {
	return ".zasp-gateway-device-associations-" + wire.Digest([]byte(s.name))
}
func (s *LegacyDeviceStore) namespaceValid() bool {
	if s.root == nil {
		return false
	}
	path, e := s.root.Lstat(s.directoryName())
	if s.associationRoot == nil {
		return errors.Is(e, os.ErrNotExist)
	}
	opened, oe := s.associationRoot.Stat(".")
	return e == nil && oe == nil && safeAssociationDirectory(path) && safeAssociationDirectory(opened) && os.SameFile(path, opened)
}
func (s *LegacyDeviceStore) openNamespace() error {
	path, e := s.root.Lstat(s.directoryName())
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || s.descriptor == nil || !safeAssociationDirectory(path) {
		return ErrUnavailable
	}
	root, e := s.root.OpenRoot(s.directoryName())
	if e != nil {
		return ErrUnavailable
	}
	opened, oe := root.Stat(".")
	after, ae := s.root.Lstat(s.directoryName())
	if oe != nil || ae != nil || !safeAssociationDirectory(opened) || !safeAssociationDirectory(after) || !os.SameFile(path, opened) || !os.SameFile(opened, after) {
		root.Close()
		return ErrUnavailable
	}
	s.associationRoot = root
	return nil
}
func (s *LegacyDeviceStore) ensureNamespace() error {
	if s.associationRoot == nil {
		if s.root.Mkdir(s.directoryName(), 0700) != nil || s.openNamespace() != nil || s.associationRoot == nil {
			return ErrUnavailable
		}
	}
	if !s.namespaceValid() || syncDirectory(s.associationRoot) != nil || syncDirectory(s.root) != nil || !s.validLocked() {
		return ErrUnavailable
	}
	return nil
}
func (s *LegacyDeviceStore) validLocked() bool {
	if s.closed || s.failed || s.root == nil || s.guard == nil || !s.guard.Valid() || !s.sourceValidLocked() || !s.namespaceValid() {
		return false
	}
	if s.descriptor == nil {
		_, present, e := readRecoverable(s.root, s.name)
		return e == nil && !present
	}
	raw, e := readExactFile(s.root, s.name, 1)
	return e == nil && bytes.Equal(raw, s.descriptorRaw)
}
func (s *LegacyDeviceStore) leaseValidLocked() bool {
	now := time.Now()
	return s.signedOK && s.begun && s.ctx != nil && s.ctx.Err() == nil && !s.started.IsZero() && now.Before(s.started.Add(30*time.Second)) && now.Before(s.deadline) && s.descriptor != nil && s.descriptor.Binding.ExpiresAt.After(now)
}
func (s *LegacyDeviceStore) liveLocked() bool {
	return s.leaseValidLocked() && s.validLocked() && s.leaseValidLocked()
}
func legacyBinding(a wire.CurrentAuthority) legacyDeviceBinding {
	return legacyDeviceBinding{a.OrganizationID, a.WorkspaceID, a.EnvironmentID, a.DeviceID, a.CredentialID, a.CredentialGeneration, a.PublicKey, a.ExpiresAt}
}
func (b legacyDeviceBinding) wire() associationwire.DeviceBinding {
	return associationwire.DeviceBinding{OrganizationID: b.OrganizationID, WorkspaceID: b.WorkspaceID, EnvironmentID: b.EnvironmentID, DeviceID: b.DeviceID, CredentialID: b.CredentialID, CredentialGeneration: b.CredentialGeneration, PublicKey: b.PublicKey, ExpiresAt: b.ExpiresAt}
}
func (s *LegacyDeviceStore) decodeDescriptor(raw []byte) (legacyDeviceDescriptor, error) {
	var value legacyDeviceDescriptor
	if len(raw) == 0 || len(raw) > 16384 || json.Unmarshal(raw, &value) != nil {
		return value, ErrUnavailable
	}
	canonical, e := json.Marshal(value)
	authority, e2 := wire.MarshalCurrentAuthority(value.FirstAuthority)
	if e != nil || e2 != nil || len(authority) == 0 || !bytes.Equal(raw, canonical) || value.Schema != "gateway-current-device-association-state-v1" || value.IdentitySource != "current_device_authority" || value.Endpoint != s.endpoint || value.CredentialID != s.credentialID || value.KeyID != s.keyID || value.PublicKey != s.publicKey || value.FirstAuthority.CredentialID != s.credentialID || value.FirstAuthority.KeyID != s.keyID || value.FirstAuthority.PublicKey != s.publicKey || value.Binding != legacyBinding(value.FirstAuthority) || !whole(value.ObservedAt) || !value.FirstAuthority.ExpiresAt.After(value.ObservedAt) {
		return value, ErrUnavailable
	}
	return value, nil
}
func (s *LegacyDeviceStore) SignAuthorityRequest(req *http.Request, now time.Time) error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.signed {
		return ErrUnavailable
	}
	s.signed = true
	s.started = time.Now()
	s.signedAt = now
	if req == nil || req.URL == nil || !whole(now) || !s.validLocked() {
		return ErrUnavailable
	}
	s.ctx = req.Context()
	deadline, ok := s.ctx.Deadline()
	if !ok || s.ctx.Err() != nil || !deadline.After(s.started) || deadline.After(s.started.Add(30*time.Second)) {
		return ErrUnavailable
	}
	s.deadline = deadline
	if req.URL.Scheme+"://"+req.URL.Host != s.endpoint {
		return ErrUnavailable
	}
	signer := func(message []byte) ([]byte, error) {
		if !s.sourceValidLocked() {
			return nil, ErrUnavailable
		}
		return ed25519.Sign(s.key, message), nil
	}
	if associationwire.SignCurrentDeviceAuthorityRequest(req, s.credentialID, s.keyID, s.publicKey, signer, now) != nil || !s.validLocked() || s.ctx.Err() != nil || !time.Now().Before(s.deadline) {
		return ErrUnavailable
	}
	s.signedOK = true
	return nil
}
func (s *LegacyDeviceStore) BeginAssociation(envelope associationwire.ChallengeEnvelope, authority wire.CurrentAuthority, now time.Time) (*LegacyAssociation, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.begun {
		return nil, ErrUnavailable
	}
	s.begun = true
	if !s.signedOK || s.ctx == nil || s.ctx.Err() != nil || !whole(now) || now.Before(s.signedAt) || now.After(s.signedAt.Add(30*time.Second)) || !time.Now().Before(s.started.Add(30*time.Second)) || !time.Now().Before(s.deadline) || !s.validLocked() {
		return nil, ErrUnavailable
	}
	rawAuthority, e := wire.MarshalCurrentAuthority(authority)
	if e != nil || len(rawAuthority) == 0 || authority.CredentialID != s.credentialID || authority.KeyID != s.keyID || authority.PublicKey != s.publicKey || !authority.ExpiresAt.After(now) || !authority.ExpiresAt.After(time.Now()) {
		return nil, ErrUnavailable
	}
	challenge, e := associationwire.ChallengeFromEnvelope(envelope)
	if e != nil || challenge.OrganizationID != authority.OrganizationID || challenge.WorkspaceID != authority.WorkspaceID || challenge.EnvironmentID != authority.EnvironmentID || challenge.DeviceID != authority.DeviceID || !challenge.ExpiresAt.After(now) || !challenge.ExpiresAt.After(time.Now()) {
		return nil, ErrUnavailable
	}
	binding := legacyBinding(authority)
	if s.descriptor != nil {
		if s.descriptor.Binding != binding {
			return nil, ErrUnavailable
		}
	} else {
		descriptor := legacyDeviceDescriptor{"gateway-current-device-association-state-v1", "current_device_authority", s.endpoint, s.credentialID, s.keyID, s.publicKey, binding, authority, now}
		encoded, e := json.Marshal(descriptor)
		if e != nil || publish(s.root, s.name, encoded) != nil {
			s.failed = true
			return nil, ErrUnavailable
		}
		s.descriptor = &descriptor
		s.descriptorRaw = append([]byte(nil), encoded...)
	}
	if s.ensureNamespace() != nil {
		s.failed = true
		return nil, ErrUnavailable
	}
	raw, e := associationwire.BuildAcceptRequest(envelope)
	if e != nil {
		return nil, ErrUnavailable
	}
	intent := legacyAssociationIntent{"gateway-current-device-association-intent-v1", "current_device_authority", s.endpoint, legacyPublicCredential{s.credentialID, s.keyID, s.publicKey}, binding, envelope, append(json.RawMessage(nil), raw...)}
	encoded, e := json.Marshal(intent)
	if e != nil {
		return nil, ErrUnavailable
	}
	prefix := challenge.ChallengeID + "." + envelope.ChallengeSHA256
	a := &LegacyAssociation{store: s, intentName: prefix + ".intent", receiptName: prefix + ".receipt", intentRaw: append([]byte(nil), encoded...), snapshot: AssociationSnapshot{Challenge: challenge, Envelope: envelope, RequestRaw: append([]byte(nil), raw...), Binding: binding.wire()}}
	_, present, e := readRecoverable(s.associationRoot, a.intentName)
	if e != nil {
		return nil, ErrUnavailable
	}
	if !present {
		if _, receiptPresent, e := readRecoverable(s.associationRoot, a.receiptName); e != nil || receiptPresent {
			return nil, ErrUnavailable
		}
	}
	if publish(s.associationRoot, a.intentName, encoded) != nil {
		s.failed = true
		return nil, ErrUnavailable
	}
	receiptRaw, present, e := readRecoverable(s.associationRoot, a.receiptName)
	if e != nil {
		return nil, ErrUnavailable
	}
	if present {
		receipt, e := a.decodeReceipt(receiptRaw)
		if e != nil {
			return nil, ErrUnavailable
		}
		if publish(s.associationRoot, a.receiptName, receiptRaw) != nil {
			s.failed = true
			return nil, ErrUnavailable
		}
		a.snapshot.Receipt = &receipt
	}
	if !a.validLocked() {
		s.failed = true
		return nil, ErrUnavailable
	}
	return a, nil
}
func (a *LegacyAssociation) validLocked() bool {
	if a.closed || a.store == nil || !a.store.liveLocked() || a.store.associationRoot == nil || !a.snapshot.Challenge.ExpiresAt.After(time.Now()) {
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
	return a.store.leaseValidLocked() && a.snapshot.Challenge.ExpiresAt.After(time.Now())
}
func (a *LegacyAssociation) Source() (string, AssociationSnapshot, error) {
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
	return s.endpoint, copyAssociationSnapshot(a.snapshot), nil
}
func (a *LegacyAssociation) Sign(message []byte) ([]byte, error) {
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
	defer s.mu.Unlock()
	if !a.validLocked() {
		return nil, ErrUnavailable
	}
	signature := ed25519.Sign(s.key, message)
	if !a.validLocked() {
		clear(signature)
		return nil, ErrUnavailable
	}
	return signature, nil
}
func (a *LegacyAssociation) decodeReceipt(raw []byte) (associationwire.AcceptResponse, error) {
	var receipt legacyAssociationReceipt
	if len(raw) == 0 || len(raw) > 16384 || json.Unmarshal(raw, &receipt) != nil {
		return associationwire.AcceptResponse{}, ErrUnavailable
	}
	canonical, e := json.Marshal(receipt)
	if e != nil || !bytes.Equal(raw, canonical) || receipt.Schema != "gateway-current-device-association-receipt-v1" || receipt.IntentSHA256 != wire.Digest(a.intentRaw) {
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
func (a *LegacyAssociation) Confirm(response associationwire.AcceptResponse, now time.Time) error {
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
	if !a.validLocked() || !whole(now) || now.Before(s.signedAt) || now.After(s.signedAt.Add(30*time.Second)) || !associationwire.AcceptResponseMatches(response, a.snapshot.RequestRaw, a.snapshot.Binding, now) || !response.Acceptance.ExpiresAt.After(time.Now()) {
		return ErrUnavailable
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
	raw, e := json.Marshal(legacyAssociationReceipt{"gateway-current-device-association-receipt-v1", wire.Digest(a.intentRaw), response})
	if e != nil || publish(s.associationRoot, a.receiptName, raw) != nil {
		s.failed = true
		return ErrUnavailable
	}
	a.snapshot.Receipt = &response
	if !a.validLocked() || !response.Acceptance.ExpiresAt.After(time.Now()) {
		s.failed = true
		return ErrUnavailable
	}
	return nil
}
func (a *LegacyAssociation) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.store = nil
	return nil
}
func (s *LegacyDeviceStore) Close() error {
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
	clear(s.sourceRaw)
	s.sourceRaw = nil
	var result error
	for _, closer := range []io.Closer{s.associationRoot, s.guard, s.root, s.sourceFile, s.sourceRoot} {
		// Typed nil pointers need explicit checks before interface dispatch.
		switch c := closer.(type) {
		case *os.Root:
			if c != nil && c.Close() != nil {
				result = ErrUnavailable
			}
		case *os.File:
			if c != nil && c.Close() != nil {
				result = ErrUnavailable
			}
		case *cacheownership.Guard:
			if c != nil && c.Close() != nil {
				result = ErrUnavailable
			}
		}
	}
	s.associationRoot = nil
	s.guard = nil
	s.root = nil
	s.sourceFile = nil
	s.sourceRoot = nil
	s.ctx = nil
	return result
}
