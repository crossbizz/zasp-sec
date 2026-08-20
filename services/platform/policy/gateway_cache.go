package policy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrGatewayPolicy = errors.New("gateway policy rejected")

var gatewayKeyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)

const (
	GatewayPolicyValid            = "valid"
	GatewayPolicyExpiredOpen      = "expired_open"
	GatewayPolicyExpiredClosed    = "expired_closed"
	maximumGatewayPolicyBytes     = 1024 * 1024
	maximumGatewayPolicyDiskBytes = maximumGatewayPolicyBytes + 512
	ed25519RawURLSignatureLength  = 86
)

type GatewayPolicyBinding struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	DeviceID       string `json:"device_id"`
}

type GatewayPolicyEnvelope struct {
	ContractVersion int              `json:"contract_version"`
	KeyID           string           `json:"key_id"`
	Algorithm       string           `json:"algorithm"`
	Audience        string           `json:"audience"`
	OrganizationID  string           `json:"organization_id"`
	WorkspaceID     string           `json:"workspace_id"`
	EnvironmentID   string           `json:"environment_id"`
	DeviceID        string           `json:"device_id"`
	Sequence        uint64           `json:"sequence"`
	PolicyVersion   uint64           `json:"policy_version"`
	IssuedAt        time.Time        `json:"issued_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
	FailureMode     string           `json:"failure_mode"`
	PayloadDigest   string           `json:"payload_digest"`
	Policies        []CompiledPolicy `json:"policies"`
	Signature       string           `json:"signature"`
}

type gatewayPolicyDiskState struct {
	Envelope   GatewayPolicyEnvelope `json:"envelope"`
	ObservedAt time.Time             `json:"observed_at"`
}

type GatewayPolicyKeys struct {
	values map[string]ed25519.PublicKey
}

func NewGatewayPolicyKeys(values map[string]ed25519.PublicKey) (GatewayPolicyKeys, error) {
	if len(values) < 1 || len(values) > 32 {
		return GatewayPolicyKeys{}, ErrGatewayPolicy
	}
	result := GatewayPolicyKeys{values: make(map[string]ed25519.PublicKey, len(values))}
	for keyID, key := range values {
		if !gatewayKeyIDPattern.MatchString(keyID) || len(key) != ed25519.PublicKeySize {
			return GatewayPolicyKeys{}, ErrGatewayPolicy
		}
		result.values[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return result, nil
}

func VerifyGatewayPolicyEnvelope(envelope GatewayPolicyEnvelope, keys GatewayPolicyKeys, binding GatewayPolicyBinding, now time.Time) (GatewayPolicyEnvelope, error) {
	return verifyGatewayPolicyEnvelope(envelope, keys, binding, now, false)
}

func verifyGatewayPolicyEnvelope(envelope GatewayPolicyEnvelope, keys GatewayPolicyKeys, binding GatewayPolicyBinding, now time.Time, allowExpired bool) (GatewayPolicyEnvelope, error) {
	if !validGatewayBinding(binding) || !canonicalGatewayTime(now) || len(keys.values) < 1 || envelope.ContractVersion != 1 || !gatewayKeyIDPattern.MatchString(envelope.KeyID) ||
		envelope.Algorithm != "Ed25519" || envelope.Audience != "runtime-gateway-policy" || envelope.Sequence < 1 || envelope.PolicyVersion < 1 ||
		envelope.OrganizationID != binding.OrganizationID || envelope.WorkspaceID != binding.WorkspaceID || envelope.EnvironmentID != binding.EnvironmentID || envelope.DeviceID != binding.DeviceID ||
		!canonicalGatewayTime(envelope.IssuedAt) || !canonicalGatewayTime(envelope.ExpiresAt) || !envelope.ExpiresAt.After(envelope.IssuedAt) || envelope.ExpiresAt.Sub(envelope.IssuedAt) > 24*time.Hour ||
		envelope.IssuedAt.After(now.Add(30*time.Second)) || !allowExpired && !envelope.ExpiresAt.After(now) || envelope.FailureMode != "open" && envelope.FailureMode != "closed" ||
		len(envelope.Policies) < 1 || len(envelope.Policies) > 512 || len(envelope.PayloadDigest) != sha256.Size*2 {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	publicKey, exists := keys.values[envelope.KeyID]
	if !exists || len(publicKey) != ed25519.PublicKeySize {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	if len(envelope.Signature) != ed25519RawURLSignatureLength {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maximumGatewayPolicyBytes {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	digest, payload, err := canonicalGatewayPolicyPayload(envelope)
	if err != nil || digest != envelope.PayloadDigest {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != envelope.Signature || !ed25519.Verify(publicKey, payload, signature) {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	verified := cloneGatewayPolicyEnvelope(envelope)
	sort.Slice(verified.Policies, func(left, right int) bool { return verified.Policies[left].ID < verified.Policies[right].ID })
	return verified, nil
}

func canonicalGatewayPolicyPayload(envelope GatewayPolicyEnvelope) (string, []byte, error) {
	if len(envelope.Policies) < 1 || len(envelope.Policies) > 512 {
		return "", nil, ErrGatewayPolicy
	}
	policies := make([]CompiledPolicy, len(envelope.Policies))
	seen := make(map[string]struct{}, len(envelope.Policies))
	for index, policy := range envelope.Policies {
		if verifyCompiled(policy) != nil {
			return "", nil, ErrGatewayPolicy
		}
		if _, exists := seen[policy.ID]; exists {
			return "", nil, ErrGatewayPolicy
		}
		seen[policy.ID] = struct{}{}
		policies[index] = cloneCompiledPolicy(policy)
	}
	sort.Slice(policies, func(left, right int) bool { return policies[left].ID < policies[right].ID })
	payload, err := json.Marshal(struct {
		ContractVersion int              `json:"contract_version"`
		KeyID           string           `json:"key_id"`
		Algorithm       string           `json:"algorithm"`
		Audience        string           `json:"audience"`
		OrganizationID  string           `json:"organization_id"`
		WorkspaceID     string           `json:"workspace_id"`
		EnvironmentID   string           `json:"environment_id"`
		DeviceID        string           `json:"device_id"`
		Sequence        uint64           `json:"sequence"`
		PolicyVersion   uint64           `json:"policy_version"`
		IssuedAt        time.Time        `json:"issued_at"`
		ExpiresAt       time.Time        `json:"expires_at"`
		FailureMode     string           `json:"failure_mode"`
		Policies        []CompiledPolicy `json:"policies"`
	}{
		ContractVersion: envelope.ContractVersion,
		KeyID:           envelope.KeyID,
		Algorithm:       envelope.Algorithm,
		Audience:        envelope.Audience,
		OrganizationID:  envelope.OrganizationID,
		WorkspaceID:     envelope.WorkspaceID,
		EnvironmentID:   envelope.EnvironmentID,
		DeviceID:        envelope.DeviceID,
		Sequence:        envelope.Sequence,
		PolicyVersion:   envelope.PolicyVersion,
		IssuedAt:        envelope.IssuedAt,
		ExpiresAt:       envelope.ExpiresAt,
		FailureMode:     envelope.FailureMode,
		Policies:        policies,
	})
	if err != nil || len(payload) > maximumGatewayPolicyBytes {
		return "", nil, ErrGatewayPolicy
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), payload, nil
}

type GatewayPolicyCache struct {
	mu         sync.Mutex
	keys       GatewayPolicyKeys
	binding    GatewayPolicyBinding
	now        func() time.Time
	path       string
	current    *GatewayPolicyEnvelope
	observedAt time.Time
}

func NewGatewayPolicyCache(keys GatewayPolicyKeys, binding GatewayPolicyBinding, now func() time.Time) (*GatewayPolicyCache, error) {
	return newGatewayPolicyCache("", keys, binding, now)
}

func NewGatewayPolicyDiskCache(path string, keys GatewayPolicyKeys, binding GatewayPolicyBinding, now func() time.Time) (*GatewayPolicyCache, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, ErrGatewayPolicy
	}
	cache, err := newGatewayPolicyCache(path, keys, binding, now)
	if err != nil {
		return nil, err
	}
	raw, err := readGatewayPolicyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cache, nil
	}
	if err != nil {
		return nil, ErrGatewayPolicy
	}
	state, err := decodeGatewayPolicyDiskState(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	nowValue, ok := gatewayNow(cache.now)
	if !ok || !canonicalGatewayTime(state.ObservedAt) {
		return nil, ErrGatewayPolicy
	}
	effectiveNow := laterGatewayTime(nowValue, state.ObservedAt)
	verified, err := verifyGatewayPolicyEnvelope(state.Envelope, cache.keys, cache.binding, effectiveNow, true)
	if err != nil {
		return nil, err
	}
	canonical, err := marshalGatewayPolicyDiskState(verified, state.ObservedAt)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrGatewayPolicy
	}
	cache.current = &verified
	cache.observedAt = state.ObservedAt
	return cache, nil
}

func newGatewayPolicyCache(path string, keys GatewayPolicyKeys, binding GatewayPolicyBinding, now func() time.Time) (*GatewayPolicyCache, error) {
	if !validGatewayBinding(binding) || len(keys.values) < 1 || now == nil {
		return nil, ErrGatewayPolicy
	}
	clonedKeys, err := NewGatewayPolicyKeys(keys.values)
	if err != nil {
		return nil, err
	}
	nowValue, ok := gatewayNow(now)
	if !ok {
		return nil, ErrGatewayPolicy
	}
	return &GatewayPolicyCache{keys: clonedKeys, binding: binding, now: now, path: path, observedAt: nowValue}, nil
}

func (cache *GatewayPolicyCache) Store(envelope GatewayPolicyEnvelope) error {
	if cache == nil || cache.now == nil {
		return ErrGatewayPolicy
	}
	nowValue, ok := gatewayNow(cache.now)
	if !ok {
		return ErrGatewayPolicy
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	effectiveNow := laterGatewayTime(nowValue, cache.observedAt)
	verified, err := VerifyGatewayPolicyEnvelope(envelope, cache.keys, cache.binding, effectiveNow)
	if err != nil {
		return err
	}
	if cache.current != nil {
		if verified.Sequence < cache.current.Sequence || verified.PolicyVersion < cache.current.PolicyVersion {
			return ErrGatewayPolicy
		}
		if verified.Sequence == cache.current.Sequence {
			if !equalGatewayEnvelope(verified, *cache.current) {
				return ErrGatewayPolicy
			}
			if cache.path != "" {
				if err := writeGatewayPolicyFile(cache.path, verified, effectiveNow); err != nil {
					return err
				}
			}
			cache.observedAt = effectiveNow
			return nil
		}
		if verified.PolicyVersion == cache.current.PolicyVersion && !equalGatewayPolicySemantics(verified, *cache.current) {
			return ErrGatewayPolicy
		}
	}
	if cache.path != "" {
		if err := writeGatewayPolicyFile(cache.path, verified, effectiveNow); err != nil {
			return err
		}
	}
	cloned := cloneGatewayPolicyEnvelope(verified)
	cache.current = &cloned
	cache.observedAt = effectiveNow
	return nil
}

func (cache *GatewayPolicyCache) Current() (GatewayPolicyEnvelope, string, error) {
	if cache == nil || cache.now == nil {
		return GatewayPolicyEnvelope{}, "", ErrGatewayPolicy
	}
	nowValue, ok := gatewayNow(cache.now)
	if !ok {
		return GatewayPolicyEnvelope{}, "", ErrGatewayPolicy
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.current == nil {
		return GatewayPolicyEnvelope{}, "", ErrGatewayPolicy
	}
	current := cloneGatewayPolicyEnvelope(*cache.current)
	effectiveNow := laterGatewayTime(nowValue, cache.observedAt)
	verified, err := verifyGatewayPolicyEnvelope(current, cache.keys, cache.binding, effectiveNow, true)
	if err != nil {
		return GatewayPolicyEnvelope{}, "", err
	}
	if effectiveNow.After(cache.observedAt) {
		if cache.path != "" {
			if err := writeGatewayPolicyFile(cache.path, verified, effectiveNow); err != nil {
				return GatewayPolicyEnvelope{}, "", err
			}
		}
		cache.observedAt = effectiveNow
	}
	if effectiveNow.Before(verified.ExpiresAt) {
		return verified, GatewayPolicyValid, nil
	}
	if verified.FailureMode == "open" {
		return verified, GatewayPolicyExpiredOpen, nil
	}
	return verified, GatewayPolicyExpiredClosed, nil
}

func decodeGatewayPolicyEnvelope(reader io.Reader) (GatewayPolicyEnvelope, error) {
	decoder := json.NewDecoder(bufio.NewReader(reader))
	decoder.DisallowUnknownFields()
	var envelope GatewayPolicyEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	return envelope, nil
}

func decodeGatewayPolicyDiskState(reader io.Reader) (gatewayPolicyDiskState, error) {
	decoder := json.NewDecoder(bufio.NewReader(reader))
	decoder.DisallowUnknownFields()
	var state gatewayPolicyDiskState
	if err := decoder.Decode(&state); err != nil {
		return gatewayPolicyDiskState{}, ErrGatewayPolicy
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return gatewayPolicyDiskState{}, ErrGatewayPolicy
	}
	return state, nil
}

func marshalGatewayPolicyDiskState(envelope GatewayPolicyEnvelope, observedAt time.Time) ([]byte, error) {
	if !canonicalGatewayTime(observedAt) {
		return nil, ErrGatewayPolicy
	}
	bytesValue, err := json.Marshal(gatewayPolicyDiskState{Envelope: cloneGatewayPolicyEnvelope(envelope), ObservedAt: observedAt})
	if err != nil || len(bytesValue) > maximumGatewayPolicyDiskBytes {
		return nil, ErrGatewayPolicy
	}
	return bytesValue, nil
}

func readGatewayPolicyFile(path string) ([]byte, error) {
	root, name, err := openGatewayPolicyRoot(path)
	if err != nil {
		return nil, ErrGatewayPolicy
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() < 2 || before.Size() > maximumGatewayPolicyDiskBytes {
		return nil, ErrGatewayPolicy
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrGatewayPolicy
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 {
		return nil, ErrGatewayPolicy
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) || after.Mode()&os.ModeSymlink != 0 {
		return nil, ErrGatewayPolicy
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumGatewayPolicyDiskBytes+1))
	if err != nil || len(raw) > maximumGatewayPolicyDiskBytes {
		return nil, ErrGatewayPolicy
	}
	return raw, nil
}

func writeGatewayPolicyFile(path string, envelope GatewayPolicyEnvelope, observedAt time.Time) (result error) {
	bytesValue, err := marshalGatewayPolicyDiskState(envelope, observedAt)
	if err != nil {
		return ErrGatewayPolicy
	}
	root, name, err := openGatewayPolicyRoot(path)
	if err != nil {
		return ErrGatewayPolicy
	}
	defer root.Close()
	if info, statErr := root.Lstat(name); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return ErrGatewayPolicy
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrGatewayPolicy
	}
	temporaryName, err := gatewayPolicyTemporaryName()
	if err != nil {
		return ErrGatewayPolicy
	}
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrGatewayPolicy
	}
	defer func() {
		_ = temporary.Close()
		if result != nil {
			_ = root.Remove(temporaryName)
		}
	}()
	if _, err := temporary.Write(bytesValue); err != nil {
		return ErrGatewayPolicy
	}
	if err := temporary.Sync(); err != nil {
		return ErrGatewayPolicy
	}
	if err := temporary.Close(); err != nil {
		return ErrGatewayPolicy
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return ErrGatewayPolicy
	}
	directoryFile, err := root.Open(".")
	if err != nil {
		return ErrGatewayPolicy
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return ErrGatewayPolicy
	}
	return nil
}

func openGatewayPolicyRoot(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", ErrGatewayPolicy
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return nil, "", ErrGatewayPolicy
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, "", ErrGatewayPolicy
	}
	directory := filepath.Dir(path)
	relative, err := filepath.Rel(string(filepath.Separator), directory)
	if err != nil {
		root.Close()
		return nil, "", ErrGatewayPolicy
	}
	if relative == "." {
		return root, name, nil
	}
	for _, component := range splitGatewayPath(relative) {
		before, statErr := root.Lstat(component)
		if statErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, "", ErrGatewayPolicy
		}
		child, openErr := root.OpenRoot(component)
		if openErr != nil {
			root.Close()
			return nil, "", ErrGatewayPolicy
		}
		opened, openStatErr := child.Stat(".")
		after, afterErr := root.Lstat(component)
		root.Close()
		if openStatErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) || after.Mode()&os.ModeSymlink != 0 {
			child.Close()
			return nil, "", ErrGatewayPolicy
		}
		root = child
	}
	return root, name, nil
}

func splitGatewayPath(path string) []string {
	if path == "." || path == "" {
		return nil
	}
	return strings.Split(path, string(filepath.Separator))
}

func gatewayPolicyTemporaryName() (string, error) {
	var bytesValue [16]byte
	if _, err := rand.Read(bytesValue[:]); err != nil {
		return "", ErrGatewayPolicy
	}
	return ".zasp-gateway-policy-" + hex.EncodeToString(bytesValue[:]), nil
}

func validGatewayBinding(value GatewayPolicyBinding) bool {
	for _, text := range []string{value.OrganizationID, value.WorkspaceID, value.EnvironmentID, value.DeviceID} {
		if _, err := domain.ParseProductID(text); err != nil {
			return false
		}
	}
	return value.OrganizationID != value.WorkspaceID && value.OrganizationID != value.EnvironmentID && value.OrganizationID != value.DeviceID &&
		value.WorkspaceID != value.EnvironmentID && value.WorkspaceID != value.DeviceID && value.EnvironmentID != value.DeviceID
}

func canonicalGatewayTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func gatewayNow(now func() time.Time) (time.Time, bool) {
	defer func() { _ = recover() }()
	value := now()
	return value, canonicalGatewayTime(value)
}

func laterGatewayTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

func cloneGatewayPolicyEnvelope(value GatewayPolicyEnvelope) GatewayPolicyEnvelope {
	policies := value.Policies
	value.Policies = make([]CompiledPolicy, len(policies))
	for index, policy := range policies {
		value.Policies[index] = cloneCompiledPolicy(policy)
	}
	return value
}

func cloneCompiledPolicy(value CompiledPolicy) CompiledPolicy {
	value.Conditions = append([]Condition(nil), value.Conditions...)
	return value
}

func equalGatewayEnvelope(left, right GatewayPolicyEnvelope) bool {
	leftBytes, leftErr := json.Marshal(cloneGatewayPolicyEnvelope(left))
	rightBytes, rightErr := json.Marshal(cloneGatewayPolicyEnvelope(right))
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func equalGatewayPolicySemantics(left, right GatewayPolicyEnvelope) bool {
	leftBytes, leftErr := json.Marshal(struct {
		FailureMode string           `json:"failure_mode"`
		Policies    []CompiledPolicy `json:"policies"`
	}{FailureMode: left.FailureMode, Policies: left.Policies})
	rightBytes, rightErr := json.Marshal(struct {
		FailureMode string           `json:"failure_mode"`
		Policies    []CompiledPolicy `json:"policies"`
	}{FailureMode: right.FailureMode, Policies: right.Policies})
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
