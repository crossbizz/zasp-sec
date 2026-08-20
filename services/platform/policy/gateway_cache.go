package policy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
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
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrGatewayPolicy = errors.New("gateway policy rejected")

var gatewayKeyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)

const (
	GatewayPolicyValid         = "valid"
	GatewayPolicyExpiredOpen   = "expired_open"
	GatewayPolicyExpiredClosed = "expired_closed"
	maximumGatewayPolicyBytes  = 1024 * 1024
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
	digest, payload, err := canonicalGatewayPolicyPayload(envelope)
	if err != nil || digest != envelope.PayloadDigest {
		return GatewayPolicyEnvelope{}, ErrGatewayPolicy
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
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
	mu      sync.RWMutex
	keys    GatewayPolicyKeys
	binding GatewayPolicyBinding
	now     func() time.Time
	path    string
	current *GatewayPolicyEnvelope
}

func NewGatewayPolicyCache(keys GatewayPolicyKeys, binding GatewayPolicyBinding, now func() time.Time) (*GatewayPolicyCache, error) {
	return newGatewayPolicyCache("", keys, binding, now)
}

func NewGatewayPolicyDiskCache(path string, keys GatewayPolicyKeys, binding GatewayPolicyBinding, now func() time.Time) (*GatewayPolicyCache, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, ErrGatewayPolicy
	}
	cache, err := newGatewayPolicyCache(path, keys, binding, now)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return cache, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 2 || info.Size() > maximumGatewayPolicyBytes {
		return nil, ErrGatewayPolicy
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrGatewayPolicy
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumGatewayPolicyBytes+1))
	if err != nil || len(raw) > maximumGatewayPolicyBytes {
		return nil, ErrGatewayPolicy
	}
	envelope, err := decodeGatewayPolicyEnvelope(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	nowValue, ok := gatewayNow(cache.now)
	if !ok {
		return nil, ErrGatewayPolicy
	}
	verified, err := verifyGatewayPolicyEnvelope(envelope, cache.keys, cache.binding, nowValue, true)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(verified)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrGatewayPolicy
	}
	cache.current = &verified
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
	if _, ok := gatewayNow(now); !ok {
		return nil, ErrGatewayPolicy
	}
	return &GatewayPolicyCache{keys: clonedKeys, binding: binding, now: now, path: path}, nil
}

func (cache *GatewayPolicyCache) Store(envelope GatewayPolicyEnvelope) error {
	if cache == nil || cache.now == nil {
		return ErrGatewayPolicy
	}
	now, ok := gatewayNow(cache.now)
	if !ok {
		return ErrGatewayPolicy
	}
	verified, err := VerifyGatewayPolicyEnvelope(envelope, cache.keys, cache.binding, now)
	if err != nil {
		return err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.current != nil {
		if verified.Sequence < cache.current.Sequence || verified.PolicyVersion < cache.current.PolicyVersion {
			return ErrGatewayPolicy
		}
		if verified.Sequence == cache.current.Sequence {
			if !equalGatewayEnvelope(verified, *cache.current) {
				return ErrGatewayPolicy
			}
			if cache.path != "" {
				return writeGatewayPolicyFile(cache.path, verified)
			}
			return nil
		}
		if verified.PolicyVersion == cache.current.PolicyVersion && !equalGatewayPolicies(verified.Policies, cache.current.Policies) {
			return ErrGatewayPolicy
		}
	}
	if cache.path != "" {
		if err := writeGatewayPolicyFile(cache.path, verified); err != nil {
			return err
		}
	}
	cloned := cloneGatewayPolicyEnvelope(verified)
	cache.current = &cloned
	return nil
}

func (cache *GatewayPolicyCache) Current(now time.Time) (GatewayPolicyEnvelope, string, error) {
	if cache == nil || !canonicalGatewayTime(now) {
		return GatewayPolicyEnvelope{}, "", ErrGatewayPolicy
	}
	cache.mu.RLock()
	if cache.current == nil {
		cache.mu.RUnlock()
		return GatewayPolicyEnvelope{}, "", ErrGatewayPolicy
	}
	current := cloneGatewayPolicyEnvelope(*cache.current)
	cache.mu.RUnlock()
	verified, err := verifyGatewayPolicyEnvelope(current, cache.keys, cache.binding, now, true)
	if err != nil {
		return GatewayPolicyEnvelope{}, "", err
	}
	if now.Before(verified.ExpiresAt) {
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

func writeGatewayPolicyFile(path string, envelope GatewayPolicyEnvelope) (result error) {
	bytesValue, err := json.Marshal(cloneGatewayPolicyEnvelope(envelope))
	if err != nil || len(bytesValue) > maximumGatewayPolicyBytes {
		return ErrGatewayPolicy
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".zasp-gateway-policy-*")
	if err != nil {
		return ErrGatewayPolicy
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if result != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return ErrGatewayPolicy
	}
	if _, err := temporary.Write(bytesValue); err != nil {
		return ErrGatewayPolicy
	}
	if err := temporary.Sync(); err != nil {
		return ErrGatewayPolicy
	}
	if err := temporary.Close(); err != nil {
		return ErrGatewayPolicy
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return ErrGatewayPolicy
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return ErrGatewayPolicy
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return ErrGatewayPolicy
	}
	return nil
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

func equalGatewayPolicies(left, right []CompiledPolicy) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
