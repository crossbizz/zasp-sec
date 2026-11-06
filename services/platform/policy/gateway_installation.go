package policy

import (
	"bytes"
	"encoding/json"
	"math"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/cacheownership"
)

// A witness is part of the same cache generation as its signed envelope. The
// original body is never reconstructed for retries or from a later clock.
type gatewayPolicyInstallation struct {
	CredentialID string          `json:"credential_id"`
	Body         json.RawMessage `json:"body"`
	Pending      bool            `json:"pending"`
}

// NewGatewayPolicyInstallationDiskCache explicitly selects durable installation
// testimony. Existing v1 caches remain readable without invented observations.
func NewGatewayPolicyInstallationDiskCache(path string, keys GatewayPolicyKeys, binding GatewayPolicyBinding, now func() time.Time) (*GatewayPolicyCache, error) {
	return newGatewayPolicyDiskCache(path, keys, binding, now, true)
}

// InstallationEnabled identifies the selected cache capability, not current
// enforcement, successful delivery, or overall service readiness.
func (cache *GatewayPolicyCache) InstallationEnabled() bool {
	if cache == nil {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.installationReadyLocked()
}
func (cache *GatewayPolicyCache) installationReadyLocked() bool {
	return !cache.closed && cache.installationEnabled && cache.root != nil && cacheownership.Supported() && cache.ownership != nil && cache.ownership.Valid()
}

func cloneGatewayInstallation(value *gatewayPolicyInstallation) *gatewayPolicyInstallation {
	if value == nil {
		return nil
	}
	return &gatewayPolicyInstallation{CredentialID: value.CredentialID, Body: append(json.RawMessage(nil), value.Body...), Pending: value.Pending}
}
func validGatewayInstallation(value *gatewayPolicyInstallation, envelope GatewayPolicyEnvelope) bool {
	if value == nil {
		return true
	}
	if _, err := domain.ParseProductID(value.CredentialID); err != nil {
		return false
	}
	observation, err := wire.ParseObservation(value.Body)
	if err != nil {
		return false
	}
	original, err := wire.MarshalObservation(observation)
	if err != nil || !bytes.Equal(original, value.Body) {
		return false
	}
	return observation.ContractVersion == envelope.ContractVersion && observation.KeyID == envelope.KeyID && observation.Algorithm == envelope.Algorithm && observation.Audience == envelope.Audience && observation.Sequence == envelope.Sequence && observation.PolicyVersion == envelope.PolicyVersion && observation.IssuedAt.Equal(envelope.IssuedAt) && observation.ExpiresAt.Equal(envelope.ExpiresAt) && observation.FailureMode == envelope.FailureMode && observation.PayloadDigest == envelope.PayloadDigest && observation.Signature == envelope.Signature && wire.ValidateAt(observation, observation.InstalledObservedAt) == nil
}
func (cache *GatewayPolicyCache) persistInstallationStateLocked(envelope GatewayPolicyEnvelope, observedAt time.Time, installation *gatewayPolicyInstallation, version int) error {
	if cache.root == nil || cache.ownership != nil && !cache.ownership.Valid() {
		return ErrGatewayPolicy
	}
	raw, err := marshalGatewayPolicyState(envelope, observedAt, version, installation)
	if err != nil {
		return ErrGatewayPolicy
	}
	return writeGatewayPolicyBytesRoot(cache.root, cache.name, raw)
}

// StoreInstallation captures a new signed source and its original observation
// before the one atomic durable write. Reopening or replaying an existing
// envelope never creates or relabels an installation witness.
func (cache *GatewayPolicyCache) StoreInstallation(envelope GatewayPolicyEnvelope, credentialID string, generation uint64) error {
	if cache == nil || cache.now == nil {
		return ErrGatewayPolicy
	}
	if generation == 0 || generation > math.MaxInt64 {
		return ErrGatewayPolicy
	}
	if _, err := domain.ParseProductID(credentialID); err != nil {
		return ErrGatewayPolicy
	}
	nowValue, ok := gatewayNow(cache.now)
	if !ok {
		return ErrGatewayPolicy
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.installationReadyLocked() {
		return ErrGatewayPolicy
	}
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
			if err := cache.persistInstallationStateLocked(verified, effectiveNow, cache.installation, cache.diskVersion); err != nil {
				return err
			}
			cache.observedAt = effectiveNow
			return nil
		}
		if verified.PolicyVersion == cache.current.PolicyVersion && !equalGatewayPolicySemantics(verified, *cache.current) {
			return ErrGatewayPolicy
		}
	}
	observation := wire.Observation{Schema: wire.ObservationSchema, CredentialGeneration: generation, ContractVersion: verified.ContractVersion, KeyID: verified.KeyID, Algorithm: verified.Algorithm, Audience: verified.Audience, Sequence: verified.Sequence, PolicyVersion: verified.PolicyVersion, IssuedAt: verified.IssuedAt, ExpiresAt: verified.ExpiresAt, FailureMode: verified.FailureMode, PayloadDigest: verified.PayloadDigest, Signature: verified.Signature, InstalledObservedAt: effectiveNow}
	raw, err := wire.MarshalObservation(observation)
	if err != nil || wire.ValidateAt(observation, effectiveNow) != nil {
		return ErrGatewayPolicy
	}
	installation := &gatewayPolicyInstallation{CredentialID: credentialID, Body: append(json.RawMessage(nil), raw...), Pending: true}
	if err := cache.persistInstallationStateLocked(verified, effectiveNow, installation, 2); err != nil {
		return err
	}
	cache.installation = installation
	cache.diskVersion = 2
	cloned := cloneGatewayPolicyEnvelope(verified)
	cache.current = &cloned
	cache.observedAt = effectiveNow
	return nil
}

// PendingInstallation returns an owned copy only for the original credential
// generation and current exact envelope. Rotation never relabels old testimony.
func (cache *GatewayPolicyCache) PendingInstallation(credentialID string, generation uint64) ([]byte, error) {
	if cache == nil {
		return nil, ErrGatewayPolicy
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.installationReadyLocked() {
		return nil, ErrGatewayPolicy
	}
	if cache.installation == nil || !cache.installation.Pending || cache.current == nil {
		return nil, nil
	}
	if !validGatewayInstallation(cache.installation, *cache.current) {
		return nil, ErrGatewayPolicy
	}
	observation, err := wire.ParseObservation(cache.installation.Body)
	if err != nil {
		return nil, ErrGatewayPolicy
	}
	if cache.installation.CredentialID != credentialID || observation.CredentialGeneration != generation {
		return nil, nil
	}
	expected, err := marshalGatewayPolicyState(*cache.current, cache.observedAt, cache.diskVersion, cache.installation)
	if err != nil {
		return nil, ErrGatewayPolicy
	}
	actual, err := readGatewayPolicyRoot(cache.root, cache.name)
	if err != nil || !bytes.Equal(expected, actual) {
		return nil, ErrGatewayPolicy
	}
	return append([]byte(nil), cache.installation.Body...), nil
}

// ConfirmInstallation persists compare-and-clear for this exact original body.
// An older response cannot erase a newer policy's pending witness.
func (cache *GatewayPolicyCache) ConfirmInstallation(raw []byte) error {
	if cache == nil {
		return ErrGatewayPolicy
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.installationReadyLocked() || cache.current == nil || cache.installation == nil || !bytes.Equal(raw, cache.installation.Body) || !validGatewayInstallation(cache.installation, *cache.current) {
		return ErrGatewayPolicy
	}
	if !cache.installation.Pending {
		return nil
	}
	next := cloneGatewayInstallation(cache.installation)
	next.Pending = false
	if err := cache.persistInstallationStateLocked(*cache.current, cache.observedAt, next, cache.diskVersion); err != nil {
		return err
	}
	cache.installation = next
	return nil
}
