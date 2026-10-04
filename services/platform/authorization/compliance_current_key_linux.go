package authorization

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComplianceCurrentPurpose is separate from the original worker purpose family.
// A key proves signer origin; it never establishes product or native admission.
type ComplianceCurrentPurpose string

const (
	ComplianceCurrentExecution ComplianceCurrentPurpose = "compliance-current-execution-v1"
	ComplianceCurrentCleanup   ComplianceCurrentPurpose = "compliance-current-cleanup-v1"
)

type ComplianceCurrentKey struct {
	purpose ComplianceCurrentPurpose
	key     [32]byte
	version string
}

func validComplianceCurrentPurpose(p ComplianceCurrentPurpose) bool {
	return p == ComplianceCurrentExecution || p == ComplianceCurrentCleanup
}
func NewComplianceCurrentKey(p ComplianceCurrentPurpose, seed []byte) (*ComplianceCurrentKey, error) {
	if !validComplianceCurrentPurpose(p) || len(seed) < 32 || len(seed) > 4096 {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte("zasp-authorization-" + string(p) + "-key-v1"))
	sum := mac.Sum(nil)
	defer clear(sum)
	k := &ComplianceCurrentKey{purpose: p}
	copy(k.key[:], sum)
	version := sha256.Sum256(k.key[:])
	k.version = hex.EncodeToString(version[:])
	return k, nil
}
func (k *ComplianceCurrentKey) Version() string {
	if k == nil {
		return ""
	}
	return k.version
}
func (k *ComplianceCurrentKey) Verifier() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.key[:]...)
}
func (ComplianceCurrentKey) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[compliance current authorization key]"))
}
func LoadComplianceCurrentKeyFile(p ComplianceCurrentPurpose, path string) (*ComplianceCurrentKey, error) {
	if !validComplianceCurrentPurpose(p) {
		return nil, ErrInvalid
	}
	held, err := holdComplianceCurrentKeyFile(path)
	if err != nil {
		return nil, ErrInvalid
	}
	seed, readErr := held.readSeed()
	defer clear(seed)
	closeErr := held.validateAndClose()
	if readErr != nil || closeErr != nil {
		return nil, ErrInvalid
	}
	return NewComplianceCurrentKey(p, seed)
}
