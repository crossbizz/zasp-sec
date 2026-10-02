package authorization

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// AttestationKey binds application Check results to the registered SQL verifier.
// It is purpose-derived from the server secret; SQL API roles never receive it.
type AttestationKey struct {
	key     [32]byte
	version string
}

func NewAttestationKey(serverSecret []byte) (*AttestationKey, error) {
	if len(serverSecret) < 32 || len(serverSecret) > 4096 {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, serverSecret)
	_, _ = mac.Write([]byte("zasp-authorization-attestation-key-v1"))
	k := &AttestationKey{}
	copy(k.key[:], mac.Sum(nil))
	id := sha256.Sum256(k.key[:])
	k.version = hex.EncodeToString(id[:])
	return k, nil
}

func (k *AttestationKey) Version() string {
	if k == nil {
		return ""
	}
	return k.version
}

// Verifier is for explicit migration-principal registration, never API output.
func (k *AttestationKey) Verifier() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.key[:]...)
}

func (k *AttestationKey) Sign(body []byte) ([]byte, error) {
	if k == nil || len(body) == 0 || len(body) > 8*1024*1024 || !json.Valid(body) {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, k.key[:])
	_, _ = mac.Write([]byte("zasp-authorization-attestation-v1\x00"))
	_, _ = mac.Write(body)
	return json.Marshal(struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}{body, k.version, hex.EncodeToString(mac.Sum(nil))})
}
