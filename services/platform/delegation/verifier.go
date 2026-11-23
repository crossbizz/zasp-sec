package delegation

import (
	"crypto/ed25519"
	"time"
)

// Verifier pins an edge deployment to a single agent and task. Its key is
// public. Agents cannot select another tenant or task through request fields.
type Verifier struct {
	Binding
	PublicKey []byte `json:"public_key"`
}

func (v *Verifier) Valid(t Tenant) bool {
	return v != nil && v.Binding.Valid() && v.Tenant == t && len(v.PublicKey) == ed25519.PublicKeySize
}

func ParseVerifier(raw string, t Tenant) (*Verifier, error) {
	if raw == "" {
		return nil, nil
	}
	var v Verifier
	if len(raw) > 2048 || strict([]byte(raw), &v) != nil || !v.Valid(t) {
		return nil, ErrDenied
	}
	return &v, nil
}

func (v *Verifier) Decide(token, op, resource string, now time.Time) Decision {
	if v == nil {
		return Decision{Status: "denied"}
	}
	return Check(ed25519.PublicKey(v.PublicKey), token, v.Binding, op, resource, now)
}
