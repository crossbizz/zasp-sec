// Package endpointprotocol defines the device request signature used in addition
// to a single-purpose transport credential. Every HTTP request is scoped to a
// unique enrolled public key and exact product operation.
package endpointprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

const Permission = "sync_endpoint"
const Audience = "zasp.endpoint-request.v1"

var ErrInvalid = errors.New("invalid endpoint request proof")
var Label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var Digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Binding struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Device       string `json:"device_id"`
	Generation   uint64 `json:"credential_generation"`
}

type Proof struct {
	Audience  string  `json:"audience"`
	Binding   Binding `json:"binding"`
	Operation string  `json:"operation"`
	Unix      int64   `json:"timestamp"`
	Nonce     string  `json:"nonce"`
	Digest    string  `json:"body_sha256"`
}

func digest(body []byte) string {
	d := sha256.Sum256(body)
	return hex.EncodeToString(d[:])
}

func Sign(headers http.Header, binding Binding, op string, body []byte, key ed25519.PrivateKey, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize || binding.Generation == 0 {
		return ErrInvalid
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	p := Proof{Audience: Audience, Binding: binding, Operation: op, Unix: now.Unix(), Nonce: hex.EncodeToString(nonce), Digest: digest(body)}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	headers.Set("X-Zasp-Device-Proof", base64.RawURLEncoding.EncodeToString(raw))
	headers.Set("X-Zasp-Device-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw)))
	return nil
}

func Parse(headers http.Header, org, ws, env, op string, body []byte, now time.Time) (Proof, []byte, error) {
	var p Proof
	proof := headers.Values("X-Zasp-Device-Proof")
	if len(proof) != 1 || len(proof[0]) > 2048 || len(headers.Values("X-Zasp-Device-Signature")) != 1 {
		return p, nil, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(proof[0])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return p, nil, ErrInvalid
	}
	canonical, _ := json.Marshal(p)
	if !bytes.Equal(canonical, raw) || p.Audience != Audience || p.Binding.Organization != org || p.Binding.Workspace != ws || p.Binding.Environment != env || p.Operation != op || p.Binding.Generation == 0 || p.Binding.Generation > 1<<53 || !Label.MatchString(p.Binding.Device) || p.Unix < now.Unix()-120 || p.Unix > now.Unix()+30 || len(p.Nonce) != 32 || p.Digest != digest(body) {
		return p, nil, ErrInvalid
	}
	if _, err := hex.DecodeString(p.Nonce); err != nil {
		return p, nil, ErrInvalid
	}
	return p, raw, nil
}

func Verify(headers http.Header, key []byte, raw []byte) bool {
	sig, err := base64.RawURLEncoding.Strict().DecodeString(headers.Get("X-Zasp-Device-Signature"))
	return err == nil && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, raw, sig)
}

type Heartbeat struct {
	Adapter      string `json:"adapter,omitempty"`
	Revision     uint64 `json:"policy_revision"`
	PolicyStatus string `json:"policy_status"`
	Queued       int    `json:"queued_receipts"`
	Gaps         uint64 `json:"dropped_receipts"`
}

func (h Heartbeat) Valid() bool {
	switch h.Adapter {
	case "", "macos_claude_ticket", "linux_claude_ticket_test":
	case "windows_inventory":
		if h.Revision != 0 || h.PolicyStatus != "policy_unavailable" || h.Queued != 0 || h.Gaps != 0 {
			return false
		}
	default:
		return false
	}
	return h.Queued >= 0 && h.Queued <= 256 && h.Revision <= 1<<53 && h.Gaps <= 1<<53 && (h.PolicyStatus == "verified_cache" || h.PolicyStatus == "policy_expired" || h.PolicyStatus == "policy_unavailable" || h.PolicyStatus == "state_unavailable")
}
