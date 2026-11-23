// Package addonsandbox verifies observations produced by an operator-trusted offline scanner.
package addonsandbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const SignatureContext = "zasp-offline-addon-observation.v1\x00"
const MaxReceiptBytes = 4096

var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var ErrReceipt = errors.New("invalid offline scanner evidence")

// Receipt contains only bounded, enumerated observations. Credentials, source
// bytes, file names and process arguments are excluded from this wire format.
type Receipt struct {
	Schema        string    `json:"schema_version"`
	Organization  string    `json:"organization_id"`
	Workspace     string    `json:"workspace_id"`
	Environment   string    `json:"environment_id"`
	Version       string    `json:"addon_version_id"`
	Manifest      string    `json:"manifest_digest"`
	Evidence      string    `json:"evidence_id"`
	Scanner       string    `json:"scanner"`
	ProfileDigest string    `json:"scanner_profile_digest"`
	Isolation     string    `json:"isolation"`
	ObservedAt    time.Time `json:"observed_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Indicators    []string  `json:"indicators"`
}

func Verify(raw, signature, key []byte, scope [3]string, profile string, now time.Time) (Receipt, error) {
	var r Receipt
	if len(raw) == 0 || len(raw) > MaxReceiptBytes || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(SignatureContext), raw...), signature) {
		return r, ErrReceipt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(&struct{}{}) != io.EOF {
		return Receipt{}, ErrReceipt
	}
	// Signed receipts use a single canonical JSON encoding, also excluding
	// duplicate keys and ambiguous numeric or time representations.
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return Receipt{}, ErrReceipt
	}
	for _, id := range []string{r.Organization, r.Workspace, r.Environment, r.Version, r.Evidence} {
		if _, err := domain.ParseProductID(id); err != nil {
			return Receipt{}, ErrReceipt
		}
	}
	if [3]string{r.Organization, r.Workspace, r.Environment} != scope || r.Schema != "zasp-offline-addon-observation.v1" || !digest.MatchString(r.Manifest) || !digest.MatchString(r.ProfileDigest) || r.ProfileDigest != profile || r.ObservedAt.IsZero() || r.ObservedAt.After(now) || !r.ExpiresAt.After(now) || r.ExpiresAt.After(r.ObservedAt.Add(7*24*time.Hour)) || r.Indicators == nil || len(r.Indicators) > 4 {
		return Receipt{}, ErrReceipt
	}
	var allowed []string
	switch r.Scanner {
	case "gvisor_tetragon":
		if r.Isolation != "egress_denied" {
			return Receipt{}, ErrReceipt
		}
		allowed = []string{"honeytoken_read", "honeytoken_egress_denied", "unexpected_process", "filesystem_write"}
	case "cisco_skill_scanner", "nvidia_skillspector":
		if r.Isolation != "offline_static" {
			return Receipt{}, ErrReceipt
		}
		allowed = []string{"instruction_override", "credential_reference", "network_reference", "broad_permissions"}
	default:
		return Receipt{}, ErrReceipt
	}
	seen := map[string]bool{}
	for _, signal := range r.Indicators {
		if !slices.Contains(allowed, signal) || seen[signal] {
			return Receipt{}, ErrReceipt
		}
		seen[signal] = true
	}
	return r, nil
}
