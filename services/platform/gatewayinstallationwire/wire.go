// Package gatewayinstallationwire defines authenticated gateway installation testimony.
package gatewayinstallationwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const ObservationSchema = "gateway-policy-installation-v1"
const ReceiptSchema = "gateway-policy-installation-receipt-v1"
const MaximumBytes = 4096

var ErrInvalid = errors.New("invalid gateway installation wire")

type Observation struct {
	Schema               string    `json:"schema"`
	CredentialGeneration uint64    `json:"credential_generation"`
	ContractVersion      int       `json:"contract_version"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	Audience             string    `json:"audience"`
	Sequence             uint64    `json:"sequence"`
	PolicyVersion        uint64    `json:"policy_version"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	FailureMode          string    `json:"failure_mode"`
	PayloadDigest        string    `json:"payload_digest"`
	Signature            string    `json:"signature"`
	InstalledObservedAt  time.Time `json:"installed_observed_at"`
}
type Binding struct{ OrganizationID, WorkspaceID, EnvironmentID, DeviceID, CredentialID string }
type Receipt struct {
	Schema                            string    `json:"schema"`
	RequestSHA256                     string    `json:"request_sha256"`
	OrganizationID                    string    `json:"organization_id"`
	WorkspaceID                       string    `json:"workspace_id"`
	EnvironmentID                     string    `json:"environment_id"`
	DeviceID                          string    `json:"device_id"`
	CredentialID                      string    `json:"credential_id"`
	CredentialGeneration              uint64    `json:"credential_generation"`
	Disposition                       string    `json:"disposition"`
	RepresentativeSHA256              string    `json:"representative_sha256"`
	RepresentativeSequence            uint64    `json:"representative_sequence"`
	RepresentativeInstalledObservedAt time.Time `json:"representative_installed_observed_at"`
	RepresentativeRecordedAt          time.Time `json:"representative_recorded_at"`
}

// ParseObservation preserves identity in the caller's original bytes. It performs
// structural checks, deliberately not a wall-clock freshness decision.
func ParseObservation(raw []byte) (Observation, error) {
	var value Observation
	fields, err := closedObject(raw, observationKeys)
	if err != nil {
		return value, ErrInvalid
	}
	if !integerFields(fields, "credential_generation", "contract_version", "sequence", "policy_version") || !timestampFields(fields, false, "issued_at", "expires_at", "installed_observed_at") {
		return value, ErrInvalid
	}
	if json.Unmarshal(raw, &value) != nil || !validObservation(value) {
		return Observation{}, ErrInvalid
	}
	return value, nil
}
func MarshalObservation(value Observation) ([]byte, error) {
	if !validObservation(value) {
		return nil, ErrInvalid
	}
	return marshalBounded(value)
}
func ParseReceipt(raw []byte) (Receipt, error) {
	var value Receipt
	fields, err := closedObject(raw, receiptKeys)
	if err != nil {
		return value, ErrInvalid
	}
	if !integerFields(fields, "credential_generation", "representative_sequence") || !timestampFields(fields, false, "representative_installed_observed_at") || !timestampFields(fields, true, "representative_recorded_at") {
		return value, ErrInvalid
	}
	if json.Unmarshal(raw, &value) != nil || !validReceipt(value) {
		return Receipt{}, ErrInvalid
	}
	return value, nil
}
func MarshalReceipt(value Receipt) ([]byte, error) {
	if !validReceipt(value) {
		return nil, ErrInvalid
	}
	return marshalBounded(value)
}
func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// ValidateAt applies first-admission time checks. Retained replay callers use
// ParseObservation instead, and separately reauthenticate current authority.
func ValidateAt(value Observation, now time.Time) error {
	if !validObservation(value) || now.IsZero() || value.IssuedAt.After(now.Add(30*time.Second)) || value.InstalledObservedAt.After(now.Add(30*time.Second)) || !value.ExpiresAt.After(now) {
		return ErrInvalid
	}
	return nil
}
func ReceiptMatches(receipt Receipt, observation Observation, requestSHA256 string, binding Binding) bool {
	if !validReceipt(receipt) || !validObservation(observation) || !hashPattern.MatchString(requestSHA256) || receipt.RequestSHA256 != requestSHA256 || receipt.OrganizationID != binding.OrganizationID || receipt.WorkspaceID != binding.WorkspaceID || receipt.EnvironmentID != binding.EnvironmentID || receipt.DeviceID != binding.DeviceID || receipt.CredentialID != binding.CredentialID || receipt.CredentialGeneration != observation.CredentialGeneration {
		return false
	}
	rank := RankCompare(receipt.RepresentativeSequence, receipt.RepresentativeInstalledObservedAt, receipt.RepresentativeSHA256, observation.Sequence, observation.InstalledObservedAt, requestSHA256)
	if receipt.Disposition == "recorded" {
		return rank == 0 && receipt.RepresentativeSHA256 == requestSHA256
	}
	return receipt.Disposition == "coalesced" && rank > 0
}

// RankCompare orders immutable testimony by sequence, original observation time,
// then the lowercase exact-body digest. It grants no caller authority.
func RankCompare(sequence uint64, observed time.Time, digest string, otherSequence uint64, otherObserved time.Time, otherDigest string) int {
	if sequence < otherSequence {
		return -1
	}
	if sequence > otherSequence {
		return 1
	}
	if observed.Before(otherObserved) {
		return -1
	}
	if observed.After(otherObserved) {
		return 1
	}
	return strings.Compare(digest, otherDigest)
}

var (
	keyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)
	hashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	integerPattern  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	productPattern  = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	observationKeys = []string{"schema", "credential_generation", "contract_version", "key_id", "algorithm", "audience", "sequence", "policy_version", "issued_at", "expires_at", "failure_mode", "payload_digest", "signature", "installed_observed_at"}
	receiptKeys     = []string{"schema", "request_sha256", "organization_id", "workspace_id", "environment_id", "device_id", "credential_id", "credential_generation", "disposition", "representative_sha256", "representative_sequence", "representative_installed_observed_at", "representative_recorded_at"}
)

func validObservation(v Observation) bool {
	if v.Schema != ObservationSchema || v.CredentialGeneration == 0 || v.CredentialGeneration > math.MaxInt64 || v.ContractVersion != 1 || !keyPattern.MatchString(v.KeyID) || v.Algorithm != "Ed25519" || v.Audience != "runtime-gateway-policy" || v.Sequence == 0 || v.Sequence > math.MaxInt64 || v.PolicyVersion == 0 || v.PolicyVersion > math.MaxInt64 || !wholeTime(v.IssuedAt) || !wholeTime(v.ExpiresAt) || !wholeTime(v.InstalledObservedAt) || !v.ExpiresAt.After(v.IssuedAt) || v.ExpiresAt.Sub(v.IssuedAt) > 24*time.Hour || v.InstalledObservedAt.Before(v.IssuedAt.Add(-30*time.Second)) || !v.InstalledObservedAt.Before(v.ExpiresAt) || v.FailureMode != "open" && v.FailureMode != "closed" || !hashPattern.MatchString(v.PayloadDigest) {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(v.Signature)
	return err == nil && len(signature) == 64 && base64.RawURLEncoding.EncodeToString(signature) == v.Signature
}
func validReceipt(v Receipt) bool {
	return v.Schema == ReceiptSchema && hashPattern.MatchString(v.RequestSHA256) && validID(v.OrganizationID) && validID(v.WorkspaceID) && validID(v.EnvironmentID) && validID(v.DeviceID) && validID(v.CredentialID) && v.CredentialGeneration > 0 && v.CredentialGeneration <= math.MaxInt64 && (v.Disposition == "recorded" || v.Disposition == "coalesced") && hashPattern.MatchString(v.RepresentativeSHA256) && v.RepresentativeSequence > 0 && v.RepresentativeSequence <= math.MaxInt64 && wholeTime(v.RepresentativeInstalledObservedAt) && microTime(v.RepresentativeRecordedAt) && (v.Disposition != "recorded" || v.RequestSHA256 == v.RepresentativeSHA256) && (v.Disposition != "coalesced" || v.RequestSHA256 != v.RepresentativeSHA256)
}
func validID(v string) bool {
	if !productPattern.MatchString(v) {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(v[4:], "-", ""))
	if err != nil || len(raw) != 16 {
		return false
	}
	raw[6] &= 0x0f
	raw[8] &= 0x3f
	for _, b := range raw {
		if b != 0 {
			return true
		}
	}
	return false
}

func wholeTime(v time.Time) bool { return microTime(v) && v.Nanosecond() == 0 }
func microTime(v time.Time) bool {
	return !v.IsZero() && v.Location() == time.UTC && v.Year() >= 1 && v.Year() <= 9999 && v.Nanosecond()%1000 == 0
}
func marshalBounded(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaximumBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func integerFields(fields map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		if !integerPattern.Match(fields[key]) {
			return false
		}
	}
	return true
}
func timestampFields(fields map[string]json.RawMessage, micro bool, keys ...string) bool {
	for _, key := range keys {
		var text string
		if json.Unmarshal(fields[key], &text) != nil {
			return false
		}
		value, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || !microTime(value) || !micro && value.Nanosecond() != 0 || value.Format(time.RFC3339Nano) != text {
			return false
		}
	}
	return true
}
func closedObject(raw []byte, keys []string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaximumBytes || !utf8.Valid(raw) || !validSurrogates(raw) {
		return nil, ErrInvalid
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, ErrInvalid
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, ErrInvalid
		}
		if _, exists := fields[key]; exists {
			return nil, ErrInvalid
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrInvalid
		}
		fields[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(fields) != len(keys) {
		return nil, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return fields, nil
}

// encoding/json replaces lone UTF-16 surrogates. Reject those source encodings
// before decoding so replacement cannot collapse distinct signed requests.
func validSurrogates(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		unit, ok := hexUnit(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		if unit < 0xd800 || unit > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, ok := hexUnit(raw[i+3 : i+7])
		if !ok || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return !inString
}
func hexUnit(raw []byte) (uint16, bool) {
	var value uint16
	for _, b := range raw {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value += uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value += uint16(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			value += uint16(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}
