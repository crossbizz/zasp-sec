// Package gatewayenrollmentwire defines the closed device bootstrap protocol.
package gatewayenrollmentwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const TokenSchema = "gateway-enrollment-token-v1"
const RequestSchema = "gateway-enrollment-request-v1"
const ReceiptSchema = "gateway-enrollment-receipt-v1"
const MaximumBytes = 4096
const EnrollmentPath = "/internal/v1/runtime-gateway/enrollments"
const AuthorizationScheme = "ZaspGatewayEnrollmentV1"

var ErrInvalid = errors.New("gateway enrollment rejected")

type TokenBundle struct {
	Schema               string    `json:"schema"`
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	EnrollmentID         string    `json:"enrollment_id"`
	TokenGeneration      uint64    `json:"token_generation"`
	CredentialGeneration uint64    `json:"credential_generation"`
	EnrollmentExpiresAt  time.Time `json:"enrollment_expires_at"`
	Locator              string    `json:"locator"`
	Secret               string    `json:"secret"`
}
type Request struct {
	Schema               string    `json:"schema"`
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	EnrollmentID         string    `json:"enrollment_id"`
	TokenGeneration      uint64    `json:"token_generation"`
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	ExpiresAt            time.Time `json:"expires_at"`
}
type Receipt struct {
	Schema               string    `json:"schema"`
	RequestSHA256        string    `json:"request_sha256"`
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	EnrollmentID         string    `json:"enrollment_id"`
	TokenGeneration      uint64    `json:"token_generation"`
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	Audience             string    `json:"audience"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	Replayed             bool      `json:"replayed"`
}

func (TokenBundle) String() string             { return "[REDACTED]" }
func (TokenBundle) GoString() string           { return "[REDACTED]" }
func (TokenBundle) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[REDACTED]") }

var tokenKeys = []string{"schema", "organization_id", "workspace_id", "environment_id", "device_id", "enrollment_id", "token_generation", "credential_generation", "enrollment_expires_at", "locator", "secret"}
var requestKeys = []string{"schema", "organization_id", "workspace_id", "environment_id", "device_id", "enrollment_id", "token_generation", "credential_id", "credential_generation", "key_id", "algorithm", "public_key", "expires_at"}
var receiptKeys = []string{"schema", "request_sha256", "organization_id", "workspace_id", "environment_id", "device_id", "enrollment_id", "token_generation", "credential_id", "credential_generation", "key_id", "algorithm", "public_key", "audience", "issued_at", "expires_at", "replayed"}

func ParseTokenBundle(raw []byte) (TokenBundle, error) {
	var v TokenBundle
	fields, e := closedObject(raw, tokenKeys)
	if e != nil || !integerFields(fields, "token_generation", "credential_generation") || !timestampFields(fields, false, "enrollment_expires_at") || json.Unmarshal(raw, &v) != nil || !validToken(v) {
		return TokenBundle{}, ErrInvalid
	}
	return v, nil
}
func MarshalTokenBundle(v TokenBundle) ([]byte, error) {
	if !validToken(v) {
		return nil, ErrInvalid
	}
	return marshalBounded(v)
}
func ParseRequest(raw []byte) (Request, error) {
	var v Request
	fields, e := closedObject(raw, requestKeys)
	if e != nil || !integerFields(fields, "token_generation", "credential_generation") || !timestampFields(fields, false, "expires_at") || json.Unmarshal(raw, &v) != nil || !validRequest(v) {
		return Request{}, ErrInvalid
	}
	return v, nil
}
func MarshalRequest(v Request) ([]byte, error) {
	if !validRequest(v) {
		return nil, ErrInvalid
	}
	return marshalBounded(v)
}
func ParseReceipt(raw []byte) (Receipt, error) {
	var v Receipt
	fields, e := closedObject(raw, receiptKeys)
	if e != nil || !integerFields(fields, "token_generation", "credential_generation") || !timestampFields(fields, false, "expires_at") || !timestampFields(fields, true, "issued_at") || json.Unmarshal(raw, &v) != nil || !validReceipt(v) {
		return Receipt{}, ErrInvalid
	}
	if !bytes.Equal(fields["replayed"], []byte("true")) && !bytes.Equal(fields["replayed"], []byte("false")) {
		return Receipt{}, ErrInvalid
	}
	return v, nil
}
func MarshalReceipt(v Receipt) ([]byte, error) {
	if !validReceipt(v) {
		return nil, ErrInvalid
	}
	return marshalBounded(v)
}
func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func RequestMatchesBundle(r Request, b TokenBundle) bool {
	return validRequest(r) && validToken(b) && r.OrganizationID == b.OrganizationID && r.WorkspaceID == b.WorkspaceID && r.EnvironmentID == b.EnvironmentID && r.DeviceID == b.DeviceID && r.EnrollmentID == b.EnrollmentID && r.TokenGeneration == b.TokenGeneration && r.CredentialGeneration == b.CredentialGeneration
}
func ReceiptMatches(v Receipt, r Request, d string) bool {
	return validReceipt(v) && validRequest(r) && hashPattern.MatchString(d) && v.RequestSHA256 == d && v.OrganizationID == r.OrganizationID && v.WorkspaceID == r.WorkspaceID && v.EnvironmentID == r.EnvironmentID && v.DeviceID == r.DeviceID && v.EnrollmentID == r.EnrollmentID && v.TokenGeneration == r.TokenGeneration && v.CredentialID == r.CredentialID && v.CredentialGeneration == r.CredentialGeneration && v.KeyID == r.KeyID && v.Algorithm == r.Algorithm && v.PublicKey == r.PublicKey && v.ExpiresAt.Equal(r.ExpiresAt)
}
func generation(v uint64) bool { return v > 0 && v <= math.MaxInt64 }
func validToken(v TokenBundle) bool {
	return v.Schema == TokenSchema && validID(v.OrganizationID) && validID(v.WorkspaceID) && validID(v.EnvironmentID) && validID(v.DeviceID) && validID(v.EnrollmentID) && generation(v.TokenGeneration) && generation(v.CredentialGeneration) && wholeTime(v.EnrollmentExpiresAt) && rawURL(v.Locator, 16, true) && rawURL(v.Secret, 32, true)
}
func validRequest(v Request) bool {
	return v.Schema == RequestSchema && validID(v.OrganizationID) && validID(v.WorkspaceID) && validID(v.EnvironmentID) && validID(v.DeviceID) && validID(v.EnrollmentID) && validID(v.CredentialID) && generation(v.TokenGeneration) && generation(v.CredentialGeneration) && keyPattern.MatchString(v.KeyID) && v.Algorithm == "Ed25519" && rawURL(v.PublicKey, 32, true) && wholeTime(v.ExpiresAt)
}
func validReceipt(v Receipt) bool {
	return v.Schema == ReceiptSchema && hashPattern.MatchString(v.RequestSHA256) && validRequest(Request{Schema: RequestSchema, OrganizationID: v.OrganizationID, WorkspaceID: v.WorkspaceID, EnvironmentID: v.EnvironmentID, DeviceID: v.DeviceID, EnrollmentID: v.EnrollmentID, TokenGeneration: v.TokenGeneration, CredentialID: v.CredentialID, CredentialGeneration: v.CredentialGeneration, KeyID: v.KeyID, Algorithm: v.Algorithm, PublicKey: v.PublicKey, ExpiresAt: v.ExpiresAt}) && v.Audience == "runtime-gateway" && microTime(v.IssuedAt) && v.IssuedAt.Before(v.ExpiresAt)
}
func rawURL(text string, size int, nonzero bool) bool {
	raw, e := base64.RawURLEncoding.DecodeString(text)
	if e != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != text {
		return false
	}
	defer clear(raw)
	if nonzero {
		for _, v := range raw {
			if v != 0 {
				return true
			}
		}
		return false
	}
	return true
}

const timestampHeader = "X-Zasp-Gateway-Timestamp"
const digestHeader = "X-Zasp-Content-SHA256"
const signatureHeader = "X-Zasp-Gateway-Signature"

// SignRequest proves submitted-key possession without replacing the enrollment
// bearer. The same canonical context as existing gateway signing is retained.
func SignRequest(req *http.Request, raw []byte, sign func([]byte) ([]byte, error), now time.Time) error {
	r, e := ParseRequest(raw)
	if e != nil || sign == nil || !wholeTime(now) || !validProofRequest(req) {
		return ErrInvalid
	}
	message, e := signingMessage(req, r.CredentialID, now, Digest(raw))
	if e != nil {
		return ErrInvalid
	}
	signature, e := sign(message)
	if e != nil || len(signature) != 64 {
		return ErrInvalid
	}
	public, _ := base64.RawURLEncoding.DecodeString(r.PublicKey)
	if !ed25519.Verify(public, message, signature) {
		return ErrInvalid
	}
	req.Header.Set(timestampHeader, now.Format(time.RFC3339))
	req.Header.Set(digestHeader, Digest(raw))
	req.Header.Set(signatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}
func VerifyRequest(req *http.Request, raw []byte, now time.Time) error {
	r, e := ParseRequest(raw)
	if e != nil || !wholeTime(now) || !validProofRequest(req) {
		return ErrInvalid
	}
	timestamp, ok := oneHeader(req.Header, timestampHeader)
	if !ok {
		return ErrInvalid
	}
	observed, e := time.Parse(time.RFC3339, timestamp)
	if e != nil || !wholeTime(observed) || observed.Format(time.RFC3339) != timestamp || observed.Before(now.Add(-30*time.Second)) || observed.After(now.Add(30*time.Second)) {
		return ErrInvalid
	}
	digest, ok := oneHeader(req.Header, digestHeader)
	if !ok || digest != Digest(raw) {
		return ErrInvalid
	}
	encoded, ok := oneHeader(req.Header, signatureHeader)
	if !ok || !rawURL(encoded, 64, false) {
		return ErrInvalid
	}
	signature, _ := base64.RawURLEncoding.DecodeString(encoded)
	public, _ := base64.RawURLEncoding.DecodeString(r.PublicKey)
	message, e := signingMessage(req, r.CredentialID, observed, digest)
	if e != nil || !ed25519.Verify(public, message, signature) {
		return ErrInvalid
	}
	return nil
}
func validProofRequest(req *http.Request) bool {
	if req == nil || req.URL == nil || req.Method != http.MethodPost || req.URL.Path != EnrollmentPath || req.URL.EscapedPath() != EnrollmentPath || req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Fragment != "" || req.URL.User != nil {
		return false
	}
	auth, ok := oneHeader(req.Header, "Authorization")
	if !ok || !strings.HasPrefix(auth, AuthorizationScheme+" ") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(auth, AuthorizationScheme+" "), ".")
	if len(parts) != 2 || !rawURL(parts[0], 16, true) || !rawURL(parts[1], 32, true) {
		return false
	}
	content, ok := oneHeader(req.Header, "Content-Type")
	if !ok || content != "application/json" {
		return false
	}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "tenant") || strings.Contains(lower, "scope") || strings.Contains(lower, "organization") || strings.Contains(lower, "workspace") || strings.Contains(lower, "environment") || lower == "x-forwarded-authorization" {
			return false
		}
	}
	return true
}
func oneHeader(headers http.Header, name string) (string, bool) {
	var values []string
	for key, v := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, v...)
		}
	}
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}
func signingMessage(req *http.Request, credential string, now time.Time, digest string) ([]byte, error) {
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	if authority == "" || len(authority) > 253 || strings.ContainsAny(authority, "@ \t\r\n\x00") || !validID(credential) || !wholeTime(now) || !hashPattern.MatchString(digest) {
		return nil, ErrInvalid
	}
	return []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", req.Method, authority, EnrollmentPath, credential, now.Format(time.RFC3339), digest}, "\n")), nil
}

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var integerPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var productPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

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
