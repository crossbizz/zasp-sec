// Package gatewayassociationwire defines administrative Device acceptance only.
package gatewayassociationwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const MaximumBytes = 16384
const ChallengeSchema = "agent-device-intent-v1"
const EnvelopeSchema = "agent-device-challenge-envelope-v1"
const AcceptSchema = "agent-device-accept-v1"
const AcceptPath = "/internal/v1/runtime-gateway/agent-device-associations/accept"

var ErrInvalid = errors.New("device association rejected")

type DeviceBinding struct {
	OrganizationID, WorkspaceID, EnvironmentID, DeviceID, CredentialID string
	CredentialGeneration                                               uint64
	PublicKey                                                          string
	ExpiresAt                                                          time.Time
}
type Challenge struct {
	Schema                     string    `json:"schema"`
	ChallengeID                string    `json:"challenge_id"`
	AssociationID              string    `json:"association_id"`
	OrganizationID             string    `json:"organization_id"`
	WorkspaceID                string    `json:"workspace_id"`
	EnvironmentID              string    `json:"environment_id"`
	AgentID                    string    `json:"agent_id"`
	AgentSourceDigest          string    `json:"agent_source_digest"`
	DeviceID                   string    `json:"device_id"`
	ExpectedAssociationVersion uint64    `json:"expected_association_version"`
	Nonce                      string    `json:"nonce"`
	ExpiresAt                  time.Time `json:"expires_at"`
}
type ChallengeEnvelope struct {
	Schema          string `json:"schema"`
	ChallengeWire   string `json:"challenge_wire"`
	ChallengeSHA256 string `json:"challenge_sha256"`
}
type DeviceCredential struct {
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	ExpiresAt            time.Time `json:"expires_at"`
}
type Acceptance struct {
	RequestSHA256 string           `json:"request_sha256"`
	Credential    DeviceCredential `json:"credential"`
	AcceptedAt    time.Time        `json:"accepted_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
}
type AcceptResponse struct {
	ChallengeID     string     `json:"challenge_id"`
	ChallengeSHA256 string     `json:"challenge_sha256"`
	AssociationID   string     `json:"association_id"`
	Acceptance      Acceptance `json:"acceptance"`
	Replayed        bool       `json:"replayed"`
}

func ParseChallengeEnvelope(raw []byte) (ChallengeEnvelope, error) {
	var v ChallengeEnvelope
	if _, e := closedObject(raw, []string{"schema", "challenge_wire", "challenge_sha256"}); e != nil || json.Unmarshal(raw, &v) != nil {
		return v, ErrInvalid
	}
	if _, e := ChallengeFromEnvelope(v); e != nil {
		return ChallengeEnvelope{}, ErrInvalid
	}
	return v, nil
}
func MarshalChallengeEnvelope(v ChallengeEnvelope) ([]byte, error) {
	if _, e := ChallengeFromEnvelope(v); e != nil {
		return nil, ErrInvalid
	}
	return marshalBounded(v)
}
func ParseChallenge(raw []byte) (Challenge, error) {
	var v Challenge
	if len(raw) > 4096 || !utf8.Valid(raw) || json.Unmarshal(raw, &v) != nil || !validChallenge(v) {
		return Challenge{}, ErrInvalid
	}
	canonical, e := json.Marshal(v)
	if e != nil || !bytes.Equal(canonical, raw) {
		return Challenge{}, ErrInvalid
	}
	return v, nil
}
func ChallengeFromEnvelope(v ChallengeEnvelope) (Challenge, error) {
	if v.Schema != EnvelopeSchema || !hashPattern.MatchString(v.ChallengeSHA256) || len(v.ChallengeWire) > 5462 {
		return Challenge{}, ErrInvalid
	}
	raw, e := base64.RawURLEncoding.DecodeString(v.ChallengeWire)
	if e != nil || len(raw) == 0 || len(raw) > 4096 || base64.RawURLEncoding.EncodeToString(raw) != v.ChallengeWire || digest(raw) != v.ChallengeSHA256 {
		return Challenge{}, ErrInvalid
	}
	return ParseChallenge(raw)
}

type acceptRequest struct {
	Schema          string `json:"schema"`
	ChallengeWire   string `json:"challenge_wire"`
	ChallengeSHA256 string `json:"challenge_sha256"`
}

func BuildAcceptRequest(v ChallengeEnvelope) ([]byte, error) {
	if _, e := ChallengeFromEnvelope(v); e != nil {
		return nil, ErrInvalid
	}
	return marshalBounded(acceptRequest{AcceptSchema, v.ChallengeWire, v.ChallengeSHA256})
}
func parseAccept(raw []byte) (ChallengeEnvelope, Challenge, error) {
	var v acceptRequest
	if _, e := closedObject(raw, []string{"schema", "challenge_wire", "challenge_sha256"}); e != nil || json.Unmarshal(raw, &v) != nil || v.Schema != AcceptSchema {
		return ChallengeEnvelope{}, Challenge{}, ErrInvalid
	}
	envelope := ChallengeEnvelope{EnvelopeSchema, v.ChallengeWire, v.ChallengeSHA256}
	challenge, e := ChallengeFromEnvelope(envelope)
	return envelope, challenge, e
}
func ParseAcceptResponse(raw []byte) (AcceptResponse, error) {
	var v AcceptResponse
	fields, e := closedObject(raw, []string{"challenge_id", "challenge_sha256", "association_id", "acceptance", "replayed"})
	if e != nil {
		return v, ErrInvalid
	}
	nested, e := closedObject(fields["acceptance"], []string{"request_sha256", "credential", "accepted_at", "expires_at"})
	if e != nil || !timestampFields(nested, true, "accepted_at", "expires_at") {
		return v, ErrInvalid
	}
	credential, e := closedObject(nested["credential"], []string{"credential_id", "credential_generation", "expires_at"})
	if e != nil || !integerFields(credential, "credential_generation") || !timestampFields(credential, true, "expires_at") {
		return v, ErrInvalid
	}
	if !bytes.Equal(fields["replayed"], []byte("true")) && !bytes.Equal(fields["replayed"], []byte("false")) {
		return v, ErrInvalid
	}
	if json.Unmarshal(raw, &v) != nil || !validResponse(v) {
		return AcceptResponse{}, ErrInvalid
	}
	return v, nil
}
func MarshalAcceptResponse(v AcceptResponse) ([]byte, error) {
	if !validResponse(v) {
		return nil, ErrInvalid
	}
	return marshalBounded(v)
}
func AcceptResponseMatches(v AcceptResponse, raw []byte, binding DeviceBinding, now time.Time) bool {
	envelope, challenge, e := parseAccept(raw)
	if e != nil || !validResponse(v) || !bindingMatches(binding, challenge, now) || v.ChallengeID != challenge.ChallengeID || v.ChallengeSHA256 != envelope.ChallengeSHA256 || v.AssociationID != challenge.AssociationID || v.Acceptance.RequestSHA256 != digest(raw) || v.Acceptance.Credential.CredentialID != binding.CredentialID || v.Acceptance.Credential.CredentialGeneration != binding.CredentialGeneration || !v.Acceptance.Credential.ExpiresAt.Equal(binding.ExpiresAt) || v.Acceptance.AcceptedAt.After(now.Add(30*time.Second)) {
		return false
	}
	expiry := challenge.ExpiresAt
	if binding.ExpiresAt.Before(expiry) {
		expiry = binding.ExpiresAt
	}
	return v.Acceptance.ExpiresAt.Equal(expiry) && expiry.After(now)
}
func validChallenge(v Challenge) bool {
	return v.Schema == ChallengeSchema && validID(v.ChallengeID) && validID(v.AssociationID) && validID(v.OrganizationID) && validID(v.WorkspaceID) && validID(v.EnvironmentID) && validID(v.AgentID) && hashPattern.MatchString(v.AgentSourceDigest) && validID(v.DeviceID) && v.ExpectedAssociationVersion <= math.MaxInt64 && rawURL(v.Nonce, 32, false) && wholeTime(v.ExpiresAt)
}
func validResponse(v AcceptResponse) bool {
	return validID(v.ChallengeID) && validID(v.AssociationID) && hashPattern.MatchString(v.ChallengeSHA256) && hashPattern.MatchString(v.Acceptance.RequestSHA256) && validID(v.Acceptance.Credential.CredentialID) && v.Acceptance.Credential.CredentialGeneration > 0 && v.Acceptance.Credential.CredentialGeneration <= math.MaxInt64 && microTime(v.Acceptance.Credential.ExpiresAt) && microTime(v.Acceptance.AcceptedAt) && microTime(v.Acceptance.ExpiresAt) && v.Acceptance.AcceptedAt.Before(v.Acceptance.ExpiresAt) && !v.Acceptance.ExpiresAt.After(v.Acceptance.Credential.ExpiresAt)
}
func bindingMatches(b DeviceBinding, c Challenge, now time.Time) bool {
	return wholeTime(now) && validID(b.OrganizationID) && validID(b.WorkspaceID) && validID(b.EnvironmentID) && validID(b.DeviceID) && validID(b.CredentialID) && b.CredentialGeneration > 0 && b.CredentialGeneration <= math.MaxInt64 && rawURL(b.PublicKey, 32, true) && microTime(b.ExpiresAt) && b.ExpiresAt.After(now) && c.ExpiresAt.After(now) && b.OrganizationID == c.OrganizationID && b.WorkspaceID == c.WorkspaceID && b.EnvironmentID == c.EnvironmentID && b.DeviceID == c.DeviceID
}
func SignAcceptRequest(req *http.Request, raw []byte, binding DeviceBinding, sign func([]byte) ([]byte, error), now time.Time) error {
	_, challenge, e := parseAccept(raw)
	if e != nil || !bindingMatches(binding, challenge, now) || sign == nil || req == nil || req.URL == nil || req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Host == "" || req.URL.User != nil || req.URL.Path != AcceptPath || req.URL.RawPath != "" || req.URL.EscapedPath() != AcceptPath || req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return ErrInvalid
	}
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	if authority != req.URL.Host || len(authority) > 253 || strings.ContainsAny(authority, "@ \t\r\n\x00") {
		return ErrInvalid
	}
	if req.Header.Get("Content-Type") != "application/json" {
		return ErrInvalid
	}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "tenant") || strings.Contains(lower, "scope") || strings.Contains(lower, "organization") || strings.Contains(lower, "workspace") || strings.Contains(lower, "environment") || lower == "x-forwarded-authorization" {
			return ErrInvalid
		}
	}
	sum := digest(raw)
	message := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", http.MethodPost, authority, AcceptPath, binding.CredentialID, now.Format(time.RFC3339), sum}, "\n"))
	signature, e := sign(message)
	public, _ := base64.RawURLEncoding.DecodeString(binding.PublicKey)
	if e != nil || len(signature) != 64 || !ed25519.Verify(public, message, signature) {
		return ErrInvalid
	}
	req.Header.Set("Authorization", "ZaspGatewayV1 "+binding.CredentialID)
	req.Header.Set("X-Zasp-Gateway-Timestamp", now.Format(time.RFC3339))
	req.Header.Set("X-Zasp-Content-SHA256", sum)
	req.Header.Set("X-Zasp-Gateway-Signature", base64.RawURLEncoding.EncodeToString(signature))
	return nil
}
func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func rawURL(v string, size int, nonzero bool) bool {
	raw, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != v {
		return false
	}
	if nonzero {
		for _, b := range raw {
			if b != 0 {
				return true
			}
		}
		return false
	}
	return true
}

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
