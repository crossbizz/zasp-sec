package gatewayenrollmentwire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"
)

// CurrentAuthority is the original device authority DTO. It is neither an
// enrollment receipt nor an independently signed server response.
type CurrentAuthority struct {
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	DeviceVersion        uint64    `json:"device_version"`
	ReplayFloor          uint64    `json:"replay_floor"`
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	Audience             string    `json:"audience"`
	ExpiresAt            time.Time `json:"expires_at"`
}

var authorityKeys = []string{"organization_id", "workspace_id", "environment_id", "device_id", "device_version", "replay_floor", "credential_id", "credential_generation", "key_id", "algorithm", "public_key", "audience", "expires_at"}

func ParseCurrentAuthority(raw []byte) (CurrentAuthority, error) {
	var value CurrentAuthority
	fields, err := closedObject(raw, authorityKeys)
	if err != nil || !integerFields(fields, "device_version", "credential_generation") || !timestampFields(fields, true, "expires_at") {
		return value, ErrInvalid
	}
	floor := string(fields["replay_floor"])
	if floor != "0" && !integerPattern.MatchString(floor) {
		return value, ErrInvalid
	}
	if json.Unmarshal(raw, &value) != nil || !validCurrentAuthority(value) {
		return CurrentAuthority{}, ErrInvalid
	}
	return value, nil
}
func MarshalCurrentAuthority(value CurrentAuthority) ([]byte, error) {
	if !validCurrentAuthority(value) {
		return nil, ErrInvalid
	}
	return marshalBounded(value)
}
func validCurrentAuthority(value CurrentAuthority) bool {
	return validID(value.OrganizationID) && validID(value.WorkspaceID) && validID(value.EnvironmentID) && validID(value.DeviceID) && validID(value.CredentialID) && generation(value.DeviceVersion) && value.ReplayFloor <= math.MaxInt64 && generation(value.CredentialGeneration) && keyPattern.MatchString(value.KeyID) && value.Algorithm == "Ed25519" && rawURL(value.PublicKey, ed25519.PublicKeySize, true) && value.Audience == "runtime-gateway" && microTime(value.ExpiresAt)
}
func CurrentAuthorityMatchesRequest(value CurrentAuthority, request Request, now time.Time) bool {
	return validCurrentAuthority(value) && validRequest(request) && wholeTime(now) && value.ExpiresAt.After(now) && value.OrganizationID == request.OrganizationID && value.WorkspaceID == request.WorkspaceID && value.EnvironmentID == request.EnvironmentID && value.DeviceID == request.DeviceID && value.CredentialID == request.CredentialID && value.CredentialGeneration == request.CredentialGeneration && value.KeyID == request.KeyID && value.Algorithm == request.Algorithm && value.PublicKey == request.PublicKey && value.ExpiresAt.Equal(request.ExpiresAt)
}

// SignAuthorityRequest signs the existing empty-body device Authority GET. The
// retained credential is the identity; no enrollment bearer or new identity is
// introduced. Standard certificate verification remains the HTTP client's job.
func SignAuthorityRequest(request *http.Request, value Request, sign func([]byte) ([]byte, error), now time.Time) error {
	const path = "/internal/v1/runtime-gateway/authority"
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil || request.URL.Path != path || request.URL.EscapedPath() != path || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" || request.URL.Opaque != "" || request.Body != nil && request.Body != http.NoBody || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || !validRequest(value) || !wholeTime(now) || sign == nil {
		return ErrInvalid
	}
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	if authority != request.URL.Host || len(authority) > 253 || strings.ContainsAny(authority, "@ \t\r\n\x00") {
		return ErrInvalid
	}
	for name := range request.Header {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "tenant") || strings.Contains(lower, "scope") || strings.Contains(lower, "organization") || strings.Contains(lower, "workspace") || strings.Contains(lower, "environment") || lower == "x-forwarded-authorization" {
			return ErrInvalid
		}
	}
	digest := Digest(nil)
	message := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", http.MethodGet, authority, path, value.CredentialID, now.Format(time.RFC3339), digest}, "\n"))
	signature, err := sign(message)
	public, decodeErr := base64.RawURLEncoding.DecodeString(value.PublicKey)
	if err != nil || decodeErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
		return ErrInvalid
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Authorization", "ZaspGatewayV1 "+value.CredentialID)
	request.Header.Set(timestampHeader, now.Format(time.RFC3339))
	request.Header.Set(digestHeader, digest)
	request.Header.Set(signatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}
