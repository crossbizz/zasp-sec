package gatewayassociationwire

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var currentDeviceKeyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)

// SignCurrentDeviceAuthorityRequest uses an existing Device credential and its
// retained key without constructing enrollment lineage. KeyID is only a local
// syntax constraint: the original signature context does not contain keyID.
// The caller must compare the actual current Authority response with all local
// credential/key facts before admitting any subsequent operation.
func SignCurrentDeviceAuthorityRequest(request *http.Request, credentialID, keyID, publicKey string, sign func([]byte) ([]byte, error), now time.Time) error {
	const path = "/internal/v1/runtime-gateway/authority"
	if request == nil || request.URL == nil || request.Context().Err() != nil || request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil || request.URL.Path != path || request.URL.EscapedPath() != path || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" || request.URL.RawFragment != "" || request.URL.Opaque != "" || request.Body != nil && request.Body != http.NoBody || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || !validID(credentialID) || !currentDeviceKeyIDPattern.MatchString(keyID) || !rawURL(publicKey, ed25519.PublicKeySize, true) || !wholeTime(now) || sign == nil {
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
	bodyDigest := digest(nil)
	canonical := []byte(strings.Join([]string{"zasp-runtime-gateway-request-v1", http.MethodGet, authority, path, credentialID, now.Format(time.RFC3339), bodyDigest}, "\n"))
	signature, err := sign(canonical)
	public, decodeErr := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || decodeErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), canonical, signature) || request.Context().Err() != nil {
		return ErrInvalid
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Authorization", "ZaspGatewayV1 "+credentialID)
	request.Header.Set("X-Zasp-Gateway-Timestamp", now.Format(time.RFC3339))
	request.Header.Set("X-Zasp-Content-SHA256", bodyDigest)
	request.Header.Set("X-Zasp-Gateway-Signature", base64.RawURLEncoding.EncodeToString(signature))
	return nil
}
