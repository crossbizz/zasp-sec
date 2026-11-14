package gcpdiscovery

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// How the product obtains a Google access token for the customer's read-only
// service account. Two ways, both ending in a token that lives for at most
// one hour and is never stored:
//
// Workload identity federation (preferred, nothing is stored anywhere). The
// product runs on AWS. It signs an AWS GetCallerIdentity request with its own
// role credentials, hands the signed request to Google's Security Token
// Service, which verifies it against the workload identity pool provider the
// customer created, and then asks the IAM Credentials API for an access
// token of the service account the customer lets that AWS role impersonate.
//
// DOCUMENTED: https://sts.googleapis.com/$discovery/rest?version=v1
// (method sts.token, GoogleIdentityStsV1ExchangeTokenRequest: the subject
// token "for AWS ... must be a serialized GetCallerIdentity token", URL-encoded
// JSON of url, method and headers, with x-goog-cloud-target-resource naming
// the provider; subject_token_type urn:ietf:params:aws:token-type:aws4_request).
// DOCUMENTED: https://iamcredentials.googleapis.com/$discovery/rest?version=v1
// (projects.serviceAccounts.generateAccessToken: scope, lifetime;
// accessToken, expireTime).
//
// A service account key (for a customer that cannot federate). The key file
// is held outside the product database, by reference; the product signs a
// JWT with it and exchanges the JWT at the token endpoint the key file names.
// UNVERIFIED: the JWT bearer grant (RFC 7523) and the key file members
// (type, client_email, private_key, token_uri) are from memory; Google's
// page for it (developers.google.com/identity/protocols/oauth2/service-account)
// was not reachable when this was written.

const (
	// Every Google API read here accepts this scope, and most accept no
	// narrower one. What the token may do is bounded by the read-only IAM
	// roles of the service account, not by the scope.
	// DOCUMENTED: the "scopes" of each method in the discovery documents
	// named in api.go.
	gcpCloudPlatformScope  = "https://www.googleapis.com/auth/cloud-platform"
	gcpSTSTokenURL         = "https://sts.googleapis.com/v1/token"
	gcpIAMCredentialsHost  = "iamcredentials.googleapis.com"
	gcpKeyTokenURL         = "https://oauth2.googleapis.com/token"
	gcpTokenLifetime       = "3600s"
	gcpMaximumTokenBytes   = 64 << 10
	gcpMaximumKeyFileBytes = 16 << 10
)

var (
	gcpServiceAccountEmailPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	gcpAudiencePattern            = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[1-9][0-9]{0,18}/locations/global/workloadIdentityPools/[a-z][a-z0-9-]{2,30}[a-z0-9]/providers/[a-z][a-z0-9-]{2,30}[a-z0-9]$`)
	gcpFederationReferencePattern = regexp.MustCompile(`^ref:gcp/workload-identity/([a-z][a-z0-9-]{4,28}[a-z0-9])/([a-z][a-z0-9-]{4,28}[a-z0-9])$`)
	gcpKeyReferencePattern        = regexp.MustCompile(`^ref:gcp/service-account-key/[a-z0-9][a-z0-9._-]{7,127}$`)
	gcpAWSRegionPattern           = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$`)
)

// FederationServiceAccount returns the service account a workload identity
// reference names: ref:gcp/workload-identity/<project>/<name> is
// <name>@<project>.iam.gserviceaccount.com.
func FederationServiceAccount(reference string) (string, bool) {
	match := gcpFederationReferencePattern.FindStringSubmatch(reference)
	if len(match) != 3 {
		return "", false
	}
	return match[2] + "@" + match[1] + ".iam.gserviceaccount.com", true
}

// ValidKeyReference reports whether reference names a stored service account key.
func ValidKeyReference(reference string) bool { return gcpKeyReferencePattern.MatchString(reference) }

// ValidAudience reports whether audience names a workload identity pool provider.
func ValidAudience(audience string) bool { return gcpAudiencePattern.MatchString(audience) }

// ValidScope reports whether scope is organizations/<number>,
// folders/<number> or projects/<project id>.
func ValidScope(scope string) bool { return gcpScopePattern.MatchString(scope) }

// AccessToken is a short-lived Google access token. Destroy clears it.
type AccessToken struct {
	Token     []byte
	ExpiresAt time.Time
}

func (token *AccessToken) Destroy() {
	if token != nil {
		clear(token.Token)
		*token = AccessToken{}
	}
}

type TokenExchangerConfig struct {
	// HTTP is a bounded client (no redirects). Required.
	HTTP *http.Client
	// AWSCredentials are the product's own AWS role credentials and
	// AWSRegion the region of the AWS STS endpoint the signed request names.
	// Both are needed only for workload identity federation.
	AWSCredentials aws.CredentialsProvider
	AWSRegion      string
	Clock          func() time.Time
}

// TokenExchanger obtains access tokens. It holds no token and no key.
type TokenExchanger struct {
	config TokenExchangerConfig
}

func NewTokenExchanger(config TokenExchangerConfig) (*TokenExchanger, error) {
	if config.HTTP == nil || config.Clock == nil || config.AWSCredentials != nil && !gcpAWSRegionPattern.MatchString(config.AWSRegion) {
		return nil, ErrInvalid
	}
	return &TokenExchanger{config: config}, nil
}

// FederatedToken exchanges the product's AWS identity for an access token of
// serviceAccount through the workload identity pool provider audience names.
func (exchanger *TokenExchanger) FederatedToken(ctx context.Context, audience, serviceAccount string) (AccessToken, error) {
	if exchanger == nil || ctx == nil || ctx.Err() != nil || exchanger.config.AWSCredentials == nil || !gcpAudiencePattern.MatchString(audience) || !gcpServiceAccountEmailPattern.MatchString(serviceAccount) {
		return AccessToken{}, ErrInvalid
	}
	subjectToken, err := exchanger.awsSubjectToken(ctx, audience)
	if err != nil {
		return AccessToken{}, err
	}
	var federated struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	exchange, _ := json.Marshal(map[string]string{
		"audience": audience, "grantType": "urn:ietf:params:oauth:grant-type:token-exchange", "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"scope": gcpCloudPlatformScope, "subjectToken": subjectToken, "subjectTokenType": "urn:ietf:params:aws:token-type:aws4_request",
	})
	if !exchanger.postJSON(ctx, gcpSTSTokenURL, "", "application/json", exchange, &federated) || !strings.EqualFold(federated.TokenType, "bearer") || !validAccessToken([]byte(federated.AccessToken)) {
		federated.AccessToken = ""
		return AccessToken{}, ErrProvider
	}
	var impersonated struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	body, _ := json.Marshal(map[string]any{"scope": []string{gcpCloudPlatformScope}, "lifetime": gcpTokenLifetime})
	ok := exchanger.postJSON(ctx, "https://"+gcpIAMCredentialsHost+"/v1/projects/-/serviceAccounts/"+url.PathEscape(serviceAccount)+":generateAccessToken", federated.AccessToken, "application/json", body, &impersonated)
	federated.AccessToken = ""
	expiresAt, timeErr := time.Parse(time.RFC3339, impersonated.ExpireTime)
	now := exchanger.config.Clock()
	if !ok || timeErr != nil || !validAccessToken([]byte(impersonated.AccessToken)) || !expiresAt.After(now.Add(time.Minute)) || expiresAt.After(now.Add(13*time.Hour)) {
		impersonated.AccessToken = ""
		return AccessToken{}, ErrProvider
	}
	result := AccessToken{Token: []byte(impersonated.AccessToken), ExpiresAt: expiresAt.UTC()}
	impersonated.AccessToken = ""
	return result, nil
}

// awsSubjectToken signs a GetCallerIdentity request with the product's AWS
// credentials and serializes it the way Google's token service reads it. The
// request is never sent by the product: Google sends it to AWS to learn who
// signed it.
func (exchanger *TokenExchanger) awsSubjectToken(ctx context.Context, audience string) (string, error) {
	credentials, err := exchanger.config.AWSCredentials.Retrieve(ctx)
	if err != nil || !credentials.HasKeys() {
		return "", ErrProvider
	}
	host := "sts." + exchanger.config.AWSRegion + ".amazonaws.com"
	endpoint := "https://" + host + "/?Action=GetCallerIdentity&Version=2011-06-15"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", ErrInvalid
	}
	request.Header.Set("x-goog-cloud-target-resource", audience)
	emptyPayload := sha256.Sum256(nil)
	if err := v4.NewSigner().SignHTTP(ctx, credentials, request, hex.EncodeToString(emptyPayload[:]), "sts", exchanger.config.AWSRegion, exchanger.config.Clock()); err != nil {
		return "", ErrProvider
	}
	type header struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	headers := []header{{"Authorization", request.Header.Get("Authorization")}, {"host", host}, {"x-amz-date", request.Header.Get("X-Amz-Date")}}
	if sessionToken := request.Header.Get("X-Amz-Security-Token"); sessionToken != "" {
		headers = append(headers, header{"x-amz-security-token", sessionToken})
	}
	headers = append(headers, header{"x-goog-cloud-target-resource", audience})
	serialized, err := json.Marshal(struct {
		Headers []header `json:"headers"`
		Method  string   `json:"method"`
		URL     string   `json:"url"`
	}{headers, http.MethodPost, endpoint})
	if err != nil || headers[0].Value == "" || headers[2].Value == "" {
		return "", ErrProvider
	}
	return url.QueryEscape(string(serialized)), nil
}

// KeyToken exchanges a service account key file for an access token. The key
// is parsed, used for one signature and cleared; the caller clears keyFile.
func (exchanger *TokenExchanger) KeyToken(ctx context.Context, keyFile []byte) (AccessToken, error) {
	if exchanger == nil || ctx == nil || ctx.Err() != nil || len(keyFile) < 64 || len(keyFile) > gcpMaximumKeyFileBytes {
		return AccessToken{}, ErrInvalid
	}
	var key struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if json.Unmarshal(keyFile, &key) != nil || key.Type != "service_account" || !gcpServiceAccountEmailPattern.MatchString(key.ClientEmail) || key.TokenURI != gcpKeyTokenURL {
		key.PrivateKey = ""
		return AccessToken{}, ErrInvalid
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	key.PrivateKey = ""
	if block == nil {
		return AccessToken{}, ErrInvalid
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	private, isRSA := parsed.(*rsa.PrivateKey)
	if err != nil || !isRSA || private.N.BitLen() < 2048 {
		return AccessToken{}, ErrInvalid
	}
	now := exchanger.config.Clock()
	encode := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]any{"iss": key.ClientEmail, "scope": gcpCloudPlatformScope, "aud": gcpKeyTokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	signingInput := encode([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		return AccessToken{}, ErrInvalid
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signingInput + "." + encode(signature)}}
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if !exchanger.postJSON(ctx, gcpKeyTokenURL, "", "application/x-www-form-urlencoded", []byte(form.Encode()), &response) || !strings.EqualFold(response.TokenType, "bearer") || response.ExpiresIn < 120 || response.ExpiresIn > 43_200 || !validAccessToken([]byte(response.AccessToken)) {
		response.AccessToken = ""
		return AccessToken{}, ErrProvider
	}
	result := AccessToken{Token: []byte(response.AccessToken), ExpiresAt: now.Add(time.Duration(response.ExpiresIn) * time.Second).UTC()}
	response.AccessToken = ""
	return result, nil
}

// postJSON posts one body and decodes one JSON document of a 200 response.
// A provider's error body is read only to bound it; it is never returned.
func (exchanger *TokenExchanger) postJSON(ctx context.Context, endpoint, bearer, contentType string, body []byte, destination any) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", contentType)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := exchanger.config.HTTP.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return false
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, gcpMaximumTokenBytes+1))
	defer clear(payload)
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || readErr != nil || len(payload) < 2 || len(payload) > gcpMaximumTokenBytes || mediaErr != nil || mediaType != "application/json" {
		return false
	}
	return json.Unmarshal(payload, destination) == nil
}

// validAccessToken admits 16 to 8192 visible ASCII bytes without a quote or
// a backslash, so a token is written into the collector's JSON credential
// without escaping and cannot change its structure.
func validAccessToken(value []byte) bool {
	if len(value) < 16 || len(value) > 8192 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

// EncodeCredential writes the credential the collector reads:
// {"access_token":"…"}.
func EncodeCredential(token []byte) ([]byte, bool) {
	if !validAccessToken(token) {
		return nil, false
	}
	encoded := make([]byte, 0, len(token)+20)
	encoded = append(encoded, gcpCredentialPrefix...)
	encoded = append(encoded, token...)
	return append(encoded, gcpCredentialSuffix...), true
}

// ValidCredential reports whether value is exactly what EncodeCredential writes.
func ValidCredential(value []byte) bool {
	_, ok := decodeCredential(value)
	return ok
}

const gcpCredentialPrefix, gcpCredentialSuffix = `{"access_token":"`, `"}`

// decodeCredential returns the token as a view into the caller's buffer.
func decodeCredential(value []byte) ([]byte, bool) {
	if len(value) < len(gcpCredentialPrefix)+len(gcpCredentialSuffix)+16 || !bytes.HasPrefix(value, []byte(gcpCredentialPrefix)) || !bytes.HasSuffix(value, []byte(gcpCredentialSuffix)) {
		return nil, false
	}
	token := value[len(gcpCredentialPrefix) : len(value)-len(gcpCredentialSuffix)]
	return token, validAccessToken(token)
}
