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
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type gcpTokenTransport func(*http.Request) (int, string)

func (transport gcpTokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	status, body := transport(request)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json; charset=UTF-8"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

const (
	gcpTestAudience       = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/zasp-pool/providers/zasp-aws"
	gcpTestServiceAccount = "zasp-reader@acme-security.iam.gserviceaccount.com"
)

// The federated exchange hands Google a signed AWS GetCallerIdentity request
// in the documented serialization, then asks for a token of the service
// account with the federated token. Neither AWS secret leaves the signature.
func TestFederatedTokenSignsACallerIdentityRequestAndImpersonatesTheServiceAccount(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.November, 14, 9, 0, 0, 0, time.UTC)
	awsSecret, awsSession := "aws-secret-"+strings.Repeat("s", 30), "aws-session-"+strings.Repeat("t", 40)
	// Built from parts: no literal here has the shape of a real key id.
	awsKeyID := "ASIA" + "TEST" + "ACCESSKEY0001"
	federatedToken, finalToken := "federated-"+strings.Repeat("f", 40), "final-token-"+strings.Repeat("g", 40)
	var subject struct {
		Headers []struct{ Key, Value string }
		Method  string
		URL     string
	}
	transport := gcpTokenTransport(func(request *http.Request) (int, string) {
		body, _ := io.ReadAll(request.Body)
		if bytes.Contains(body, []byte(awsSecret)) {
			t.Error("the AWS secret key was sent")
		}
		switch request.URL.String() {
		case "https://sts.googleapis.com/v1/token":
			var exchange map[string]string
			if json.Unmarshal(body, &exchange) != nil || exchange["audience"] != gcpTestAudience || exchange["grantType"] != "urn:ietf:params:oauth:grant-type:token-exchange" ||
				exchange["subjectTokenType"] != "urn:ietf:params:aws:token-type:aws4_request" || exchange["requestedTokenType"] != "urn:ietf:params:oauth:token-type:access_token" || exchange["scope"] != gcpCloudPlatformScope {
				t.Errorf("exchange = %v", exchange)
			}
			decoded, err := url.QueryUnescape(exchange["subjectToken"])
			if err != nil || json.Unmarshal([]byte(decoded), &subject) != nil {
				t.Errorf("subject token is not URL-encoded JSON: %v", err)
			}
			return 200, `{"access_token":"` + federatedToken + `","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`
		case "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(gcpTestServiceAccount) + ":generateAccessToken":
			var generate struct {
				Scope    []string `json:"scope"`
				Lifetime string   `json:"lifetime"`
			}
			if request.Header.Get("Authorization") != "Bearer "+federatedToken || json.Unmarshal(body, &generate) != nil || len(generate.Scope) != 1 || generate.Scope[0] != gcpCloudPlatformScope || generate.Lifetime != "3600s" {
				t.Errorf("generateAccessToken request = %s", body)
			}
			return 200, `{"accessToken":"` + finalToken + `","expireTime":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`
		}
		t.Errorf("unexpected call %s", request.URL)
		return 500, `{}`
	})
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: awsKeyID, SecretAccessKey: awsSecret, SessionToken: awsSession, CanExpire: true, Expires: now.Add(time.Hour)}, nil
	})
	exchanger, err := NewTokenExchanger(TokenExchangerConfig{HTTP: &http.Client{Transport: transport}, AWSCredentials: credentials, AWSRegion: "us-east-1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	token, err := exchanger.FederatedToken(context.Background(), gcpTestAudience, gcpTestServiceAccount)
	if err != nil || string(token.Token) != finalToken || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("token = %q, %v, %v", token.Token, token.ExpiresAt, err)
	}
	headers := map[string]string{}
	for _, header := range subject.Headers {
		headers[header.Key] = header.Value
	}
	authorization := headers["Authorization"]
	if subject.Method != "POST" || subject.URL != "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" || headers["host"] != "sts.us-east-1.amazonaws.com" || headers["x-amz-date"] != "20261114T090000Z" ||
		headers["x-amz-security-token"] != awsSession || headers["x-goog-cloud-target-resource"] != gcpTestAudience ||
		!strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 Credential="+awsKeyID+"/20261114/us-east-1/sts/aws4_request") || !strings.Contains(authorization, "x-goog-cloud-target-resource") {
		t.Fatalf("subject token = %#v", subject)
	}
	token.Destroy()
	if token.Token != nil {
		t.Fatal("the token was not cleared")
	}
	for _, refused := range [][2]string{{"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p", gcpTestServiceAccount}, {gcpTestAudience, "someone@example.com"}} {
		if _, err := exchanger.FederatedToken(context.Background(), refused[0], refused[1]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%v = %v", refused, err)
		}
	}
}

// A key file is used for one RS256 signature the provider can verify with
// the key's public half; the private key is never sent.
func TestKeyTokenSignsAJWTBearerAssertion(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.November, 14, 9, 0, 0, 0, time.UTC)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyFile, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": gcpTestServiceAccount, "private_key": string(keyPEM), "token_uri": "https://oauth2.googleapis.com/token", "private_key_id": "k1"})
	issued := "key-token-" + strings.Repeat("k", 40)
	transport := gcpTokenTransport(func(request *http.Request) (int, string) {
		body, _ := io.ReadAll(request.Body)
		form, _ := url.ParseQuery(string(body))
		parts := strings.Split(form.Get("assertion"), ".")
		if request.URL.String() != "https://oauth2.googleapis.com/token" || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 || bytes.Contains(body, der[:64]) {
			t.Errorf("token request = %s", body)
			return 400, `{}`
		}
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		if rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature) != nil || json.Unmarshal(claimsJSON, &claims) != nil || claims["iss"] != gcpTestServiceAccount || claims["aud"] != "https://oauth2.googleapis.com/token" || claims["scope"] != gcpCloudPlatformScope || claims["exp"].(float64)-claims["iat"].(float64) != 3600 {
			t.Errorf("assertion claims = %s", claimsJSON)
		}
		return 200, `{"access_token":"` + issued + `","token_type":"Bearer","expires_in":3599}`
	})
	exchanger, err := NewTokenExchanger(TokenExchangerConfig{HTTP: &http.Client{Transport: transport}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	token, err := exchanger.KeyToken(context.Background(), keyFile)
	if err != nil || string(token.Token) != issued || !token.ExpiresAt.Equal(now.Add(3599*time.Second)) {
		t.Fatalf("token = %q, %v", token.Token, err)
	}
	// A key that names another token endpoint, or is not a service account
	// key, is refused before anything is sent.
	for _, mutate := range []func(map[string]string){
		func(key map[string]string) { key["token_uri"] = "https://attacker.example/token" },
		func(key map[string]string) { key["type"] = "authorized_user" },
		func(key map[string]string) { key["private_key"] = "not a key" },
	} {
		var key map[string]string
		_ = json.Unmarshal(keyFile, &key)
		mutate(key)
		mutated, _ := json.Marshal(key)
		if _, err := exchanger.KeyToken(context.Background(), mutated); !errors.Is(err, ErrInvalid) {
			t.Fatalf("mutated key = %v", err)
		}
	}
	// Without AWS credentials there is no federation.
	if _, err := exchanger.FederatedToken(context.Background(), gcpTestAudience, gcpTestServiceAccount); !errors.Is(err, ErrInvalid) {
		t.Fatalf("federation without AWS credentials = %v", err)
	}
}

func TestReferencesAndCredentialEncoding(t *testing.T) {
	t.Parallel()
	if email, ok := FederationServiceAccount("ref:gcp/workload-identity/acme-security/zasp-reader"); !ok || email != gcpTestServiceAccount {
		t.Fatalf("service account = %q, %v", email, ok)
	}
	for _, reference := range []string{"ref:gcp/workload-identity/acme-security", "ref:gcp/service-account-key/customer-0001", "ref:aws/workload-identity/acme-security/zasp-reader", "ref:gcp/workload-identity/Acme/zasp-reader"} {
		if _, ok := FederationServiceAccount(reference); ok {
			t.Fatalf("%q accepted", reference)
		}
	}
	if !ValidKeyReference("ref:gcp/service-account-key/customer-0001") || ValidKeyReference("ref:gcp/service-account-key/x") || !ValidAudience(gcpTestAudience) || ValidAudience("https:"+gcpTestAudience) ||
		!ValidScope("folders/42") || !ValidScope("projects/alpha-prod") || ValidScope("projects/Alpha") || ValidScope("organizations/012") {
		t.Fatal("reference grammar")
	}
	encoded, ok := EncodeCredential([]byte(gcpTestToken))
	if !ok || string(encoded) != `{"access_token":"`+gcpTestToken+`"}` || !ValidCredential(encoded) || ValidCredential([]byte(`{"access_token":"a\"b-0123456789abcdef"}`)) {
		t.Fatalf("credential = %s", encoded)
	}
	if _, ok := EncodeCredential([]byte("has space in token value")); ok {
		t.Fatal("a token with a space was encoded")
	}
}
