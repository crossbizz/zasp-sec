package aigateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSubjectJWT(t *testing.T, profile WorkloadIdentityProfile, id string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"iss": profile.Issuer, "sub": profile.Subject, "aud": []string{profile.TokenAudience}, "exp": time.Now().Add(30 * time.Minute).Unix(), "jti": id})
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".provider-verifies-signature"
}

func TestPrivateFederationPinsIssuerRoleRegionAndRotation(t *testing.T) {
	for _, provider := range []string{ModeBedrock, ModeVertex} {
		t.Run(provider, func(t *testing.T) {
			profile := WorkloadIdentityProfile{Issuer: "https://issuer.customer.example", Subject: "system:serviceaccount:security:model", TokenAudience: "sts.amazonaws.com", STSPrivateIP: "10.1.2.3"}
			const ref = "secret_ref_planner/org/workspace/environment/model"
			a := DeploymentAttestation{Purpose: PurposeTriage, WorkloadIdentity: &profile}
			region := "us-east-1"
			if provider == ModeBedrock {
				profile.RoleARN = "arn:aws:iam::123456789012:role/security/reader"
				a.Bedrock = &BedrockQualificationProfile{VPCEHost: "vpce-aaa.bedrock-runtime.us-east-1.vpce.amazonaws.com", PrivateIP: "10.1.2.4", Model: modelHaiku, CredentialReference: ref, MaximumNanoCredits: 10}
			} else {
				region = "europe-west4"
				profile.WorkloadProvider = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/customer-models/providers/oidc"
				profile.TokenAudience = profile.WorkloadProvider
				a.Vertex = &VertexQualificationProfile{Location: region, Project: "tenant-stage", PrivateIP: "10.1.2.4", Model: modelGemini, CredentialReference: ref, MaximumNanoCredits: 10}
			}
			if !a.ScopedTo("org", "workspace", "environment") || a.ScopedTo("other", "workspace", "environment") {
				t.Fatal("cloud qualification credential scope")
			}
			file := filepath.Join(t.TempDir(), "projected.jwt")
			setToken := func(value string) {
				if err := os.WriteFile(file, []byte(value+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			token := testSubjectJWT(t, profile, "initial")
			setToken(token)
			bound, err := a.cloudBinding(file)
			if err != nil {
				t.Fatal(err)
			}
			var broker *privateFederation
			switch d := bound.Driver.(type) {
			case *BedrockDriver:
				broker = d.workload
			case *VertexDriver:
				broker = d.workload
			}
			exchanges := 0
			broker.client.Transport = semanticTransport(func(r *http.Request) (*http.Response, error) {
				exchanges++
				if r.Method != http.MethodPost || r.URL.String() != broker.endpoint || r.Header.Get("Authorization") != "" || r.ParseForm() != nil {
					t.Fatal("unexpected exchange")
				}
				payload := ""
				if provider == ModeBedrock {
					if r.URL.Host != "sts.us-east-1.amazonaws.com" || r.Form.Get("RoleArn") != profile.RoleARN || r.Form.Get("WebIdentityToken") != token || r.Form.Get("DurationSeconds") != "900" {
						t.Fatal("unexpected STS role or audience")
					}
					payload = fmt.Sprintf(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/reader/zasp-model</Arn></AssumedRoleUser><Credentials><AccessKeyId>TEST-KEY</AccessKeyId><SecretAccessKey>test-session-signing-material</SecretAccessKey><SessionToken>test-session-token</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().UTC().Add(15*time.Minute).Format(time.RFC3339))
				} else {
					if r.URL.Host != "sts.europe-west4.rep.googleapis.com" || r.Form.Get("audience") != profile.WorkloadProvider || r.Form.Get("subject_token") != token {
						t.Fatal("unexpected WIF provider")
					}
					payload = `{"access_token":"customer-scoped-access-token","expires_in":900,"token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload))}, nil
			})
			sign := func() (*http.Request, error) {
				r, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://regional-model.example/test", strings.NewReader("{}"))
				if err != nil {
					t.Fatal(err)
				}
				return r, broker.sign(r, []byte("{}"))
			}
			r, err := sign()
			if err != nil {
				t.Fatal(err)
			}
			if provider == ModeBedrock && (!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/bedrock/aws4_request") || r.Header.Get("X-Amz-Security-Token") != "test-session-token") {
				t.Fatal("missing scoped SigV4")
			}
			if provider == ModeVertex && r.Header.Get("Authorization") != "Bearer customer-scoped-access-token" {
				t.Fatal("missing scoped access token")
			}
			if _, err := sign(); err != nil || exchanges != 1 {
				t.Fatalf("cached exchange count %d", exchanges)
			}
			token = testSubjectJWT(t, profile, "rotated")
			setToken(token)
			if _, err := sign(); err != nil || exchanges != 2 {
				t.Fatalf("JWT rotation skipped: %d: %v", exchanges, err)
			}
			if next, err := a.cloudBinding(file); err != nil || next.Binding != bound.Binding {
				t.Fatal("rotation changed deployment identity")
			}
			other := profile
			other.Subject = "other-workload"
			setToken(testSubjectJWT(t, other, "wrong-subject"))
			if _, err := sign(); err == nil || exchanges != 2 {
				t.Fatal("wrong subject admitted")
			}
			a.WorkloadIdentity = &other
			changed, err := a.cloudBinding(file)
			if err != nil || changed.Binding.CredentialDigest == bound.Binding.CredentialDigest || changed.Binding.DeploymentDigest == bound.Binding.DeploymentDigest {
				t.Fatal("new authority reused prior qualification")
			}
			other.STSPrivateIP = "8.8.8.8"
			if _, err := a.cloudBinding(file); err == nil {
				t.Fatal("public federation IP accepted")
			}
		})
	}
}
