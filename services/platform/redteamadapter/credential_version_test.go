package redteamadapter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func TestSecretsAuthorizationAssociatesReturnedVersionWithSigningMaterial(t *testing.T) {
	for _, tc := range []struct{ version, secret, want string }{
		{"11111111-1111-4111-8111-111111111111", strings.Repeat("a", 64), "4a39ffdd9ed811c9218d6c0bac81ddfb6d42cb62bafcb63216d974de315ad2e3"},
		{"22222222-2222-4222-8222-222222222222", strings.Repeat("b", 64), "5f65298e70dfd76362bd2652a3cfdea1295d172285625af91ff8da88563fe5cb"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			providerCopy := []byte(tc.secret)
			provider := &secretsAPIStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: providerCopy, VersionId: &tc.version}}
			resolver, err := NewSecretsCredentialResolver(provider, "zasp/red-team/targets", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"input":"bounded canary"}`)
			authorization, err := AuthorizeTargetPayload(context.Background(), resolver, "ref:red-team/target-0001", payload)
			mac := hmac.New(sha256.New, []byte(tc.secret))
			_, _ = mac.Write(payload)
			if err != nil || authorization.CredentialVersionDigest != tc.want || authorization.Signature != "sha256:"+hex.EncodeToString(mac.Sum(nil)) {
				t.Fatalf("authorization failed: %v", err)
			}
			for _, b := range providerCopy {
				if b != 0 {
					t.Fatal("provider bytes retained")
				}
			}
			if provider.output.SecretBinary != nil {
				t.Fatal("provider output retained secret")
			}
		})
	}
}

func TestSecretsCredentialRejectsMissingOrMalformedVersionAndClearsBytes(t *testing.T) {
	for _, version := range []*string{nil, ptrVersion(""), ptrVersion(strings.Repeat("a", 31)), ptrVersion(strings.Repeat("a", 65)), ptrVersion(strings.Repeat("a", 31) + "\n"), ptrVersion(strings.Repeat("a", 31) + " "), ptrVersion(strings.Repeat("a", 31) + "é")} {
		providerCopy := []byte(strings.Repeat("s", 64))
		provider := &secretsAPIStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: providerCopy, VersionId: version}}
		resolver, _ := NewSecretsCredentialResolver(provider, "zasp/red-team/targets", time.Second)
		credential, err := resolver.ResolveTargetCredential(context.Background(), "ref:red-team/target-0001")
		if err != ErrAdapter || credential != nil {
			t.Fatal("unversioned/malformed credential admitted")
		}
		for _, b := range providerCopy {
			if b != 0 {
				t.Fatal("rejected secret bytes retained")
			}
		}
	}
}

func ptrVersion(value string) *string { return &value }

func TestHTTPSObservationRetainsSigningVersionWithoutSendingItToTarget(t *testing.T) {
	const version = "11111111-1111-4111-8111-111111111111"
	const digest = "4a39ffdd9ed811c9218d6c0bac81ddfb6d42cb62bafcb63216d974de315ad2e3"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, values := range r.Header {
			for _, value := range values {
				if strings.Contains(value, version) || strings.Contains(value, digest) {
					t.Error("credential version leaked to target")
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":"Protected response"}`))
	}))
	defer server.Close()
	provider := &secretsAPIStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte(strings.Repeat("s", 64)), VersionId: ptrVersion(version)}}
	resolver, _ := NewSecretsCredentialResolver(provider, "zasp/red-team/targets", time.Second)
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, resolver, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := journalRequestFixture(t)
	_, observation, err := invoker.InvokeObserved(context.Background(), request.Invocation)
	if err != nil || observation.CredentialVersionDigest != digest {
		t.Fatalf("invocation version association missing: %v", err)
	}
	raw, err := json.Marshal(observation)
	if err != nil || strings.Contains(string(raw), digest) || strings.Contains(string(raw), version) || strings.Contains(string(raw), "credential") {
		t.Fatal("internal credential provenance leaked into public observation")
	}
}
