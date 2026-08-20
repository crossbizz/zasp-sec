package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const testDiscoveryCACertificatePEM = `-----BEGIN CERTIFICATE-----
MIICvjCCAaYCCQCa7cxZ6Y3MiTANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZ6
YXNwLWRpc2NvdmVyeS10ZXN0LWNhMB4XDTI2MDgyMDA5MTQxNloXDTM2MDgxNzA5
MTQxNlowITEfMB0GA1UEAwwWemFzcC1kaXNjb3ZlcnktdGVzdC1jYTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANh6kp693Js5s/ywepHGGfE7RTk1pt1w
PkPnqrnKa4t1WXrvITg1qedB3L3RvvXBPXYGV+8VOba4rmA7utEO0sHcbzfINGYq
wkdpOtuh+RwLmCNV23ON+snR9NbKtqeFB1Res/AkWvynIFotV5dw8Hx2AgMzBjy8
Hcffg28rN0C4GwzevV/kZ/rJFKsaK2NQR13khiTdVsbxoVPyI059T0iJ1/C4HthH
hL30/vtPdCQrAWmUri/+v/mCVbNaObBSQSx+1IlWWyXcngJyIaV5UF7r0gJtmPxq
dy9QJDcg129UYtEI1nrDFOQarinotqi3Piul6KEEWpCfV8XPAejRPlkCAwEAATAN
BgkqhkiG9w0BAQsFAAOCAQEAMH7DRwGWSGQsgYZ60GHATgxtjMgyPdj25gdgAs4l
mpWnq1ZPjbip6qTKsieLLTwnbkTI2wH4TPq70ap9yopJVc0cmytAWzRT2IaECDp7
ZPrYLLzuZ9aco0pdECZZObO036RLWnPGWTr8uUnLiS6SCJKDYSBoltxHwYOxlGlC
MOcVZWwReBWmZPdqvXbWVJbcf1XnCYnaMOh57My+6HO5n/HTRFR6eGTx6gK9IL25
c+ycq4+Zi7euxAKVlGLmEVTLX9y09AQq9YOk8A8SWuYhYV+CcOduXy9k15O0OJIJ
bVTUV5LTcltIKutavvUDzuCeBB13DHmiz84JpOusjUjBQQ==
-----END CERTIFICATE-----
`

type discoverySecretReaderStub struct {
	mu     sync.Mutex
	values map[string][]byte
	calls  []string
	err    error
}

func (stub *discoverySecretReaderStub) ResolveDiscoverySecret(_ context.Context, reference string) ([]byte, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls = append(stub.calls, reference)
	if stub.err != nil {
		return nil, stub.err
	}
	value, ok := stub.values[reference]
	if !ok {
		return nil, errDiscoveryCredentialUnavailable
	}
	return bytes.Clone(value), nil
}

type discoveryAssumeRoleStub struct {
	mu    sync.Mutex
	input *sts.AssumeRoleInput
	out   *sts.AssumeRoleOutput
	err   error
}

func (stub *discoveryAssumeRoleStub) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	copyOfInput := *input
	stub.input = &copyOfInput
	return stub.out, stub.err
}

type discoveryGitHubMintStub struct {
	mu             sync.Mutex
	appID          string
	installationID int64
	key            []byte
	result         discoveryGitHubInstallationToken
	err            error
}

func (stub *discoveryGitHubMintStub) MintDiscoveryInstallationToken(_ context.Context, appID string, privateKey []byte, installationID int64) (discoveryGitHubInstallationToken, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.appID = appID
	stub.installationID = installationID
	stub.key = bytes.Clone(privateKey)
	return cloneDiscoveryGitHubInstallationToken(stub.result), stub.err
}

type discoveryOktaExchangeStub struct {
	mu           sync.Mutex
	issuer       string
	clientID     string
	clientSecret []byte
	refreshToken []byte
	result       discoveryOktaAccessToken
	err          error
}

func (stub *discoveryOktaExchangeStub) ExchangeDiscoveryRefreshToken(_ context.Context, issuer, clientID string, clientSecret, refreshToken []byte) (discoveryOktaAccessToken, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.issuer = issuer
	stub.clientID = clientID
	stub.clientSecret = bytes.Clone(clientSecret)
	stub.refreshToken = bytes.Clone(refreshToken)
	return cloneDiscoveryOktaAccessToken(stub.result), stub.err
}

func TestProductionDiscoveryCredentialsResolveExactProviderMaterial(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	caBundle := []byte(testDiscoveryCACertificatePEM)
	tests := []struct {
		name       string
		input      apiserver.ExecutionJobInput
		secrets    map[string][]byte
		wantCalls  []string
		wantFields discoveryCredentialEnvelope
	}{
		{
			name:       "aws",
			input:      discoveryCredentialInput(scope, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/external-id/customer-0001", collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`, now),
			secrets:    map[string][]byte{"ref:aws/external-id/customer-0001": []byte("external-id-customer-0001")},
			wantCalls:  []string{"ref:aws/external-id/customer-0001"},
			wantFields: discoveryCredentialEnvelope{Provider: collection.ProviderAWS, SubjectKind: "aws_account", SubjectID: "123456789012", Region: "us-east-1", AccessKeyID: []byte("ASIAEXAMPLE000001"), SecretAccessKey: []byte(strings.Repeat("s", 40)), SessionToken: []byte(strings.Repeat("t", 32))},
		},
		{
			name:  "kubernetes",
			input: discoveryCredentialInput(scope, collection.ProviderKubernetes, collection.CredentialKubernetesCluster, "ref:kubernetes/connection/customer-0001", collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example.test/customer"}, `{"connection_reference":"ref:kubernetes/connection/customer-0001"}`, now),
			secrets: map[string][]byte{
				"ref:kubernetes/connection/customer-0001": []byte(`{"endpoint":"https://cluster.example.test","context":"customer","ca_reference":"ref:kubernetes/ca/customer-0001","credential_reference":"ref:kubernetes/credential/customer-0001"}`),
				"ref:kubernetes/ca/customer-0001":         bytes.Clone(caBundle),
				"ref:kubernetes/credential/customer-0001": []byte("kubernetes-token-customer-0001"),
			},
			wantCalls:  []string{"ref:kubernetes/connection/customer-0001", "ref:kubernetes/ca/customer-0001", "ref:kubernetes/credential/customer-0001"},
			wantFields: discoveryCredentialEnvelope{Provider: collection.ProviderKubernetes, SubjectKind: "kubernetes_cluster", SubjectID: "cluster.example.test/customer", Endpoint: "https://cluster.example.test", Context: "customer", CABundlePEM: bytes.Clone(caBundle), BearerToken: []byte("kubernetes-token-customer-0001")},
		},
		{
			name:       "github",
			input:      discoveryCredentialInput(scope, collection.ProviderGitHub, collection.CredentialGitHubInstallation, "ref:github/installation/123456", collection.SubjectBinding{Kind: "github_installation", ID: "123456"}, `{"authorization_mode":"github_app"}`, now),
			secrets:    map[string][]byte{"ref:github/app-private-key-0001": []byte("private-key-material")},
			wantCalls:  []string{"ref:github/app-private-key-0001"},
			wantFields: discoveryCredentialEnvelope{Provider: collection.ProviderGitHub, SubjectKind: "github_installation", SubjectID: "123456", BearerToken: []byte("github-installation-token")},
		},
		{
			name:       "okta",
			input:      discoveryCredentialInput(scope, collection.ProviderOkta, collection.CredentialOktaRefresh, "ref:okta/refresh/customer-0001", collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, `{"issuer":"https://acme.okta.com"}`, now),
			secrets:    map[string][]byte{"ref:okta/client-secret-0001": []byte("okta-client-secret-value"), "ref:okta/refresh/customer-0001": []byte("okta-refresh-token-value")},
			wantCalls:  []string{"ref:okta/client-secret-0001", "ref:okta/refresh/customer-0001"},
			wantFields: discoveryCredentialEnvelope{Provider: collection.ProviderOkta, SubjectKind: "okta_tenant", SubjectID: "acme.okta.com", Issuer: "https://acme.okta.com", BearerToken: []byte("okta-access-token-value")},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secrets := &discoverySecretReaderStub{values: test.secrets}
			assume := &discoveryAssumeRoleStub{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAEXAMPLE000001"), SecretAccessKey: aws.String(strings.Repeat("s", 40)), SessionToken: aws.String(strings.Repeat("t", 32)), Expiration: aws.Time(now.Add(15 * time.Minute))}}}
			github := &discoveryGitHubMintStub{result: discoveryGitHubInstallationToken{Token: []byte("github-installation-token"), InstallationID: 123456, ExpiresAt: now.Add(time.Hour)}}
			okta := &discoveryOktaExchangeStub{result: discoveryOktaAccessToken{Token: []byte("okta-access-token-value"), Tenant: "acme.okta.com", Scopes: []string{"okta.apps.read", "okta.groups.read", "okta.users.read"}, ExpiresAt: now.Add(time.Hour)}}
			resolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: assume, GitHub: github, Okta: okta, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }})
			if err != nil {
				t.Fatalf("new resolver: %v", err)
			}
			request := discoveryCredentialMaterialRequest{Scope: scope, Input: test.input, WorkerID: "discovery-worker-a", LeaseToken: []byte("lease-token-0000000000000001"), Credential: credentialRequestForJob(mustCollectionRequest(t, scope, test.input))}
			material, err := resolver.ResolveDiscoveryCredential(context.Background(), request)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			var got discoveryCredentialEnvelope
			if err := material.Use(request.Credential, func(value []byte) error {
				var decodeErr error
				got, decodeErr = decodeDiscoveryCredentialEnvelope(value)
				return decodeErr
			}); err != nil {
				t.Fatalf("use: %v", err)
			}
			material.Destroy()
			if got.Provider != test.wantFields.Provider || got.SubjectKind != test.wantFields.SubjectKind || got.SubjectID != test.wantFields.SubjectID || got.Region != test.wantFields.Region || got.Endpoint != test.wantFields.Endpoint || got.Context != test.wantFields.Context || got.Issuer != test.wantFields.Issuer || !bytes.Equal(got.CABundlePEM, test.wantFields.CABundlePEM) || !bytes.Equal(got.BearerToken, test.wantFields.BearerToken) || !bytes.Equal(got.AccessKeyID, test.wantFields.AccessKeyID) || !bytes.Equal(got.SecretAccessKey, test.wantFields.SecretAccessKey) || !bytes.Equal(got.SessionToken, test.wantFields.SessionToken) || !got.ExpiresAt.After(test.input.LeaseExpiresAt.Add(time.Minute)) || test.name == "kubernetes" && !got.ExpiresAt.Equal(now.Add(discoveryStaticCredentialTTL)) {
				t.Fatalf("unexpected envelope: %#v", got)
			}
			if !equalStrings(secrets.calls, test.wantCalls) {
				t.Fatalf("secret calls=%v want=%v", secrets.calls, test.wantCalls)
			}
			got.Destroy()
		})
	}
}

func TestProductionDiscoveryCredentialsRejectBindingAndConfigurationBeforeIO(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	base := discoveryCredentialInput(scope, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/external-id/customer-0001", collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`, now)
	secrets := &discoverySecretReaderStub{values: map[string][]byte{"ref:aws/external-id/customer-0001": []byte("external-id-customer-0001")}}
	assume := &discoveryAssumeRoleStub{}
	resolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: assume, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	valid := discoveryCredentialMaterialRequest{Scope: scope, Input: base, WorkerID: "discovery-worker-a", LeaseToken: []byte("lease-token-0000000000000001"), Credential: credentialRequestForJob(mustCollectionRequest(t, scope, base))}
	tests := map[string]func(*discoveryCredentialMaterialRequest){
		"scope":  func(request *discoveryCredentialMaterialRequest) { request.Scope = domain.Scope{} },
		"worker": func(request *discoveryCredentialMaterialRequest) { request.WorkerID = "bad worker" },
		"lease":  func(request *discoveryCredentialMaterialRequest) { request.LeaseToken = []byte("short") },
		"job": func(request *discoveryCredentialMaterialRequest) {
			request.Input.JobID = discoveryCredentialID(99).String()
		},
		"credential": func(request *discoveryCredentialMaterialRequest) {
			request.Credential.Reference = "ref:aws/external-id/other-0001"
		},
		"configuration": func(request *discoveryCredentialMaterialRequest) {
			request.Input.Configuration = json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery","secret":"leak"}`)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneDiscoveryCredentialMaterialRequest(valid)
			mutate(&request)
			if _, err := resolver.ResolveDiscoveryCredential(context.Background(), request); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if len(secrets.calls) != 0 || assume.input != nil {
		t.Fatalf("dependency called before rejection: secrets=%v assume=%#v", secrets.calls, assume.input)
	}
}

func TestProductionDiscoveryCredentialsBindProviderSubjectsAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	secrets := &discoverySecretReaderStub{values: map[string][]byte{"ref:github/app-private-key-0001": []byte("private-key-material")}}
	github := &discoveryGitHubMintStub{result: discoveryGitHubInstallationToken{Token: []byte("github-installation-token"), InstallationID: 654321, ExpiresAt: now.Add(time.Hour)}}
	resolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: &discoveryAssumeRoleStub{}, GitHub: github, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	input := discoveryCredentialInput(scope, collection.ProviderGitHub, collection.CredentialGitHubInstallation, "ref:github/installation/123456", collection.SubjectBinding{Kind: "github_installation", ID: "123456"}, `{"authorization_mode":"github_app"}`, now)
	request := discoveryCredentialMaterialRequest{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: []byte("lease-token-0000000000000001"), Credential: credentialRequestForJob(mustCollectionRequest(t, scope, input))}
	if _, err := resolver.ResolveDiscoveryCredential(context.Background(), request); err == nil {
		t.Fatal("foreign installation attestation accepted")
	}
	if github.installationID != 123456 || github.appID != "123456" || !bytes.Equal(github.key, []byte("private-key-material")) {
		t.Fatalf("mint request not exact: %#v", github)
	}
	if strings.Contains(errString(resolver.ResolveDiscoveryCredential(context.Background(), request)), "private-key-material") || strings.Contains(errString(resolver.ResolveDiscoveryCredential(context.Background(), request)), string(request.LeaseToken)) {
		t.Fatal("secret or lease token escaped stable error")
	}
}

func discoveryCredentialScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(discoveryCredentialID(1), discoveryCredentialID(2), discoveryCredentialID(3))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func discoveryCredentialInput(scope domain.Scope, provider collection.Provider, class collection.CredentialClass, reference string, subject collection.SubjectBinding, configuration string, now time.Time) apiserver.ExecutionJobInput {
	input := workerExecutionInput(scope, discoveryCredentialID(4).String())
	input.Provider = provider
	input.CredentialClass = class
	input.CredentialReference = reference
	input.SubjectKind = subject.Kind
	input.SubjectID = subject.ID
	input.ExpectedSubject = subject
	input.CursorProvider = nil
	input.CursorVersion = nil
	input.CursorValue = nil
	input.Configuration = json.RawMessage(configuration)
	input.LeaseExpiresAt = now.Add(30 * time.Second)
	return input
}

func mustCollectionRequest(t *testing.T, scope domain.Scope, input apiserver.ExecutionJobInput) collection.Request {
	t.Helper()
	request, ok := collectionRequest(scope, input)
	if !ok {
		t.Fatalf("invalid collection request for %#v", input)
	}
	return request
}

func discoveryCredentialID(index int) domain.ProductID {
	value, _ := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", 90000000+index, index))
	return value
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func errString(_ *collection.CredentialMaterial, err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ discoverySecretReader = (*discoverySecretReaderStub)(nil)
var _ discoveryAssumeRoleAPI = (*discoveryAssumeRoleStub)(nil)
var _ discoveryGitHubTokenAPI = (*discoveryGitHubMintStub)(nil)
var _ discoveryOktaTokenAPI = (*discoveryOktaExchangeStub)(nil)

func TestDiscoveryCredentialFailureIsStableAndRedacted(t *testing.T) {
	now := time.Now().UTC()
	scope := discoveryCredentialScope(t)
	secret := "external-id-do-not-log"
	secrets := &discoverySecretReaderStub{values: map[string][]byte{"ref:aws/external-id/customer-0001": []byte(secret)}}
	assume := &discoveryAssumeRoleStub{err: errors.New("upstream echoed " + secret)}
	resolver, err := newProductionDiscoveryCredentialResolver(productionDiscoveryCredentialConfig{Secrets: secrets, AssumeRole: assume, GitHub: &discoveryGitHubMintStub{}, Okta: &discoveryOktaExchangeStub{}, GitHubAppID: "123456", GitHubPrivateKeyReference: "ref:github/app-private-key-0001", OktaClientID: "0oa1234567890abcdef", OktaClientSecretReference: "ref:okta/client-secret-0001", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	input := discoveryCredentialInput(scope, collection.ProviderAWS, collection.CredentialAWSAssumeRole, "ref:aws/external-id/customer-0001", collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp/discovery"}`, now)
	request := discoveryCredentialMaterialRequest{Scope: scope, Input: input, WorkerID: "discovery-worker-a", LeaseToken: []byte("lease-token-0000000000000001"), Credential: credentialRequestForJob(mustCollectionRequest(t, scope, input))}
	_, resolveErr := resolver.ResolveDiscoveryCredential(context.Background(), request)
	if resolveErr == nil || strings.Contains(resolveErr.Error(), secret) || strings.Contains(resolveErr.Error(), request.Input.CredentialReference) || strings.Contains(resolveErr.Error(), string(request.LeaseToken)) {
		t.Fatalf("unstable error: %v", resolveErr)
	}
}
