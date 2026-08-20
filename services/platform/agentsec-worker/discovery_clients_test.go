package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
)

type discoveryCollectionAPIStub struct {
	credential []byte
	request    githubdiscovery.CollectionPageRequest
	page       githubdiscovery.CollectionPage
	err        error
}

func (stub *discoveryCollectionAPIStub) FetchCollectionPage(_ context.Context, credential []byte, request githubdiscovery.CollectionPageRequest) (githubdiscovery.CollectionPage, error) {
	stub.credential = bytes.Clone(credential)
	stub.request = request
	return stub.page, stub.err
}

func (stub *discoveryCollectionAPIStub) CheckCollectionReadiness(context.Context) error {
	return stub.err
}

type discoveryCallerIdentityStub struct {
	credentials aws.Credentials
	region      string
	input       *sts.GetCallerIdentityInput
	output      *sts.GetCallerIdentityOutput
	err         error
}

func (stub *discoveryCallerIdentityStub) GetCallerIdentity(_ context.Context, input *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	stub.input = input
	return stub.output, stub.err
}

func TestDiscoveryProviderAPIsUseOnlyDecodedExactMaterial(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name     string
		provider collection.Provider
		envelope discoveryCredentialEnvelope
		request  githubdiscovery.CollectionPageRequest
		newAPI   func(*discoveryCollectionAPIStub) githubdiscovery.CollectionAPI
	}{
		{
			name: "github", provider: collection.ProviderGitHub,
			envelope: discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderGitHub, SubjectKind: "github_installation", SubjectID: "123456", ExpiresAt: now.Add(time.Minute), BearerToken: []byte("github-installation-token")},
			request:  githubdiscovery.CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "123456"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096},
			newAPI: func(stub *discoveryCollectionAPIStub) githubdiscovery.CollectionAPI {
				return newDiscoveryGitHubCollectionAPI(stub)
			},
		},
		{
			name: "kubernetes", provider: collection.ProviderKubernetes,
			envelope: discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderKubernetes, SubjectKind: "kubernetes_cluster", SubjectID: "cluster.example.test/customer", ExpiresAt: now.Add(time.Minute), Endpoint: "https://cluster.example.test", Context: "customer", CABundlePEM: []byte(testDiscoveryCACertificatePEM), BearerToken: []byte("kubernetes-token-customer-0001")},
			request:  githubdiscovery.CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example.test/customer"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096},
			newAPI: func(stub *discoveryCollectionAPIStub) githubdiscovery.CollectionAPI {
				return newDiscoveryKubernetesCollectionAPI([]string{"203.0.113.0/24"}, func(config kubernetesdiscovery.PinnedCollectionAPIConfig) (kubernetesdiscovery.CollectionAPI, error) {
					if config.Endpoint != "https://cluster.example.test" || !bytes.Equal(config.CABundlePEM, []byte(testDiscoveryCACertificatePEM)) || len(config.AllowedCIDRs) != 1 || config.AllowedCIDRs[0] != "203.0.113.0/24" {
						t.Fatal("kubernetes config was not exact")
					}
					return stub, nil
				})
			},
		},
		{
			name: "okta", provider: collection.ProviderOkta,
			envelope: discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderOkta, SubjectKind: "okta_tenant", SubjectID: "acme.okta.com", ExpiresAt: now.Add(time.Minute), Issuer: "https://acme.okta.com", BearerToken: []byte("okta-access-token-value")},
			request:  githubdiscovery.CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096},
			newAPI: func(stub *discoveryCollectionAPIStub) githubdiscovery.CollectionAPI {
				return newDiscoveryOktaCollectionAPI(func(issuer string, timeout time.Duration) (idpdiscovery.CollectionAPI, error) {
					if issuer != "https://acme.okta.com" || timeout != time.Second {
						t.Fatal("okta config was not exact")
					}
					return stub, nil
				}, time.Second)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &discoveryCollectionAPIStub{}
			api := test.newAPI(stub)
			credential, err := encodeDiscoveryCredentialEnvelope(test.envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.FetchCollectionPage(context.Background(), credential, test.request); err != nil {
				t.Fatalf("fetch: %v", err)
			}
			clear(credential)
			if !bytes.Equal(stub.credential, test.envelope.BearerToken) || stub.request.Provider != test.provider || stub.request.Subject.Kind != test.envelope.SubjectKind || stub.request.Subject.ID != test.envelope.SubjectID {
				t.Fatalf("provider request not exact: credential=%q request=%#v", stub.credential, stub.request)
			}
		})
	}
}

func TestDiscoveryProviderAPIsRejectForeignOrMalformedEnvelopeBeforeProvider(t *testing.T) {
	now := time.Now().UTC()
	stub := &discoveryCollectionAPIStub{}
	api := newDiscoveryGitHubCollectionAPI(stub)
	request := githubdiscovery.CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "123456"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096}
	envelope := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderGitHub, SubjectKind: "github_installation", SubjectID: "654321", ExpiresAt: now.Add(time.Minute), BearerToken: []byte("github-installation-token")}
	foreign, _ := encodeDiscoveryCredentialEnvelope(envelope)
	for _, credential := range [][]byte{foreign, []byte(`{"version":"discovery_credential_v1","provider":"github","subject_kind":"github_installation","subject_id":"123456","expires_at":"2026-08-20T00:00:00Z","bearer_token":"c2VjcmV0","extra":true}`)} {
		if _, err := api.FetchCollectionPage(context.Background(), credential, request); err == nil {
			t.Fatal("hostile envelope accepted")
		}
	}
	if len(stub.credential) != 0 {
		t.Fatal("provider called for hostile envelope")
	}
}

func TestDiscoveryProviderAPIsClassifyExpiredEphemeralTokenRetryable(t *testing.T) {
	stub := &discoveryCollectionAPIStub{}
	api := newDiscoveryGitHubCollectionAPI(stub)
	request := githubdiscovery.CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "123456"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096}
	envelope := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderGitHub, SubjectKind: "github_installation", SubjectID: "123456", ExpiresAt: time.Now().UTC().Add(-time.Second), BearerToken: []byte("github-installation-token")}
	credential, err := encodeDiscoveryCredentialEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.FetchCollectionPage(context.Background(), credential, request)
	clear(credential)
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure == nil || failure.Code() != collection.FailureRetryable || len(stub.credential) != 0 {
		t.Fatalf("failure=%#v err=%v providerCredential=%q", failure, err, stub.credential)
	}
}

func TestDiscoveryAWSIdentityCallerUsesExplicitSessionAndAttestsSubject(t *testing.T) {
	now := time.Now().UTC()
	stub := &discoveryCallerIdentityStub{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp/discovery-session"), UserId: aws.String("role-id:session")}}
	caller, err := newDiscoveryAWSCollectionIdentityCaller(func(region string, credentials aws.Credentials) (discoveryCallerIdentityAPI, error) {
		stub.region, stub.credentials = region, credentials
		return stub, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderAWS, SubjectKind: "aws_account", SubjectID: "123456789012", ExpiresAt: now.Add(time.Minute), Region: "us-east-1", AccessKeyID: []byte("ASIAEXAMPLE000001"), SecretAccessKey: []byte("12345678901234567890123456789012"), SessionToken: []byte("session-token-0000000000000001")}
	credential, _ := encodeDiscoveryCredentialEnvelope(envelope)
	identity, err := caller.GetCollectionIdentity(context.Background(), credential)
	clear(credential)
	if err != nil || identity.AccountID != "123456789012" || stub.region != "us-east-1" || stub.credentials.AccessKeyID != "ASIAEXAMPLE000001" || stub.credentials.Source != "zasp-discovery-assume-role" || stub.input == nil {
		t.Fatalf("identity=%#v stub=%#v err=%v", identity, stub, err)
	}
	stub.output.Account = aws.String("999999999999")
	credential, _ = encodeDiscoveryCredentialEnvelope(envelope)
	if _, err := caller.GetCollectionIdentity(context.Background(), credential); err == nil {
		t.Fatal("foreign account accepted")
	}
}

func TestDiscoveryProviderAPIsRedactPanicsAndErrors(t *testing.T) {
	secret := []byte("github-installation-token")
	stub := &discoveryCollectionAPIStub{err: errors.New("provider echoed " + string(secret))}
	api := newDiscoveryGitHubCollectionAPI(stub)
	envelope := discoveryCredentialEnvelope{Version: discoveryCredentialEnvelopeVersion, Provider: collection.ProviderGitHub, SubjectKind: "github_installation", SubjectID: "123456", ExpiresAt: time.Now().UTC().Add(time.Minute), BearerToken: secret}
	credential, _ := encodeDiscoveryCredentialEnvelope(envelope)
	_, err := api.FetchCollectionPage(context.Background(), credential, githubdiscovery.CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "123456"}, Page: 1, RemainingItems: 1, RemainingBytes: 4096})
	if err == nil || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatalf("unstable provider error: %v", err)
	}
}

var _ githubdiscovery.CollectionAPI = (*discoveryCollectionAPIStub)(nil)
var _ discoveryCallerIdentityAPI = (*discoveryCallerIdentityStub)(nil)
